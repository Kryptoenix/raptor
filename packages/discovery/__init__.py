#!/usr/bin/env python3
"""
RAPTOR v2 — Vulnerability Discovery Phase

Runs selected discovery tools against a repository and collects findings.
Each tool is independent — failures in one don't block others.

Usage:
    from packages.discovery import DiscoveryOrchestrator

    orchestrator = DiscoveryOrchestrator(
        repo_path=Path("/path/to/repo"),
        out_dir=Path("/path/to/output"),
        strategy="webapp",
    )
    findings = orchestrator.run(semgrep=True, codeql=False, trufflehog=True, llmscan=True)

To add a new discovery tool:
    1. Write a _run_<toolname>() method that returns List[Dict]
    2. Add it to the TOOLS registry in run()
    3. Add a toggle parameter to run()
"""

import json
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.json import save_json
from core.logging import get_logger

logger = get_logger()


# ═══════════════════════════════════════════════════════════════════════════
# Constants
# ═══════════════════════════════════════════════════════════════════════════

README_MAX_CHARS = 3000
README_FILENAMES = [
    "README.md", "README.txt", "README", "README.rst",
    "readme.md", "readme.txt", "Readme.md",
]

SEMGREP_TIMEOUT  = 600   # seconds
TRUFFLEHOG_TIMEOUT = 300
CODEQL_TIMEOUT   = 900

# Semgrep configs tried in order — first one that produces results wins.
SEMGREP_CONFIGS = ["p/default", "p/security-audit", "auto"]


# ═══════════════════════════════════════════════════════════════════════════
# Orchestrator
# ═══════════════════════════════════════════════════════════════════════════

class DiscoveryOrchestrator:
    """
    Runs selected discovery tools and returns combined findings.

    Attributes:
        repo_path:       Absolute path to the target repository.
        out_dir:         Directory for tool outputs (SARIF files, JSON, etc.).
        strategy:        "webapp" or "binary" — controls LLMScan prompts.
        readme_context:  Contents of the project README (read by caller).
        errors:          Populated after run() with any tool error messages.
    """

    def __init__(
        self,
        repo_path: Path,
        out_dir: Path,
        strategy: str = "webapp",
        readme_context: str = "",
    ):
        self.repo_path = Path(repo_path).resolve()
        self.out_dir = Path(out_dir)
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.strategy = strategy
        self.readme_context = readme_context
        self.errors: List[str] = []

    # ─── Public entry point ───────────────────────────────────────────

    def run(
        self,
        semgrep: bool = True,
        codeql: bool = True,
        trufflehog: bool = True,
        llmscan: bool = True,
        max_retries: int = 2,
    ) -> List[Dict[str, Any]]:
        """
        Run all enabled tools and return the combined raw findings.

        Each tool runs independently with a retry loop. A failure in one
        tool does not prevent the others from running.
        """
        # Tool registry: (display_name, enabled, runner_method)
        tools = [
            ("trufflehog", trufflehog, self._run_trufflehog),
            ("semgrep",    semgrep,    self._run_semgrep),
            ("codeql",     codeql,     self._run_codeql),
            ("llmscan",    llmscan,    self._run_llmscan),
        ]

        enabled = [name for name, on, _ in tools if on]

        logger.info("=" * 60)
        logger.info("RAPTOR DISCOVERY PHASE")
        logger.info("Strategy: %s | Tools: %s",
                     self.strategy, ", ".join(enabled) or "none")
        logger.info("=" * 60)

        all_findings: List[Dict[str, Any]] = []

        for name, is_enabled, runner in tools:
            if not is_enabled:
                continue

            logger.info("\n── %s ──", name)
            findings, error = _run_with_retry(runner, max_retries, name)
            all_findings.extend(findings)

            if error:
                self.errors.append(f"{name}: {error}")

        # Persist combined results
        save_json(self.out_dir / "discovery_findings.json", {
            "tool": "raptor-discovery",
            "strategy": self.strategy,
            "total_findings": len(all_findings),
            "errors": self.errors,
            "findings": all_findings,
        })

        logger.info("\n── Discovery complete: %d findings ──", len(all_findings))
        if self.errors:
            logger.warning("Tool errors: %s", "; ".join(self.errors))

        return all_findings

    # ─── Tool: TruffleHog (secrets scanning) ──────────────────────────

    def _run_trufflehog(self) -> List[Dict[str, Any]]:
        """Scan for hardcoded secrets and credentials."""
        trufflehog_bin = _require_tool("trufflehog")
        if not trufflehog_bin:
            return []

        result = subprocess.run(
            [trufflehog_bin, "filesystem", str(self.repo_path),
             "--json", "--no-update"],
            capture_output=True, text=True, timeout=TRUFFLEHOG_TIMEOUT,
        )

        findings = []
        for line in (result.stdout or "").strip().splitlines():
            finding = _parse_trufflehog_line(line)
            if finding:
                findings.append(finding)

        save_json(self.out_dir / "trufflehog_results.json", findings)
        return findings

    # ─── Tool: Semgrep (static analysis) ──────────────────────────────

    def _run_semgrep(self) -> List[Dict[str, Any]]:
        """Run Semgrep static analysis with SARIF output."""
        semgrep_bin = _require_tool("semgrep")
        if not semgrep_bin:
            return []

        sarif_out = self.out_dir / "semgrep_results.sarif"

        # Build config list: local rules first, then remote packs
        raptor_root = Path(__file__).resolve().parents[1]
        local_rules = raptor_root / "engine" / "semgrep" / "rules"

        configs = []
        if local_rules.is_dir() and any(local_rules.glob("*.yaml")):
            configs.append(str(local_rules))
        configs.extend(SEMGREP_CONFIGS)

        # Try each config until one produces findings
        for config in configs:
            findings = self._try_semgrep_config(semgrep_bin, config, sarif_out)
            if findings:
                return findings

        # No config produced findings — return whatever the last SARIF had
        return _load_sarif(sarif_out, tool="semgrep")

    def _try_semgrep_config(
        self, binary: str, config: str, sarif_out: Path,
    ) -> List[Dict[str, Any]]:
        """Try a single Semgrep config. Returns findings or []."""
        result = subprocess.run(
            [binary, "--config", config, "--sarif",
             "--output", str(sarif_out), "--no-error",
             str(self.repo_path)],
            capture_output=True, text=True, timeout=SEMGREP_TIMEOUT,
        )

        if "403" in result.stderr or "Failed to download" in result.stderr:
            logger.warning("Semgrep config '%s': network error, skipping", config)
            return []

        if result.returncode != 0 and not sarif_out.exists():
            logger.warning("Semgrep config '%s': failed (exit %d)", config, result.returncode)
            return []

        findings = _load_sarif(sarif_out, tool="semgrep")
        if findings:
            logger.info("Semgrep config '%s': %d findings", config, len(findings))
        return findings

    # ─── Tool: CodeQL (deep static analysis) ──────────────────────────

    def _run_codeql(self) -> List[Dict[str, Any]]:
        """Run CodeQL analysis and collect SARIF results."""
        from packages.codeql.agent import CodeQLAgent

        agent = CodeQLAgent(repo_path=self.repo_path, out_dir=self.out_dir)
        agent.run_autonomous_analysis()

        findings = []
        for sarif_file in self.out_dir.rglob("*.sarif"):
            if "codeql" in sarif_file.name.lower():
                findings.extend(_load_sarif(sarif_file, tool="codeql"))
        return findings

    # ─── Tool: LLMScan (AI-powered code analysis) ────────────────────

    def _run_llmscan(self) -> List[Dict[str, Any]]:
        """Run the LLM-powered direct code scanner."""
        from packages.llm_scan import LLMScanner

        llmscan_out = self.out_dir / "llmscan"
        llmscan_out.mkdir(parents=True, exist_ok=True)

        scanner = LLMScanner(
            repo_path=self.repo_path,
            out_dir=llmscan_out,
            max_files=200,
            max_chunks_per_file=20,
        )
        return scanner.scan()

    # ─── Static helpers ───────────────────────────────────────────────

    @staticmethod
    def read_readme(repo_path: Path) -> str:
        """
        Read the project README for context.
        Returns the first README_MAX_CHARS characters, or "" if not found.
        """
        for name in README_FILENAMES:
            readme = Path(repo_path) / name
            if not readme.exists():
                continue
            try:
                content = readme.read_text(encoding="utf-8", errors="replace")
                if len(content) > README_MAX_CHARS:
                    content = content[:README_MAX_CHARS] + "\n... (truncated)"
                logger.info("Read README: %s (%d chars)", name, len(content))
                return content
            except OSError:
                continue
        return ""


# ═══════════════════════════════════════════════════════════════════════════
# Module-level helpers (used by the orchestrator, testable independently)
# ═══════════════════════════════════════════════════════════════════════════

def _require_tool(name: str) -> Optional[str]:
    """Return the path to a tool binary, or None with a warning."""
    path = shutil.which(name)
    if not path:
        logger.warning("%s not installed — skipping", name)
    return path


def _run_with_retry(
    func: Callable,
    max_retries: int,
    tool_name: str,
) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """
    Execute a tool function with automatic retry on failure.
    Returns (findings, error_message_or_None).
    """
    last_error = None

    for attempt in range(max_retries + 1):
        try:
            if attempt > 0:
                logger.info("Retrying %s (attempt %d/%d)...",
                            tool_name, attempt + 1, max_retries + 1)
                time.sleep(2)

            findings = func()
            logger.info("✓ %s: %d finding(s)", tool_name, len(findings))
            return findings, None

        except Exception as exc:
            last_error = str(exc)
            logger.warning("%s attempt %d failed: %s",
                           tool_name, attempt + 1, last_error)

    logger.error("✗ %s failed after %d attempts: %s",
                 tool_name, max_retries + 1, last_error)
    return [], last_error


def _load_sarif(sarif_path: Path, tool: str = "") -> List[Dict[str, Any]]:
    """Load a SARIF file and return normalised findings."""
    if not sarif_path.exists() or sarif_path.stat().st_size < 50:
        return []

    from packages.llm_scan.merger import load_sarif_findings

    findings = load_sarif_findings(sarif_path)
    for f in findings:
        f["tool"] = f.get("tool") or tool
        f["sources"] = [tool]
    return findings


def _parse_trufflehog_line(line: str) -> Optional[Dict[str, Any]]:
    """Parse one JSON-lines output from TruffleHog into a finding dict."""
    try:
        item = json.loads(line)
    except (json.JSONDecodeError, ValueError):
        return None

    meta = item.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {})
    detector = item.get("DetectorName", "unknown")
    verified = item.get("Verified", False)

    return {
        "rule_id":          detector.lower().replace(" ", "-"),
        "file_path":        meta.get("file", ""),
        "start_line":       meta.get("line", 0),
        "end_line":         meta.get("line", 0),
        "message":          f"Secret detected: {detector} (verified: {verified})",
        "severity":         "critical" if verified else "high",
        "level":            "critical" if verified else "high",
        "vuln_type":        "hardcoded_secret",
        "cwe_id":           "CWE-798",
        "tool":             "trufflehog",
        "confidence":       "high" if verified else "medium",
        "is_exploitable":   verified,
        "is_true_positive": True,
        "sources":          ["trufflehog"],
        "reasoning":        f"Detected {detector} credential (verified={verified}).",
        "raw_trufflehog":   item,
    }
