#!/usr/bin/env python3
"""
RAPTOR v2 — Vulnerability Validation Phase

Takes raw findings from discovery, deduplicates them, and enriches each with:
  - vuln_code:            the 1-3 lines where the bug resides
  - surrounding_context:  neighbouring source lines for context
  - exploit_code:         proof-of-concept exploit (LLM-generated)
  - patch_code:           fixed version of the vulnerable code
  - remediation:          human-readable fix description
  - credential impact:    for TruffleHog secrets — how the credential can be abused

Optionally tests web findings against a live APP URL using nmap/gobuster/sqlmap.

To add a new enrichment step:
    1. Add a method to ValidationOrchestrator
    2. Call it from _enrich_finding() in the appropriate place
"""

import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.json import save_json
from core.logging import get_logger

logger = get_logger()


# ═══════════════════════════════════════════════════════════════════════════
# Unified finding schema
# ═══════════════════════════════════════════════════════════════════════════

FINDING_SCHEMA_FIELDS = [
    # Identity
    "rule_id", "file_path", "start_line", "end_line",
    "message", "tool", "severity", "level",
    "vuln_type", "cwe_id", "confidence",

    # Validation results
    "is_true_positive", "is_exploitable", "exploitability_score",
    "ruling", "cvss_score_estimate", "cvss_vector",

    # Analysis
    "reasoning", "attack_scenario", "impact",
    "remediation", "dataflow_summary",
    "false_positive_reason",

    # Code artifacts
    "exploit_code", "patch_code",
    "vuln_code",
    "surrounding_context",

    # Provenance
    "sources",
]

# How many source lines to show above/below the vulnerable code
CONTEXT_LINES = 5

# Map TruffleHog detector names to credential-abuse examples
CREDENTIAL_IMPACT_MAP = {
    "mysql":      "mysql -u <user> -p'<secret>' -h <host>",
    "postgres":   "psql 'postgresql://<user>:<secret>@<host>/<db>'",
    "mongodb":    "mongosh 'mongodb://<user>:<secret>@<host>/<db>'",
    "aws":        "aws configure  (use found Access Key ID + Secret)",
    "github":     "curl -H 'Authorization: token <token>' https://api.github.com/user",
    "slack":      "curl -H 'Authorization: Bearer <token>' https://slack.com/api/auth.test",
    "stripe":     "curl https://api.stripe.com/v1/charges -u <key>:",
    "sendgrid":   "Send emails via SendGrid API with found key",
    "twilio":     "Send SMS/calls via Twilio API with found credentials",
    "azure":      "az login --service-principal with found credentials",
    "gcp":        "gcloud auth activate-service-account --key-file=<found_key>",
    "jwt":        "Forge valid JWT tokens for any user/role",
    "privatekey": "Impersonate the key owner (SSH, TLS, code signing)",
}


# ═══════════════════════════════════════════════════════════════════════════
# Orchestrator
# ═══════════════════════════════════════════════════════════════════════════

class ValidationOrchestrator:
    """
    Deduplicates findings, then enriches each with code context,
    exploit PoC, patch, and remediation.

    Attributes:
        repo_path:  Absolute path to the repository (for source extraction).
        out_dir:    Output directory for validation artifacts.
        strategy:   "webapp" or "binary".
        app_url:    (webapp only) Live URL to test findings against.
        proxy_url:  (webapp only) HTTP proxy for outbound requests.
        llm:        LLMClient instance, or None if no LLM is available.
    """

    def __init__(
        self,
        repo_path: Path,
        out_dir: Path,
        strategy: str = "webapp",
        app_url: str = "",
        proxy_url: str = "",
    ):
        self.repo_path = Path(repo_path).resolve()
        self.out_dir = Path(out_dir)
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.strategy = strategy
        self.app_url = app_url
        self.proxy_url = proxy_url
        self.llm = _init_llm_client()

    # ─── Public entry point ───────────────────────────────────────────

    def run(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Deduplicate → enrich → optionally live-test → save results.
        Returns the list of enriched findings.
        """
        logger.info("=" * 60)
        logger.info("RAPTOR VALIDATION PHASE")
        logger.info("=" * 60)
        logger.info("Input findings: %d", len(findings))

        # Step 1: Deduplicate across tools
        deduped = self._deduplicate(findings)
        logger.info("After dedup: %d findings", len(deduped))

        # Step 2: Enrich each finding
        validated = []
        for i, finding in enumerate(deduped, 1):
            logger.info("[%d/%d] %s  %s:%s",
                        i, len(deduped),
                        finding.get("rule_id", "?"),
                        finding.get("file_path", "?"),
                        finding.get("start_line", "?"))
            validated.append(self._enrich_finding(finding))

        # Step 3: Live testing (webapp + APP URL only)
        if self.app_url and self.strategy == "webapp":
            logger.info("\n── Live testing: %s ──", self.app_url)
            self._test_against_app(validated)

        # Persist
        save_json(self.out_dir / "validated_findings.json", {
            "total_findings": len(validated),
            "exploitable": sum(1 for f in validated if f.get("is_exploitable")),
            "results": validated,
        })

        exploitable = sum(1 for f in validated if f.get("is_exploitable"))
        logger.info("\n── Validation complete: %d findings (%d exploitable) ──",
                     len(validated), exploitable)
        return validated

    # ─── Deduplication ────────────────────────────────────────────────

    def _deduplicate(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Merge overlapping findings from different tools."""
        from packages.llm_scan.merger import merge_findings

        llm = [f for f in findings if "llmscan" in (f.get("sources") or [f.get("tool", "")])]
        other = [f for f in findings if "llmscan" not in (f.get("sources") or [f.get("tool", "")])]

        if llm and other:
            return merge_findings(llm, other)
        return findings

    # ─── Per-finding enrichment ───────────────────────────────────────

    def _enrich_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enrich a single finding with source context, exploit, and patch.
        Returns a new dict (does not mutate the input).
        """
        enriched = dict(finding)

        # 1. Extract source code context
        file_path = finding.get("file_path", "")
        start     = int(finding.get("start_line", 0))
        end       = int(finding.get("end_line", start))

        if file_path and start > 0:
            vuln_code, context = _extract_code_context(
                self.repo_path, file_path, start, end,
            )
            enriched["vuln_code"] = vuln_code
            enriched["surrounding_context"] = context

        # 2. TruffleHog credential impact
        if finding.get("tool") == "trufflehog" and finding.get("raw_trufflehog"):
            enriched["attack_scenario"] = _credential_impact(finding["raw_trufflehog"])

        # 3. LLM-powered exploit + patch generation
        if self.llm and not enriched.get("exploit_code"):
            _llm_generate_exploit_and_patch(self.llm, enriched)

        # 4. Ensure every schema field exists (prevents KeyError downstream)
        for field in FINDING_SCHEMA_FIELDS:
            enriched.setdefault(field, "")
            if enriched[field] is None:
                enriched[field] = ""

        return enriched

    # ─── Live testing (webapp mode) ───────────────────────────────────

    def _test_against_app(self, findings: List[Dict[str, Any]]) -> None:
        """
        Test findings against a live web application.

        Runs (if installed):
          - nmap:    top-100 port scan against the host
          - gobuster: directory brute-force
          - sqlmap:  SQL injection validation for SQLi findings
        """
        logger.info("Testing %d findings against %s", len(findings), self.app_url)
        host = urlparse(self.app_url).hostname

        # nmap
        self._run_nmap(host)

        # gobuster
        self._run_gobuster()

        # sqlmap for SQLi findings
        sqli = [f for f in findings
                if "sql" in (f.get("vuln_type") or "").lower()
                or "sqli" in (f.get("rule_id") or "").lower()]
        for finding in sqli[:3]:
            self._run_sqlmap(finding)

    def _run_nmap(self, host: Optional[str]) -> None:
        nmap = shutil.which("nmap")
        if not nmap or not host:
            return
        try:
            cmd = [nmap, "-sV", "-T4", "--top-ports", "100", host]
            if self.proxy_url:
                cmd.extend(["--proxies", self.proxy_url])
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            (self.out_dir / "nmap_results.txt").write_text(result.stdout, encoding="utf-8")
            logger.info("nmap scan complete")
        except Exception as exc:
            logger.warning("nmap failed: %s", exc)

    def _run_gobuster(self) -> None:
        gobuster = shutil.which("gobuster")
        if not gobuster:
            return
        try:
            cmd = [gobuster, "dir", "-u", self.app_url,
                   "-w", "/usr/share/wordlists/dirb/common.txt",
                   "-t", "10", "-o", str(self.out_dir / "gobuster_results.txt")]
            if self.proxy_url:
                cmd.extend(["-p", self.proxy_url])
            subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            logger.info("gobuster scan complete")
        except Exception as exc:
            logger.warning("gobuster failed: %s", exc)

    def _run_sqlmap(self, finding: Dict[str, Any]) -> None:
        sqlmap = shutil.which("sqlmap")
        if not sqlmap:
            return
        try:
            cmd = [sqlmap, "-u", self.app_url.rstrip("/"),
                   "--batch", "--level", "1", "--risk", "1", "--timeout", "30"]
            if self.proxy_url:
                cmd.extend(["--proxy", self.proxy_url])
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            if "injectable" in result.stdout.lower():
                finding["is_exploitable"] = True
                finding["ruling"] = "confirmed-by-sqlmap"
                logger.info("✓ sqlmap confirmed: %s", finding.get("rule_id"))
        except Exception as exc:
            logger.debug("sqlmap failed: %s", exc)


# ═══════════════════════════════════════════════════════════════════════════
# Module-level helpers
# ═══════════════════════════════════════════════════════════════════════════

def _init_llm_client():
    """Try to create an LLM client. Returns None if unavailable."""
    try:
        from packages.llm_analysis.llm.config import LLMConfig
        from packages.llm_analysis.llm.client import LLMClient
        return LLMClient(LLMConfig())
    except Exception as exc:
        logger.warning("No LLM available for validation: %s", exc)
        return None


def _extract_code_context(
    repo_path: Path,
    file_path: str,
    start_line: int,
    end_line: int,
) -> tuple:
    """
    Read the source file and extract:
      - vuln_code:          the exact vulnerable lines
      - surrounding_context: lines around it with line numbers

    Returns ("", "") if the file can't be read.
    """
    candidates = [repo_path / file_path, Path(file_path)]

    for path in candidates:
        if not path.exists():
            continue
        try:
            all_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            total = len(all_lines)

            # Vulnerable code (the exact lines)
            vs = max(0, start_line - 1)
            ve = min(total, end_line)
            vuln_code = "\n".join(all_lines[vs:ve])

            # Surrounding context (wider window with line numbers)
            cs = max(0, start_line - 1 - CONTEXT_LINES)
            ce = min(total, end_line + CONTEXT_LINES)
            context = "\n".join(
                f"{i+1:4d} | {line}"
                for i, line in enumerate(all_lines[cs:ce], start=cs)
            )
            return vuln_code, context
        except OSError:
            continue

    return "", ""


def _credential_impact(trufflehog_data: Dict) -> str:
    """
    Describe how a discovered credential can be abused.
    Maps detector name → concrete exploitation command.
    """
    detector = trufflehog_data.get("DetectorName", "").lower()
    verified = trufflehog_data.get("Verified", False)

    for key, impact in CREDENTIAL_IMPACT_MAP.items():
        if key in detector:
            return impact

    return f"Credential found ({'verified' if verified else 'unverified'}): {detector}"


def _llm_generate_exploit_and_patch(llm, finding: Dict[str, Any]) -> None:
    """
    Ask the LLM to produce an exploit PoC and a patch.
    Modifies `finding` dict in-place.
    """
    vuln_code = finding.get("vuln_code", "")
    context   = finding.get("surrounding_context", "")
    message   = finding.get("message", "")

    if not vuln_code and not context and not message:
        return

    prompt = (
        f"Vulnerability: {finding.get('vuln_type', '')}\n"
        f"File: {finding.get('file_path', '')}\n"
        f"Message: {message}\n"
        f"Reasoning: {finding.get('reasoning', '')}\n\n"
        f"Vulnerable code:\n```\n{vuln_code}\n```\n\n"
        f"Context:\n```\n{context}\n```\n\n"
        "Provide:\n"
        "1. EXPLOIT: A working proof-of-concept (code or curl command)\n"
        "2. PATCH: Fixed version of the vulnerable code\n"
        "3. REMEDIATION: One paragraph describing the fix\n\n"
        "Format your response exactly as:\n"
        "EXPLOIT:\n<code>\n\n"
        "PATCH:\n<code>\n\n"
        "REMEDIATION:\n<text>"
    )

    try:
        response = llm.generate(
            prompt=prompt,
            system_prompt=(
                "You are a security researcher. "
                "Generate exploit PoC and patch for the given vulnerability."
            ),
            temperature=0.2,
            max_tokens=4096,
        )
        if not response:
            return

        text = response.content if hasattr(response, "content") else str(response)
        sections = _parse_exploit_patch_sections(text)

        for key in ("exploit_code", "patch_code", "remediation"):
            if sections.get(key):
                finding[key] = sections[key]

    except Exception as exc:
        logger.debug("LLM exploit/patch generation failed: %s", exc)


def _parse_exploit_patch_sections(text: str) -> Dict[str, str]:
    """
    Parse the LLM response into exploit_code, patch_code, remediation sections.
    Strips markdown code fences from code sections.
    """
    sections = {"exploit_code": "", "patch_code": "", "remediation": ""}
    current_key = None

    for line in text.split("\n"):
        header = line.strip().upper()
        if header.startswith("EXPLOIT:"):
            current_key = "exploit_code"
            continue
        elif header.startswith("PATCH:"):
            current_key = "patch_code"
            continue
        elif header.startswith("REMEDIATION:"):
            current_key = "remediation"
            continue

        if current_key:
            sections[current_key] += line + "\n"

    # Strip markdown fences from code sections
    for key in ("exploit_code", "patch_code"):
        val = sections[key].strip()
        val = re.sub(r'^```\w*\s*\n?', '', val, flags=re.MULTILINE)
        val = re.sub(r'\n?```\s*$',    '', val, flags=re.MULTILINE)
        sections[key] = val.strip()

    sections["remediation"] = sections["remediation"].strip()
    return sections
