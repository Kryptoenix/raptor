"""
LLM Direct-Code Scanner.

Walks a repository, sends source chunks to an LLM with a security-focused
system prompt, and returns structured vulnerability findings.

Cross-file context injection:
  Before scanning each chunk, related files (repositories, models, services
  referenced by the chunk) are looked up in a pre-built index and their
  first 60 lines are included in the prompt. This reduces false positives
  caused by the LLM not being able to verify framework behaviour (e.g.
  Spring Data JPA vs raw JDBC queries).
"""

from __future__ import annotations

import json
import logging as _logging
import re as _re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

# Ensure repo root is on the path for cross-package imports
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from core.json import save_json
from .chunker import walk_repo, SourceChunk, is_scannable, _SKIP_DIRS, _security_tier

logger = _logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Security-focused system prompt
# ---------------------------------------------------------------------------

SECURITY_SYSTEM_PROMPT = (
    "You are a senior offensive security researcher and code auditor.\n"
    "Your task is to find REAL security vulnerabilities in source code chunks.\n"
    "\n"
    "RULES:\n"
    "\n"
    "1. PROOF-REQUIRED: Every finding MUST reference the exact vulnerable line(s). "
    "If you cannot point to a specific line that is insecure, do NOT report it.\n"
    "\n"
    "2. FRAMEWORK-AWARENESS:\n"
    "   - Spring Data JPA repository.save(entity) or @Query with :param bindings: "
    "NOT SQL injection unless you see raw string concatenation.\n"
    "   - PreparedStatement with ? placeholders: NOT injectable.\n"
    "   - BCrypt/Argon2 password hashing: secure. Plain String password storage: insecure.\n"
    "   - If a method calls another method whose body is not in this chunk, "
    "assess risk based on the visible code pattern (e.g. passing unsanitised "
    "user input to a method named 'query' or 'execute' IS worth flagging).\n"
    "\n"
    "3. VULNERABILITY SCOPE — report ALL of the following when found:\n"
    "   - SQL injection: raw string concatenation in SQL queries, "
    "JDBC Statement.execute with user input, unsanitised @Query, "
    "EntityManager.createNativeQuery with concatenation\n"
    "   - Cross-Site Scripting (XSS): user input rendered in HTML templates "
    "without escaping (th:utext, ${...} in JSP without c:out, raw output "
    "in Thymeleaf/Freemarker/Mustache, innerHTML assignment, "
    "document.write with user data)\n"
    "   - Cross-Site Request Forgery (CSRF): CSRF protection explicitly "
    "disabled (csrf().disable(), @DisableCsrf), missing CSRF tokens in "
    "forms that perform state-changing operations, no CSRF filter configured\n"
    "   - Broken Authentication / Session Management: missing authentication "
    "checks on sensitive endpoints, overly permissive security config "
    "(e.g. .antMatchers('/**').permitAll()), session fixation, weak "
    "password storage (MD5/SHA1/plaintext passwords)\n"
    "   - Security Misconfiguration: hardcoded secrets/credentials/API keys, "
    "debug mode enabled in production, default passwords, overly permissive "
    "CORS, exposed admin panels/consoles (e.g. /h2-console), verbose error "
    "messages leaking stack traces, application.secret left as default\n"
    "   - Sensitive Data Exposure: passwords logged or stored in plaintext, "
    "sensitive data in URL parameters, missing HTTPS enforcement\n"
    "   - Insecure Direct Object References (IDOR): accessing resources by "
    "user-supplied ID without authorisation checks\n"
    "   - Path traversal with user input\n"
    "   - SSRF, XXE, unsafe deserialization\n"
    "   - Command injection (Runtime.exec/os.system with user input)\n"
    "   - Insecure cryptography (MD5/SHA1 for passwords, ECB mode, static IV)\n"
    "\n"
    "4. CONFIDENCE CALIBRATION:\n"
    "   - If you can see the vulnerable code directly: confidence=high\n"
    "   - If the pattern strongly suggests a vulnerability but depends on "
    "unseen code: confidence=medium\n"
    "   - Do NOT suppress findings just because you cannot see 100% of the "
    "call chain. A controller that passes raw user input to a method called "
    "'executeQuery' IS suspicious and should be reported with appropriate "
    "confidence level.\n"
    "\n"
    "5. TEMPLATE & CONFIG FILES: When analysing HTML templates, JSP files, "
    "Thymeleaf templates, or configuration files (application.conf, "
    "application.properties, SecurityConfiguration), actively look for "
    "the vulnerability patterns listed above. Configuration files are "
    "especially important for CSRF, auth, and security misconfiguration.\n"
    "\n"
    "Output ONLY a valid JSON array. Each element has exactly these keys:\n"
    '{\n'
    '  "rule_id":              string  -- short snake_case id e.g. "sqli-native-query",\n'
    '  "vuln_type":            string  -- snake_case category,\n'
    '  "cwe_id":               string  -- "CWE-89" format,\n'
    '  "severity":             string  -- "critical" | "high" | "medium" | "low",\n'
    '  "start_line":           int     -- 1-based line of the vulnerable code,\n'
    '  "end_line":             int     -- last vulnerable line (>= start_line),\n'
    '  "message":              string  -- one sentence, cite the specific method/variable,\n'
    '  "reasoning":            string  -- cite the exact code that makes this exploitable,\n'
    '  "attack_scenario":      string  -- step-by-step with specific payload example,\n'
    '  "impact":               string  -- what an attacker concretely achieves,\n'
    '  "remediation":          string  -- specific fix with code example,\n'
    '  "is_exploitable":       bool,\n'
    '  "exploitability_score": float   -- 0.0-1.0,\n'
    '  "cvss_vector":          string  -- CVSS 3.1 vector or "",\n'
    '  "cvss_score_estimate":  float or null,\n'
    '  "confidence":           string  -- "high" | "medium" | "low"\n'
    "}\n"
    "\n"
    "Return [] if you find no confirmed issues. "
    "No markdown fences. No text outside the JSON array."
)


# ---------------------------------------------------------------------------
# Per-chunk prompt builder
# ---------------------------------------------------------------------------

def _build_chunk_prompt(chunk: SourceChunk, related_context: str = "") -> str:
    """
    Build the per-chunk security analysis prompt.

    related_context: brief snippets from other files in the same package that
    help the LLM understand data flow (e.g. the repository class referenced by
    the controller being analysed).
    """
    # Hint about what kind of file this is so the LLM knows what to look for
    file_lower = chunk.file_path.lower()
    file_hints = []
    if any(kw in file_lower for kw in ("security", "config", "auth")):
        file_hints.append("This appears to be a SECURITY CONFIGURATION file — "
                          "check for CSRF disabled, overly permissive access rules, "
                          "weak auth settings, exposed endpoints.")
    if any(kw in file_lower for kw in ("controller", "handler", "endpoint", "resource", "api")):
        file_hints.append("This appears to be a CONTROLLER/ENDPOINT — "
                          "check for missing auth checks, unsanitised input handling, "
                          "IDOR, injection via user parameters.")
    if any(ext in file_lower for ext in (".html", ".jsp", ".ftl", ".vm", ".hbs", ".erb", ".thymeleaf")):
        file_hints.append("This is a TEMPLATE file — "
                          "check for XSS (unescaped user output), "
                          "missing CSRF tokens in forms, template injection.")
    if any(kw in file_lower for kw in ("application.conf", "application.properties", ".env")):
        file_hints.append("This is an APPLICATION CONFIG file — "
                          "check for hardcoded secrets, default passwords, "
                          "debug mode, insecure default settings.")

    parts = [
        f"File: {chunk.file_path} (lines {chunk.start_line}-{chunk.end_line})",
        f"Language: {chunk.language or 'unknown'}",
        f"Chunk type: {chunk.chunk_type}" + (f" ({chunk.name})" if chunk.name else ""),
    ]
    if file_hints:
        parts += ["", "FILE CONTEXT HINTS:"] + [f"  - {h}" for h in file_hints]
    parts += [
        "",
        "PRIMARY CODE TO ANALYSE:",
        f"```{chunk.language}",
        chunk.content,
        "```",
    ]
    if related_context:
        parts += [
            "",
            "RELATED FILES (for cross-file context — helps assess data flow):",
            related_context,
        ]
    parts += [
        "",
        "Analyse the PRIMARY CODE for ALL security vulnerabilities from the "
        "scope defined in the system prompt.",
        "Report findings at the appropriate confidence level.",
        "For framework-managed code (ORM, prepared statements), only flag "
        "injection if you see raw string concatenation.",
        "Return ONLY a JSON array as specified in the system prompt.",
    ]
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# LLM Scanner
# ---------------------------------------------------------------------------

class LLMScanner:
    """
    Walk a repository and use an LLM to find security vulnerabilities directly
    in source code, without relying on static analysis rules.
    """

    def __init__(
        self,
        repo_path: Path,
        out_dir: Path,
        max_files: int = 200,
        max_chunks_per_file: int = 20,
        concurrency: int = 1,
        llm_config=None,
    ) -> None:
        self.repo_path = Path(repo_path).resolve()
        self.out_dir   = Path(out_dir)
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.max_files           = max_files
        self.max_chunks_per_file = max_chunks_per_file
        self.concurrency         = concurrency

        # Initialise LLM client
        try:
            from packages.llm_analysis.llm.config import LLMConfig
            from packages.llm_analysis.llm.client import LLMClient
            cfg = llm_config or LLMConfig()
            self.llm = LLMClient(cfg)
            self._has_llm = True
            logger.info(
                "LLM direct scanner: %s/%s",
                cfg.primary_model.provider if cfg.primary_model else "?",
                cfg.primary_model.model_name if cfg.primary_model else "?",
            )
        except Exception as exc:
            logger.warning("No LLM available for direct scan: %s", exc)
            self.llm = None
            self._has_llm = False

    # ── Public entry point ──────────────────────────────────────────────────

    def scan(self) -> List[Dict[str, Any]]:
        """
        Scan the repository and return a list of raw finding dicts.
        Results are also saved to out_dir/llmscan_findings.json.
        """
        if not self._has_llm:
            logger.error(
                "LLM direct scan requires an external LLM (ANTHROPIC_API_KEY, "
                "OPENAI_API_KEY, etc.). No LLM configured."
            )
            return []

        logger.info("=" * 60)
        logger.info("RAPTOR LLM DIRECT-CODE SCAN")
        logger.info("Repo: %s", self.repo_path)
        logger.info("Max files: %d", self.max_files)
        logger.info("=" * 60)

        # Build cross-file context index
        context_index = self._build_context_index()
        logger.info("Context index built: %d files indexed", len(context_index))

        all_findings: List[Dict[str, Any]] = []
        stats = {"files": 0, "chunks": 0, "findings": 0, "errors": 0}
        current_file = ""
        chunks_this_file = 0

        for chunk in walk_repo(self.repo_path, max_files=self.max_files):
            if chunk.file_path != current_file:
                current_file = chunk.file_path
                chunks_this_file = 0
                stats["files"] += 1

            if chunks_this_file >= self.max_chunks_per_file:
                continue
            chunks_this_file += 1
            stats["chunks"] += 1

            related = self._gather_related_context(chunk, context_index)
            findings = self._scan_chunk(chunk, related_context=related)
            all_findings.extend(findings)
            stats["findings"] += len(findings)

            if findings:
                logger.info(
                    "  [+] %s:%d-%d -- %d finding(s)",
                    chunk.file_path,
                    chunk.start_line,
                    chunk.end_line,
                    len(findings),
                )

        logger.info(
            "LLM scan complete: %d files, %d chunks, %d findings",
            stats["files"], stats["chunks"], stats["findings"],
        )

        out_file = self.out_dir / "llmscan_findings.json"
        save_json(out_file, {
            "tool": "llmscan",
            "repo": str(self.repo_path),
            "stats": stats,
            "findings": all_findings,
        })
        logger.info("LLM scan results: %s", out_file)

        return all_findings

    # ── Cross-file context ──────────────────────────────────────────────────

    def _build_context_index(self) -> Dict[str, List[tuple]]:
        """
        Index: lowercase_stem -> [(rel_path, first_120_lines_excerpt), ...]
        Allows controllers to find their repositories, models, services etc.
        Also logs file tier statistics for visibility.
        """
        index: Dict[str, List[tuple]] = {}
        count = 0
        limit = self.max_files * 2
        tier_counts = {1: 0, 2: 0, 3: 0}
        total_scannable = 0

        for abs_path in sorted(self.repo_path.rglob("*")):
            if not abs_path.is_file():
                continue
            try:
                rel_parts = abs_path.relative_to(self.repo_path).parts
            except ValueError:
                continue
            if any(p in _SKIP_DIRS for p in rel_parts[:-1]):
                continue
            if not is_scannable(abs_path):
                continue

            total_scannable += 1
            rel = abs_path.relative_to(self.repo_path)
            tier = _security_tier(rel)
            tier_counts[tier] = tier_counts.get(tier, 0) + 1

            if count >= limit:
                continue  # keep counting total_scannable but stop indexing

            try:
                text = abs_path.read_text(encoding="utf-8", errors="replace")
                lines = text.splitlines()
                excerpt = "\n".join(lines[:120])
                stem = abs_path.stem.lower()
                index.setdefault(stem, []).append((str(rel), excerpt))
                count += 1
            except OSError:
                pass

        # Log tier breakdown so user knows what's being prioritised
        logger.info(
            "File inventory: %d scannable files "
            "(T1-high: %d, T2-medium: %d, T3-low: %d)",
            total_scannable, tier_counts[1], tier_counts[2], tier_counts[3],
        )
        if total_scannable > self.max_files:
            logger.info(
                "Budget: %d files (T1 always included; T2/T3 fill remaining)",
                self.max_files,
            )

        return index

    def _gather_related_context(
        self,
        chunk: SourceChunk,
        index: Dict[str, List[tuple]],
    ) -> str:
        """
        Find related files by matching CamelCase/snake_case identifiers from
        the chunk content against file stems in the index. Returns a compact
        string with labelled excerpts (max ~800 chars to avoid token waste).
        """
        content = chunk.content
        file_stem = Path(chunk.file_path).stem.lower()

        # Extract identifiers: CamelCase words and dot-separated import paths
        raw_idents = _re.findall(r"[A-Z][a-z]+[A-Za-z]*|[a-z]{3,}[A-Z][A-Za-z]*", content)
        # Also break apart package/import strings like "sec.project.repository.UserRepo"
        import_paths = _re.findall(r"[a-zA-Z][a-zA-Z0-9_]{2,}", content)
        identifiers = set(i.lower() for i in raw_idents + import_paths if len(i) > 3)

        MAX_CHARS = 2000
        related_parts: List[str] = []
        seen_paths: set = set()

        for ident in sorted(identifiers):
            if sum(len(p) for p in related_parts) >= MAX_CHARS:
                break
            if ident == file_stem:
                continue
            matches = index.get(ident, [])
            for rel_path, excerpt in matches:
                if rel_path in seen_paths or rel_path == chunk.file_path:
                    continue
                seen_paths.add(rel_path)
                budget = MAX_CHARS - sum(len(p) for p in related_parts)
                if budget < 60:
                    break
                trimmed = excerpt[:budget]
                related_parts.append(f"// {rel_path}\n{trimmed}")
                break  # one match per stem

        return "\n\n".join(related_parts)

    # ── Internal helpers ────────────────────────────────────────────────────

    def _scan_chunk(
        self,
        chunk: SourceChunk,
        related_context: str = "",
    ) -> List[Dict[str, Any]]:
        """Send one chunk to the LLM and parse the findings."""
        prompt = _build_chunk_prompt(chunk, related_context=related_context)
        try:
            response = self.llm.generate(
                prompt=prompt,
                system_prompt=SECURITY_SYSTEM_PROMPT,
                temperature=0.1,
                max_tokens=8192,  # Ensure enough room for full JSON findings
            )
            if response is None:
                return []

            raw_text = (
                response.content if hasattr(response, "content") else str(response)
            ).strip()
            findings = self._parse_response(raw_text, chunk)

            # If parsing failed but the LLM clearly started producing JSON
            # (contains { but we got 0 findings), the response was truncated.
            # Retry with a much shorter prompt to free up output token budget.
            if not findings and len(raw_text) > 20 and "{" in raw_text:
                logger.info(
                    "Retrying %s:%d-%d with compact prompt "
                    "(response truncated, %d chars produced 0 findings)",
                    chunk.file_path, chunk.start_line, chunk.end_line, len(raw_text),
                )
                compact_prompt = (
                    f"File: {chunk.file_path} ({chunk.language or 'unknown'})\n"
                    f"```\n{chunk.content}\n```\n"
                    "List security vulnerabilities as JSON array. Each object: "
                    "rule_id, vuln_type, cwe_id, severity, start_line, end_line, "
                    "message, reasoning, is_exploitable, confidence. "
                    "Keep message/reasoning under 30 words. Return [] if none."
                )
                try:
                    retry_resp = self.llm.generate(
                        prompt=compact_prompt,
                        system_prompt="Security auditor. Find vulnerabilities. JSON only.",
                        temperature=0.1,
                        max_tokens=8192,
                    )
                    if retry_resp:
                        retry_text = (
                            retry_resp.content if hasattr(retry_resp, "content")
                            else str(retry_resp)
                        ).strip()
                        retry_findings = self._parse_response(retry_text, chunk)
                        if retry_findings:
                            logger.info(
                                "Compact retry recovered %d finding(s) for %s",
                                len(retry_findings), chunk.file_path,
                            )
                            return retry_findings
                        else:
                            logger.warning(
                                "Compact retry also failed for %s", chunk.file_path,
                            )
                except Exception as retry_exc:
                    logger.warning(
                        "Compact retry error for %s: %s", chunk.file_path, retry_exc,
                    )

            return findings

        except Exception as exc:
            logger.warning(
                "LLM scan error for %s:%d: %s",
                chunk.file_path,
                chunk.start_line,
                exc,
            )
            return []

    def _parse_response(
        self, raw: str, chunk: SourceChunk
    ) -> List[Dict[str, Any]]:
        """Parse the LLM JSON response into validated finding dicts."""
        text = raw.strip()

        # Strip markdown fences if the model added them
        if text.startswith("```"):
            lines = text.split("\n")
            text = "\n".join(lines[1:] if lines[0].startswith("```") else lines)
            if text.endswith("```"):
                text = text[: text.rfind("```")].rstrip()

        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            m = _re.search(r"\[[\s\S]*\]", text)
            if m:
                try:
                    parsed = json.loads(m.group())
                except json.JSONDecodeError:
                    # Try to salvage truncated JSON — extract complete objects
                    parsed = self._salvage_truncated_json(text, chunk)
                    if not parsed:
                        logger.warning("Could not parse LLM response for %s: %s",
                                       chunk.file_path, text[:200])
                        return []
            else:
                # No closing ] found — likely truncated output. Try salvage.
                parsed = self._salvage_truncated_json(text, chunk)
                if not parsed:
                    logger.debug("No JSON array found in LLM response for %s: %s",
                                 chunk.file_path, text[:200])
                    return []

        if not isinstance(parsed, list):
            return []

        # Cap findings per chunk — a local LLM producing 40+ findings for a
        # single chunk is almost certainly hallucinating. Real code rarely has
        # more than ~10 distinct vulnerabilities in a 300-line chunk.
        MAX_FINDINGS_PER_CHUNK = 15
        if len(parsed) > MAX_FINDINGS_PER_CHUNK:
            logger.warning(
                "LLM reported %d findings for %s:%d-%d — capping at %d (likely hallucination)",
                len(parsed), chunk.file_path, chunk.start_line, chunk.end_line,
                MAX_FINDINGS_PER_CHUNK,
            )
            parsed = parsed[:MAX_FINDINGS_PER_CHUNK]

        findings: List[Dict[str, Any]] = []
        for raw_f in parsed:
            if not isinstance(raw_f, dict):
                continue

            # ── Quality gate: reject empty/garbage findings ──────────────
            # A valid finding must have at least a message OR reasoning that
            # explains what the vulnerability is. Findings with all empty
            # fields are noise from the LLM failing to produce structured output.
            msg = (raw_f.get("message") or "").strip()
            reasoning = (raw_f.get("reasoning") or "").strip()
            vuln_type = (raw_f.get("vuln_type") or "").strip()

            if not msg and not reasoning:
                # No message and no reasoning — this finding says nothing useful.
                # Skip it silently (don't even log — these are common with local models).
                continue

            if not msg and not vuln_type:
                # Has reasoning but no message and no vuln_type — too vague to be useful.
                continue

            # Translate line numbers: LLM may report relative (1-based within chunk)
            # or absolute. We accept both and clamp to chunk range.
            start = int(raw_f.get("start_line", chunk.start_line))
            end   = int(raw_f.get("end_line", start))

            # If reported lines look relative (1..chunk_length), translate to file coords
            chunk_len = chunk.end_line - chunk.start_line + 1
            if start <= chunk_len and end <= chunk_len:
                start = chunk.start_line + start - 1
                end   = chunk.start_line + end   - 1

            # Hard clamp to chunk bounds
            start = max(chunk.start_line, min(start, chunk.end_line))
            end   = max(start,            min(end,   chunk.end_line))

            finding = {
                "rule_id":              raw_f.get("rule_id", "llm-finding"),
                "file_path":            chunk.file_path,
                "start_line":           start,
                "end_line":             end,
                "message":              raw_f.get("message", ""),
                "severity":             (raw_f.get("severity") or "medium").lower(),
                "level":                (raw_f.get("severity") or "medium").lower(),
                "vuln_type":            raw_f.get("vuln_type", ""),
                "cwe_id":               raw_f.get("cwe_id", ""),
                "reasoning":            raw_f.get("reasoning", ""),
                "attack_scenario":      raw_f.get("attack_scenario", ""),
                "impact":               raw_f.get("impact", ""),
                "remediation":          raw_f.get("remediation", ""),
                "is_exploitable":       bool(raw_f.get("is_exploitable", False)),
                "is_true_positive":     True,
                "exploitability_score": raw_f.get("exploitability_score"),
                "confidence":           raw_f.get("confidence", "medium"),
                "cvss_vector":          raw_f.get("cvss_vector", ""),
                "cvss_score_estimate":  raw_f.get("cvss_score_estimate"),
                "tool":                 "llmscan",
                "sources":              ["llmscan"],
            }
            findings.append(finding)

        return findings

    @staticmethod
    def _salvage_truncated_json(text: str, chunk: SourceChunk) -> Optional[list]:
        """
        Attempt to recover complete JSON objects from a truncated LLM response.

        When the LLM runs out of output tokens, the JSON array is cut off
        mid-object. This method finds all complete {...} objects within the
        text and returns them as a list.

        Example truncated input:
            [{"rule_id": "xss", "severity": "high", ...}, {"rule_id": "csrf
        Returns:
            [{"rule_id": "xss", "severity": "high", ...}]
        """
        # Find all complete top-level JSON objects using brace matching
        objects = []
        depth = 0
        obj_start = None
        in_string = False
        escape_next = False

        for i, ch in enumerate(text):
            if escape_next:
                escape_next = False
                continue
            if ch == '\\' and in_string:
                escape_next = True
                continue
            if ch == '"' and not escape_next:
                in_string = not in_string
                continue
            if in_string:
                continue

            if ch == '{':
                if depth == 0:
                    obj_start = i
                depth += 1
            elif ch == '}':
                depth -= 1
                if depth == 0 and obj_start is not None:
                    candidate = text[obj_start:i + 1]
                    try:
                        obj = json.loads(candidate)
                        if isinstance(obj, dict) and obj.get("rule_id"):
                            objects.append(obj)
                    except json.JSONDecodeError:
                        pass
                    obj_start = None

        if objects:
            logger.info(
                "Salvaged %d complete finding(s) from truncated LLM response for %s",
                len(objects), chunk.file_path,
            )
        return objects or None
