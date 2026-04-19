"""
Finding merger and deduplicator.

Merges LLM direct-scan findings with Semgrep/CodeQL SARIF findings into a
single normalised list, deduplicating overlapping results.

Deduplication strategy
──────────────────────
Two findings are considered duplicates when ALL of the following are true:
  1. Same file path (normalised, case-insensitive on Windows).
  2. Line ranges overlap (finding A covers some of the lines covered by B).
  3. Similarity score >= SIMILARITY_THRESHOLD:
       - Same vuln_type or cwe_id: +0.5
       - Both exploitable / both non-exploitable: +0.2
       - Similar rule_id (edit-distance-based): +0.1 … +0.3

When two findings are merged, we keep the one with the richer data (more
fields set, higher CVSS, more detailed reasoning), supplemented by unique
data from the other.  The merged finding records all source tools.

Output format
─────────────
Each finding dict has the canonical RAPTOR agentic schema fields:
    rule_id, file_path, start_line, end_line, severity, level,
    message, tool, vuln_type, cwe_id, is_exploitable, is_true_positive,
    exploitability_score, confidence, cvss_score_estimate, cvss_vector,
    reasoning, attack_scenario, impact, remediation, dataflow_summary,
    false_positive_reason, ruling
"""

from __future__ import annotations

import hashlib
import re
from typing import Any, Dict, List, Optional, Sequence

SIMILARITY_THRESHOLD = 0.5

# ---------------------------------------------------------------------------
# Normalisation helpers
# ---------------------------------------------------------------------------

def _norm_path(p: str) -> str:
    """
    Normalise a file path for comparison.

    Handles the common case where SARIF tools emit absolute paths like
    /home/user/.../repo/src/main/Foo.java while the LLM scanner uses
    relative paths like src/main/Foo.java.
    """
    p = p.replace("\\", "/").lower().strip()

    # Strip file:// URI prefix if present
    if p.startswith("file://"):
        p = p[7:]

    # Remove leading ./ and /
    while p.startswith("./") or p.startswith("/"):
        p = p.lstrip("./").lstrip("/")

    # For paths with directory components, try to find the repo-relative portion.
    if "/" in p:
        _REPO_MARKERS = (
            "src/", "lib/", "pkg/", "cmd/", "internal/",
            "config/", "conf/",
            "controllers/", "models/", "views/", "templates/",
            "routes/", "handlers/", "middleware/", "services/",
            "resources/", "public/", "static/", "assets/",
            "java/", "scala/", "kotlin/",
            "app/",  # app/ last because it's very common as a dir name
        )
        found_marker = False
        for marker in _REPO_MARKERS:
            # Match marker at start of string or after a /
            if p.startswith(marker):
                # Path already starts with the marker — it's repo-relative
                found_marker = True
                break
            idx = p.find("/" + marker)
            if idx != -1:
                p = p[idx + 1:]  # keep from marker onward
                found_marker = True
                break

        if not found_marker:
            # No marker match — file is likely at repo root or in an
            # unconventional directory. Use just the filename.
            # e.g. "home/kryp/repo/vuln-bank/app.py" -> "app.py"
            p = p.rsplit("/", 1)[-1]

    return p


def _overlap(a_start: int, a_end: int, b_start: int, b_end: int) -> bool:
    """Return True if two line ranges overlap (inclusive)."""
    return a_start <= b_end and b_start <= a_end


def _severity_level(sev: str) -> int:
    """Return a numeric severity level for ranking."""
    sev = (sev or "").lower()
    return {"critical": 5, "high": 4, "error": 4, "medium": 3, "warning": 3,
            "low": 2, "note": 1, "info": 1}.get(sev, 0)


def _token_set(s: str) -> set[str]:
    return set(re.findall(r"[a-z0-9]+", (s or "").lower()))


def _similarity(a: Dict, b: Dict) -> float:
    """
    Heuristic similarity score in [0, 1] between two findings.
    Only called when file paths already match and lines overlap.
    """
    score = 0.0

    # Vuln type match
    at = (a.get("vuln_type") or "").lower()
    bt = (b.get("vuln_type") or "").lower()
    if at and bt and at == bt:
        score += 0.5
    elif at and bt and (_token_set(at) & _token_set(bt)):
        score += 0.25

    # CWE match
    ac = (a.get("cwe_id") or "").upper()
    bc = (b.get("cwe_id") or "").upper()
    if ac and bc and ac == bc:
        score += 0.3

    # Rule ID similarity
    ar = _token_set(a.get("rule_id", ""))
    br = _token_set(b.get("rule_id", ""))
    if ar and br:
        iou = len(ar & br) / max(len(ar | br), 1)
        score += iou * 0.2

    return min(score, 1.0)


# ---------------------------------------------------------------------------
# Normalise a single finding from any source into the canonical schema
# ---------------------------------------------------------------------------

def normalise_finding(f: Dict[str, Any], tool_override: Optional[str] = None) -> Dict[str, Any]:
    """
    Normalise a raw finding from LLM scan, Semgrep SARIF, or CodeQL SARIF
    into the canonical RAPTOR finding schema.
    """
    out: Dict[str, Any] = {}

    # Identity
    out["rule_id"]   = f.get("rule_id") or f.get("id") or f.get("ruleId") or "unknown"
    out["file_path"] = f.get("file_path") or f.get("path") or f.get("file") or ""
    out["start_line"] = int(f.get("start_line") or f.get("line") or 0)
    out["end_line"]   = int(f.get("end_line") or out["start_line"] or 0)
    out["message"]    = f.get("message") or f.get("description") or ""

    # Tool attribution
    out["tool"] = tool_override or f.get("tool") or ""

    # Severity / level
    sev = (f.get("severity") or f.get("level") or f.get("severity_assessment") or "").lower()
    sev = sev.replace("error", "high").replace("warning", "medium").replace("note", "low")
    out["severity"] = sev or "unknown"
    out["level"]    = out["severity"]

    # Structured fields
    out["vuln_type"]   = f.get("vuln_type") or f.get("vuln_type") or ""
    out["cwe_id"]      = f.get("cwe_id") or ""
    out["confidence"]  = f.get("confidence") or ""

    # Boolean verdicts
    out["is_true_positive"] = f.get("is_true_positive")    # may be None
    out["is_exploitable"]   = f.get("is_exploitable") or f.get("exploitable") or False
    out["exploitability_score"] = f.get("exploitability_score")
    out["ruling"]            = f.get("ruling") or ""

    # CVSS
    out["cvss_score_estimate"] = f.get("cvss_score_estimate") or f.get("cvss_estimate")
    out["cvss_vector"]         = f.get("cvss_vector") or ""

    # Textual LLM fields
    out["reasoning"]             = f.get("reasoning") or ""
    out["attack_scenario"]       = f.get("attack_scenario") or ""
    out["impact"]                = f.get("impact") or ""
    out["remediation"]           = f.get("remediation") or ""
    out["dataflow_summary"]      = f.get("dataflow_summary") or ""
    out["false_positive_reason"] = f.get("false_positive_reason") or ""

    # Code / exploits / patches (pass-through)
    out["exploit_code"] = f.get("exploit_code") or f.get("code") or ""
    out["patch_code"]   = f.get("patch_code") or f.get("patch") or ""

    # Source tracking
    out["sources"] = f.get("sources") or ([out["tool"]] if out["tool"] else [])

    return out


# ---------------------------------------------------------------------------
# Richness score — used to choose the "better" finding when merging
# ---------------------------------------------------------------------------

def _richness(f: Dict) -> int:
    """Higher = more fields filled in and better quality."""
    score = 0
    for field in ("reasoning", "attack_scenario", "impact", "remediation",
                  "dataflow_summary", "cvss_vector", "cwe_id", "vuln_type"):
        if f.get(field):
            score += 1
    if f.get("cvss_score_estimate"):
        score += int(f["cvss_score_estimate"])  # higher CVSS → preferred
    if f.get("is_exploitable"):
        score += 2
    if f.get("exploit_code"):
        score += 3
    return score


def _merge_pair(primary: Dict, secondary: Dict) -> Dict:
    """
    Merge two duplicate findings, keeping primary as base and supplementing
    with any non-empty fields from secondary.  Combine source lists.
    """
    merged = dict(primary)
    for key, val in secondary.items():
        if key == "sources":
            continue
        if not merged.get(key) and val:
            merged[key] = val
    # Union of sources
    all_sources = list(dict.fromkeys(
        list(primary.get("sources") or []) +
        list(secondary.get("sources") or [])
    ))
    merged["sources"] = all_sources
    # Combine tool field
    merged["tool"] = ", ".join(s for s in all_sources if s) or merged.get("tool", "")
    return merged


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def merge_findings(
    llm_findings:    Sequence[Dict[str, Any]],
    sarif_findings:  Sequence[Dict[str, Any]],
    *,
    llm_tool_label:   str = "llmscan",
    sarif_tool_label: str = "",   # set per-finding if already tagged
) -> List[Dict[str, Any]]:
    """
    Merge and deduplicate LLM findings with Semgrep/CodeQL findings.

    Parameters
    ----------
    llm_findings:   Raw finding dicts from LLMScanner.
    sarif_findings: Normalised finding dicts from SARIF parsers (already
                    have 'tool' set to 'semgrep' or 'codeql').
    llm_tool_label: Tool label to stamp on LLM findings.
    sarif_tool_label: Override tool label for sarif findings (if not set).

    Returns
    -------
    List of merged, deduplicated, sorted finding dicts.
    """
    # 1. Normalise all findings
    norm_llm   = [normalise_finding(f, tool_override=llm_tool_label)  for f in llm_findings]
    norm_sarif = [normalise_finding(f, tool_override=sarif_tool_label or None) for f in sarif_findings]

    all_findings = norm_sarif + norm_llm   # SARIF first: they are ground-truth anchors

    # 2. Cluster duplicates with union-find
    n = len(all_findings)
    parent = list(range(n))

    def find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(x: int, y: int) -> None:
        px, py = find(x), find(y)
        if px != py:
            parent[px] = py

    for i in range(n):
        fi = all_findings[i]
        pi = _norm_path(fi["file_path"])
        si = fi["start_line"]
        ei = fi["end_line"]
        for j in range(i + 1, n):
            if find(i) == find(j):
                continue
            fj = all_findings[j]
            pj = _norm_path(fj["file_path"])
            if pi != pj:
                continue
            if not _overlap(si, ei, fj["start_line"], fj["end_line"]):
                continue
            if _similarity(fi, fj) >= SIMILARITY_THRESHOLD:
                union(i, j)

    # 3. For each cluster, merge into the richest primary
    clusters: Dict[int, List[int]] = {}
    for i in range(n):
        root = find(i)
        clusters.setdefault(root, []).append(i)

    merged: List[Dict[str, Any]] = []
    for indices in clusters.values():
        if len(indices) == 1:
            merged.append(all_findings[indices[0]])
        else:
            # Sort by richness descending; richer = primary
            sorted_idx = sorted(indices, key=lambda i: _richness(all_findings[i]), reverse=True)
            primary = all_findings[sorted_idx[0]]
            for idx in sorted_idx[1:]:
                primary = _merge_pair(primary, all_findings[idx])
            merged.append(primary)

    # 4. Sort: severity desc, then exploitable first, then file/line
    def sort_key(f: Dict) -> tuple:
        return (
            -_severity_level(f.get("severity", "")),
            0 if f.get("is_exploitable") else 1,
            -(f.get("cvss_score_estimate") or 0),
            f.get("file_path", ""),
            f.get("start_line", 0),
        )

    merged.sort(key=sort_key)
    return merged


def load_sarif_findings(sarif_path) -> List[Dict[str, Any]]:
    """
    Parse a SARIF file and return a flat list of normalised finding dicts.
    Handles both Semgrep and CodeQL SARIF formats.
    """
    import json
    from pathlib import Path

    sarif_path = Path(sarif_path)
    if not sarif_path.exists():
        return []

    try:
        data = json.loads(sarif_path.read_text(encoding="utf-8", errors="replace"))
    except (json.JSONDecodeError, OSError):
        return []

    findings: List[Dict[str, Any]] = []
    for run in data.get("runs", []):
        tool_name = (
            run.get("tool", {}).get("driver", {}).get("name", "")
            or run.get("tool", {}).get("name", "")
        ).lower()

        # Index rules by ID for message lookup
        rules: Dict[str, Dict] = {}
        for rule in run.get("tool", {}).get("driver", {}).get("rules", []):
            rules[rule["id"]] = rule

        for result in run.get("results", []):
            rule_id = result.get("ruleId", "")
            rule    = rules.get(rule_id, {})

            # Message
            msg = (
                result.get("message", {}).get("text", "")
                or rule.get("shortDescription", {}).get("text", "")
                or rule.get("fullDescription", {}).get("text", "")
                or ""
            )

            # Level / severity
            level = result.get("level", rule.get("defaultConfiguration", {}).get("level", "warning"))

            # Location(s)
            for loc in result.get("locations", [{}]):
                phys = loc.get("physicalLocation", {})
                uri  = phys.get("artifactLocation", {}).get("uri", "")
                reg  = phys.get("region", {})
                start_line = reg.get("startLine", 1)
                end_line   = reg.get("endLine", start_line)

                findings.append({
                    "rule_id":    rule_id,
                    "file_path":  uri,
                    "start_line": start_line,
                    "end_line":   end_line,
                    "message":    msg,
                    "level":      level,
                    "severity":   level,
                    "tool":       tool_name or "sarif",
                })

    return findings
