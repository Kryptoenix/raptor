#!/usr/bin/env python3
"""
RAPTOR LLM Direct-Code Scanner

Walks a repository, chunks source files intelligently (by file, function,
class, or sliding window), sends each chunk to an LLM with a
security-focused system prompt, collects structured findings, then merges
and deduplicates them with any existing Semgrep/CodeQL SARIF output.

Usage:
    python3 raptor_llmscan.py --repo /path/to/repo [options]

Output:
    out/<name>/llmscan/
        llmscan_findings.json     — raw LLM findings
        merged_findings.json      — merged + deduplicated with SARIF
        merged_report.json        — full report (summary + all findings)
"""

import argparse
import json
import sys
import time
from pathlib import Path

# Ensure repo root is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from core.config import RaptorConfig
from core.json import save_json
from core.logging import get_logger
from packages.llm_scan import LLMScanner, merge_findings
from packages.llm_scan.merger import load_sarif_findings, normalise_finding

logger = get_logger()


def main() -> None:
    ap = argparse.ArgumentParser(
        description="RAPTOR LLM Direct-Code Scanner — AI-powered vulnerability discovery",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan a repository with LLM only
  python3 raptor_llmscan.py --repo /path/to/repo

  # Scan and merge with existing Semgrep/CodeQL SARIF files
  python3 raptor_llmscan.py --repo /path/to/repo --sarif out/scan_*/semgrep*.sarif

  # Limit scope for fast triage
  python3 raptor_llmscan.py --repo /path/to/repo --max-files 50

  # Write output to a specific directory
  python3 raptor_llmscan.py --repo /path/to/repo --out out/my_scan
""",
    )

    ap.add_argument("--repo",      required=True,         help="Path to repository to scan")
    ap.add_argument("--out",                              help="Output directory (default: out/llmscan_<name>_<ts>)")
    ap.add_argument("--sarif",     nargs="*", default=[], help="SARIF files to merge with LLM findings (glob patterns accepted)")
    ap.add_argument("--max-files", type=int, default=200, help="Maximum source files to scan (default: 200)")
    ap.add_argument("--max-chunks-per-file", type=int, default=20, help="Maximum chunks per file (default: 20)")
    ap.add_argument("--no-merge",  action="store_true",   help="Skip merging with SARIF; output LLM findings only")
    ap.add_argument("--min-severity", default="low",
                    choices=["critical", "high", "medium", "low"],
                    help="Minimum severity to include in merged output (default: low)")
    args = ap.parse_args()

    repo_path = Path(args.repo).resolve()
    if not repo_path.exists():
        print(f"✗ Repository not found: {repo_path}")
        sys.exit(1)

    repo_name = repo_path.name
    timestamp = int(time.time())
    if args.out:
        out_dir = Path(args.out)
    else:
        out_dir = RaptorConfig.get_out_dir() / f"llmscan_{repo_name}_{timestamp}"
    out_dir.mkdir(parents=True, exist_ok=True)

    print("\n" + "=" * 70)
    print("RAPTOR LLM DIRECT-CODE SCANNER")
    print("=" * 70)
    print(f"  Repository : {repo_path}")
    print(f"  Output     : {out_dir}")
    print(f"  Max files  : {args.max_files}")
    print("=" * 70 + "\n")

    logger.info("=" * 70)
    logger.info("RAPTOR LLM DIRECT-CODE SCAN STARTED")
    logger.info("Repo: %s", repo_path)
    logger.info("Output: %s", out_dir)
    logger.info("=" * 70)

    # ── Phase 1: LLM scan ──────────────────────────────────────────────────
    print("[1/3] Running LLM direct-code analysis...")
    scanner = LLMScanner(
        repo_path=repo_path,
        out_dir=out_dir / "llmscan",
        max_files=args.max_files,
        max_chunks_per_file=args.max_chunks_per_file,
    )
    llm_findings = scanner.scan()
    print(f"      Found {len(llm_findings)} raw LLM finding(s)")

    # ── Phase 2: Load SARIF findings ───────────────────────────────────────
    sarif_findings = []
    if args.sarif and not args.no_merge:
        import glob
        print("[2/3] Loading SARIF findings for merge...")
        for pattern in args.sarif:
            for sarif_file in sorted(glob.glob(str(pattern), recursive=True)):
                loaded = load_sarif_findings(sarif_file)
                print(f"      {sarif_file}: {len(loaded)} finding(s)")
                sarif_findings.extend(loaded)
    else:
        print("[2/3] Skipping SARIF merge (no --sarif specified or --no-merge set)")

    # ── Phase 3: Merge & deduplicate ───────────────────────────────────────
    print("[3/3] Merging and deduplicating findings...")
    if args.no_merge or not sarif_findings:
        # No merge — just normalise LLM findings
        merged = [normalise_finding(f, tool_override="llmscan") for f in llm_findings]
    else:
        merged = merge_findings(
            llm_findings=llm_findings,
            sarif_findings=sarif_findings,
        )

    # Apply minimum severity filter
    sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    min_rank = sev_rank.get(args.min_severity, 0)
    merged = [f for f in merged if sev_rank.get(f.get("severity", "low"), 0) >= min_rank]

    # ── Save results ───────────────────────────────────────────────────────
    merged_file = out_dir / "merged_findings.json"
    save_json(merged_file, merged)

    # Build summary
    from collections import Counter
    sev_counts = Counter(f.get("severity", "unknown") for f in merged)
    tool_counts = Counter()
    for f in merged:
        for t in (f.get("sources") or [f.get("tool", "unknown")]):
            tool_counts[t] += 1

    exploitable = sum(1 for f in merged if f.get("is_exploitable"))
    llm_only    = sum(1 for f in merged if f.get("sources") == ["llmscan"] or f.get("tool") == "llmscan")
    sarif_only  = sum(1 for f in merged if all(t != "llmscan" for t in (f.get("sources") or [])))
    both        = len(merged) - llm_only - sarif_only

    report = {
        "tool":     "llmscan",
        "repo":     str(repo_path),
        "mode":     "llmscan",
        "total_findings": len(merged),
        "exploitable":    exploitable,
        "severity_breakdown": dict(sev_counts),
        "source_breakdown": {
            "llm_only":  llm_only,
            "sarif_only": sarif_only,
            "merged_both": both,
        },
        "tool_breakdown": dict(tool_counts),
        "results": merged,
    }

    report_file = out_dir / "merged_report.json"
    save_json(report_file, report)

    # ── Summary output ─────────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("LLM SCAN COMPLETE")
    print("=" * 70)
    print(f"  Total findings : {len(merged)}")
    print(f"  Exploitable    : {exploitable}")
    for sev in ["critical", "high", "medium", "low"]:
        cnt = sev_counts.get(sev, 0)
        if cnt:
            print(f"  {sev.capitalize():<12} : {cnt}")
    if sarif_findings:
        print(f"\n  Source breakdown:")
        print(f"    LLM only        : {llm_only}")
        print(f"    SARIF only      : {sarif_only}")
        print(f"    Confirmed (both): {both}")
    print(f"\n  Outputs:")
    print(f"    LLM findings    : {out_dir}/llmscan/llmscan_findings.json")
    print(f"    Merged findings : {merged_file}")
    print(f"    Full report     : {report_file}")
    print("=" * 70 + "\n")

    logger.info("LLM scan complete: %d findings (%d exploitable)", len(merged), exploitable)

    return 0 if not merged else 1


if __name__ == "__main__":
    try:
        sys.exit(main() or 0)
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
        sys.exit(130)
