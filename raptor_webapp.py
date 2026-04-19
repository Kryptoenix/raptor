#!/usr/bin/env python3
"""
RAPTOR v2 — Web App Analysis Mode

Pipeline: Discovery → Validation → Reporting

Discovery: TruffleHog + Semgrep + CodeQL + LLMScan (web strategy)
Validation: Dedup → Validate → Exploit PoC → Patch → Remediation
Optional: Test findings against live APP URL via nmap/gobuster/sqlmap
"""

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from core.json import save_json
from core.logging import get_logger

logger = get_logger()


def main() -> int:
    ap = argparse.ArgumentParser(
        description="RAPTOR Web App Analysis — full pipeline"
    )
    ap.add_argument("--repo", required=True, help="Path to web application source code")
    ap.add_argument("--out", help="Output directory")
    # Tool toggles
    ap.add_argument("--semgrep", action="store_true", default=True, help="Run Semgrep (default: on)")
    ap.add_argument("--no-semgrep", action="store_true", help="Disable Semgrep")
    ap.add_argument("--codeql", action="store_true", default=False, help="Run CodeQL")
    ap.add_argument("--no-codeql", action="store_true", help="Disable CodeQL")
    ap.add_argument("--trufflehog", action="store_true", default=True, help="Run TruffleHog (default: on)")
    ap.add_argument("--no-trufflehog", action="store_true", help="Disable TruffleHog")
    ap.add_argument("--llmscan", action="store_true", default=True, help="Run LLMScan (default: on)")
    ap.add_argument("--no-llmscan", action="store_true", help="Disable LLMScan")
    # Web-specific options
    ap.add_argument("--app-url", default="", help="Target app URL for live testing")
    ap.add_argument("--proxy-url", default="", help="Proxy URL for all outbound requests")

    args = ap.parse_args()

    repo_path = Path(args.repo).resolve()
    if not repo_path.exists():
        print(f"✗ Repository not found: {repo_path}")
        return 1

    out_dir = Path(args.out) if args.out else Path(f"out/webapp_{repo_path.name}_{int(time.time())}")
    out_dir.mkdir(parents=True, exist_ok=True)

    # Resolve toggle flags
    use_semgrep = args.semgrep and not args.no_semgrep
    use_codeql = args.codeql and not args.no_codeql
    use_trufflehog = args.trufflehog and not args.no_trufflehog
    use_llmscan = args.llmscan and not args.no_llmscan

    start_time = time.time()

    print("\n" + "=" * 60)
    print("🌐 RAPTOR WEB APP ANALYSIS")
    print("=" * 60)
    print(f"  Repository: {repo_path.name}")
    print(f"  Strategy: webapp")
    tools = []
    if use_semgrep: tools.append("Semgrep")
    if use_codeql: tools.append("CodeQL")
    if use_trufflehog: tools.append("TruffleHog")
    if use_llmscan: tools.append("LLMScan")
    print(f"  Tools: {', '.join(tools) or 'none'}")
    if args.app_url:
        print(f"  App URL: {args.app_url}")
    if args.proxy_url:
        print(f"  Proxy: {args.proxy_url}")
    print()

    # ── Read README for context ──────────────────────────────────────
    from packages.discovery import DiscoveryOrchestrator
    readme = DiscoveryOrchestrator.read_readme(repo_path)

    # ══════════════════════════════════════════════════════════════════
    # PHASE 1: VULNERABILITY DISCOVERY
    # ══════════════════════════════════════════════════════════════════
    print("═" * 60)
    print("📡 PHASE 1: VULNERABILITY DISCOVERY")
    print("═" * 60 + "\n")

    discovery = DiscoveryOrchestrator(
        repo_path=repo_path,
        out_dir=out_dir / "discovery",
        strategy="webapp",
        readme_context=readme,
    )

    raw_findings = discovery.run(
        semgrep=use_semgrep,
        codeql=use_codeql,
        trufflehog=use_trufflehog,
        llmscan=use_llmscan,
    )

    print(f"\n  Discovery complete: {len(raw_findings)} raw findings\n")

    # ══════════════════════════════════════════════════════════════════
    # PHASE 2: VULNERABILITY VALIDATION
    # ══════════════════════════════════════════════════════════════════
    print("═" * 60)
    print("🔍 PHASE 2: VULNERABILITY VALIDATION")
    print("═" * 60 + "\n")

    from packages.validation import ValidationOrchestrator

    validator = ValidationOrchestrator(
        repo_path=repo_path,
        out_dir=out_dir / "validation",
        strategy="webapp",
        app_url=args.app_url,
        proxy_url=args.proxy_url,
    )

    validated = validator.run(raw_findings)

    # ══════════════════════════════════════════════════════════════════
    # FINAL REPORT
    # ══════════════════════════════════════════════════════════════════
    duration = time.time() - start_time

    report = {
        "tool": "raptor",
        "mode": "webapp",
        "repo": str(repo_path),
        "duration_seconds": duration,
        "discovery": {
            "raw_findings": len(raw_findings),
            "tools_used": tools,
            "errors": discovery.errors,
        },
        "validation": {
            "total_findings": len(validated),
            "exploitable": sum(1 for f in validated if f.get("is_exploitable")),
            "with_exploit": sum(1 for f in validated if f.get("exploit_code")),
            "with_patch": sum(1 for f in validated if f.get("patch_code")),
        },
        "results": validated,
    }

    report_file = out_dir / "merged_report.json"
    save_json(report_file, report)

    # Summary
    print("\n" + "=" * 60)
    print("🎉 ANALYSIS COMPLETE")
    print("=" * 60)
    print(f"  Total findings: {len(validated)}")
    print(f"  Exploitable: {sum(1 for f in validated if f.get('is_exploitable'))}")
    print(f"  With exploit PoC: {sum(1 for f in validated if f.get('exploit_code'))}")
    print(f"  With patch: {sum(1 for f in validated if f.get('patch_code'))}")
    print(f"  Duration: {duration:.1f}s")
    print(f"  Report: {report_file}")
    print("=" * 60 + "\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
