#!/usr/bin/env python3
"""
RAPTOR v2 — Binary Analysis Mode

Pipeline: Discovery → Validation → Fuzzing (optional) → Reporting

Two sub-modes:
  --repo: Given source code → compile, instrument, fuzz, analyse
  --binary: Given compiled binary → reverse engineer, analyse, fuzz

Discovery: TruffleHog + Semgrep + CodeQL + LLMScan (binary strategy)
Validation: Dedup → Validate → Exploit PoC → Patch
Fuzzing: AFL++ instrumentation, corpus gen, crash analysis with gdb/valgrind
"""

import argparse
import shutil
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from core.json import save_json
from core.logging import get_logger

logger = get_logger()


def main() -> int:
    ap = argparse.ArgumentParser(
        description="RAPTOR Binary Analysis — full pipeline"
    )
    # Input: source repo or pre-compiled binary
    input_group = ap.add_mutually_exclusive_group(required=True)
    input_group.add_argument("--repo", help="Path to C/C++ source repository")
    input_group.add_argument("--binary", help="Path to pre-compiled binary")

    ap.add_argument("--out", help="Output directory")
    # Tool toggles
    ap.add_argument("--semgrep", action="store_true", default=True)
    ap.add_argument("--no-semgrep", action="store_true")
    ap.add_argument("--codeql", action="store_true", default=False)
    ap.add_argument("--no-codeql", action="store_true")
    ap.add_argument("--trufflehog", action="store_true", default=True)
    ap.add_argument("--no-trufflehog", action="store_true")
    ap.add_argument("--llmscan", action="store_true", default=True)
    ap.add_argument("--no-llmscan", action="store_true")
    ap.add_argument("--fuzz", action="store_true", default=False, help="Run AFL++ fuzzing")
    ap.add_argument("--no-fuzz", action="store_true")
    # Fuzzing options
    ap.add_argument("--duration", type=int, default=3600, help="Fuzzing duration (seconds)")
    ap.add_argument("--asan", action="store_true", help="Enable AddressSanitizer")
    ap.add_argument("--corpus", help="Path to seed corpus")
    ap.add_argument("--target-binary", help="Name of binary after build (if repo produces multiple)")
    # Binary-specific
    ap.add_argument("--bug-track-url", default="", help="URL with crash/PoC to parse")
    ap.add_argument("--emulate", action="store_true", help="Attempt firmware emulation with QEMU")

    args = ap.parse_args()

    start_time = time.time()
    is_source_mode = bool(args.repo)

    if is_source_mode:
        repo_path = Path(args.repo).resolve()
        if not repo_path.exists():
            print(f"✗ Repository not found: {repo_path}")
            return 1
        target_name = repo_path.name
    else:
        binary_path = Path(args.binary).resolve()
        if not binary_path.exists():
            print(f"✗ Binary not found: {binary_path}")
            return 1
        target_name = binary_path.stem
        repo_path = binary_path.parent

    out_dir = Path(args.out) if args.out else Path(f"out/binary_{target_name}_{int(time.time())}")
    out_dir.mkdir(parents=True, exist_ok=True)

    use_semgrep = args.semgrep and not args.no_semgrep
    use_codeql = args.codeql and not args.no_codeql
    use_trufflehog = args.trufflehog and not args.no_trufflehog
    use_llmscan = args.llmscan and not args.no_llmscan
    use_fuzz = args.fuzz and not args.no_fuzz

    print("\n" + "=" * 60)
    print("🔧 RAPTOR BINARY ANALYSIS")
    print("=" * 60)
    print(f"  Target: {target_name}")
    print(f"  Mode: {'source code' if is_source_mode else 'pre-compiled binary'}")
    tools = []
    if use_semgrep: tools.append("Semgrep")
    if use_codeql: tools.append("CodeQL")
    if use_trufflehog: tools.append("TruffleHog")
    if use_llmscan: tools.append("LLMScan")
    if use_fuzz: tools.append("AFL++")
    print(f"  Tools: {', '.join(tools) or 'none'}")
    print()

    all_findings = []

    # ══════════════════════════════════════════════════════════════════
    # PHASE 0: BUG TRACK URL (if provided)
    # Fetch crash/PoC from a URL and analyse immediately with gdb/rr
    # ══════════════════════════════════════════════════════════════════
    if args.bug_track_url:
        print("═" * 60)
        print("🐛 PHASE 0: BUG TRACK URL ANALYSIS")
        print("═" * 60 + "\n")

        bug_findings = _fetch_and_analyse_bug_url(
            args.bug_track_url,
            binary_path if not is_source_mode else None,
            out_dir,
        )
        all_findings.extend(bug_findings)
        print(f"\n  Bug track URL: {len(bug_findings)} finding(s)\n")

    # ══════════════════════════════════════════════════════════════════
    # PHASE 1: VULNERABILITY DISCOVERY (source code analysis)
    # ══════════════════════════════════════════════════════════════════
    if is_source_mode and any([use_semgrep, use_codeql, use_trufflehog, use_llmscan]):
        print("═" * 60)
        print("📡 PHASE 1: VULNERABILITY DISCOVERY")
        print("═" * 60 + "\n")

        from packages.discovery import DiscoveryOrchestrator
        readme = DiscoveryOrchestrator.read_readme(repo_path)

        discovery = DiscoveryOrchestrator(
            repo_path=repo_path,
            out_dir=out_dir / "discovery",
            strategy="binary",
            readme_context=readme,
        )

        raw_findings = discovery.run(
            semgrep=use_semgrep,
            codeql=use_codeql,
            trufflehog=use_trufflehog,
            llmscan=use_llmscan,
        )
        all_findings.extend(raw_findings)
        print(f"\n  Discovery: {len(raw_findings)} raw findings\n")

    # ══════════════════════════════════════════════════════════════════
    # PHASE 2: FUZZING (source mode: compile + instrument + fuzz)
    # ══════════════════════════════════════════════════════════════════
    fuzz_findings = []
    if use_fuzz:
        print("═" * 60)
        print("🔨 PHASE 2: AFL++ FUZZING")
        print("═" * 60 + "\n")

        if is_source_mode:
            fuzz_findings = _fuzz_from_source(
                repo_path, out_dir, args
            )
        else:
            fuzz_findings = _fuzz_binary(
                binary_path, out_dir, args
            )
        all_findings.extend(fuzz_findings)

    # ══════════════════════════════════════════════════════════════════
    # PHASE 2.5: QEMU FIRMWARE EMULATION (if --emulate and binary exists)
    # Useful for cross-architecture firmware binaries (ARM, MIPS, etc.)
    # ══════════════════════════════════════════════════════════════════
    if args.emulate:
        print("═" * 60)
        print("🖥️  PHASE 2.5: QEMU FIRMWARE EMULATION")
        print("═" * 60 + "\n")

        # Find the binary: either the user-provided one, or the one
        # built during Phase 2, or the one found in the repo
        emul_binary = None
        if not is_source_mode:
            emul_binary = binary_path
        else:
            # Find the most likely target in the repo
            from raptor_fuzzing import _find_instrumented_binary
            emul_binary = _find_instrumented_binary(
                repo_path, repo_path, args.target_binary
            )

        if emul_binary and emul_binary.exists():
            emul_findings = _emulate_with_qemu(emul_binary, out_dir)
            all_findings.extend(emul_findings)
            print(f"\n  Emulation: {len(emul_findings)} finding(s)\n")
        else:
            print("  ⚠ No binary found to emulate — skipping\n")

    # ══════════════════════════════════════════════════════════════════
    # PHASE 3: BINARY ANALYSIS (valgrind, gdb, reverse engineering)
    # ══════════════════════════════════════════════════════════════════
    if not is_source_mode:
        print("═" * 60)
        print("🔬 PHASE 3: BINARY ANALYSIS")
        print("═" * 60 + "\n")

        binary_findings = _analyse_binary(binary_path, out_dir)
        all_findings.extend(binary_findings)

    # ══════════════════════════════════════════════════════════════════
    # PHASE 4: VULNERABILITY VALIDATION
    # ══════════════════════════════════════════════════════════════════
    if all_findings:
        print("═" * 60)
        print("🔍 PHASE 4: VULNERABILITY VALIDATION")
        print("═" * 60 + "\n")

        from packages.validation import ValidationOrchestrator
        validator = ValidationOrchestrator(
            repo_path=repo_path,
            out_dir=out_dir / "validation",
            strategy="binary",
        )
        validated = validator.run(all_findings)
    else:
        validated = []

    # ══════════════════════════════════════════════════════════════════
    # FINAL REPORT
    # ══════════════════════════════════════════════════════════════════
    duration = time.time() - start_time

    report = {
        "tool": "raptor",
        "mode": "binary",
        "target": target_name,
        "duration_seconds": duration,
        "total_findings": len(validated),
        "exploitable": sum(1 for f in validated if f.get("is_exploitable")),
        "results": validated,
    }

    report_file = out_dir / "merged_report.json"
    save_json(report_file, report)

    print("\n" + "=" * 60)
    print("🎉 ANALYSIS COMPLETE")
    print("=" * 60)
    print(f"  Total findings: {len(validated)}")
    print(f"  Exploitable: {sum(1 for f in validated if f.get('is_exploitable'))}")
    print(f"  Crashes found: {len(fuzz_findings)}")
    print(f"  Duration: {duration:.1f}s")
    print(f"  Report: {report_file}")
    print("=" * 60 + "\n")

    return 0


def _fuzz_from_source(repo_path: Path, out_dir: Path, args) -> list:
    """Compile, instrument, and fuzz from source."""
    # Reuse the existing instrumentation pipeline
    from raptor_fuzzing import _instrument_from_source, _detect_input_mode

    binary_path, corpus_dir, dict_path = _instrument_from_source(
        repo_path, out_dir / "fuzz", args
    )
    if not binary_path:
        logger.error("Instrumentation failed — skipping fuzzing")
        return []

    # Auto-detect input mode
    input_mode = _detect_input_mode(binary_path)

    # Run fuzzing
    from packages.fuzzing import AFLRunner
    try:
        runner = AFLRunner(
            binary_path=binary_path,
            corpus_dir=corpus_dir,
            output_dir=out_dir / "fuzz" / "afl_output",
            dict_path=dict_path,
            input_mode=input_mode,
        )
        num_crashes, crashes_dir = runner.run_fuzzing(
            duration=args.duration,
            max_crashes=10,
        )

        if num_crashes > 0:
            return _analyse_crashes(crashes_dir, binary_path, out_dir)
    except Exception as exc:
        logger.error("Fuzzing failed: %s", exc)

    return []


def _fuzz_binary(binary_path: Path, out_dir: Path, args) -> list:
    """Fuzz a pre-compiled binary."""
    from raptor_fuzzing import _detect_input_mode
    from packages.fuzzing import AFLRunner

    input_mode = _detect_input_mode(binary_path)

    # Ensure executable
    import os, stat
    if not os.access(binary_path, os.X_OK):
        binary_path.chmod(binary_path.stat().st_mode | stat.S_IEXEC)

    try:
        runner = AFLRunner(
            binary_path=binary_path,
            output_dir=out_dir / "fuzz" / "afl_output",
            input_mode=input_mode,
        )
        num_crashes, crashes_dir = runner.run_fuzzing(
            duration=args.duration,
            max_crashes=10,
        )

        if num_crashes > 0:
            return _analyse_crashes(crashes_dir, binary_path, out_dir)
    except Exception as exc:
        logger.error("Fuzzing failed: %s", exc)

    return []


def _analyse_crashes(crashes_dir: Path, binary_path: Path, out_dir: Path) -> list:
    """
    Analyse crashes with gdb (backtrace + registers), rr (reverse execution
    if available), and valgrind (memory check).

    rr is Mozilla's record-and-replay debugger — it lets you rewind execution
    from the crash point. Extremely useful for understanding how a bug was
    triggered. Install: apt install rr  (requires Linux, x86/x86_64)
    """
    findings = []
    if not crashes_dir.exists():
        return findings

    crash_files = sorted(crashes_dir.glob("id:*"))[:10]  # Cap at 10
    gdb_bin = shutil.which("gdb")
    rr_bin = shutil.which("rr")
    valgrind_bin = shutil.which("valgrind")

    # Crash analysis output dir (for rr recordings, valgrind logs, etc.)
    crash_analysis_dir = out_dir / "crash_analysis"
    crash_analysis_dir.mkdir(parents=True, exist_ok=True)

    for idx, crash_file in enumerate(crash_files):
        finding = {
            "rule_id": f"crash-{crash_file.name[:20]}",
            "file_path": str(crash_file),
            "start_line": 0,
            "end_line": 0,
            "message": f"AFL++ crash: {crash_file.name}",
            "tool": "afl++",
            "severity": "high",
            "vuln_type": "crash",
            "cwe_id": "",
            "is_exploitable": False,
            "sources": ["afl++"],
        }

        # ── GDB analysis: backtrace, registers, signal info ──────────
        if gdb_bin:
            try:
                gdb_cmd = [
                    gdb_bin, "-batch",
                    "-ex", "run",
                    "-ex", "bt full",
                    "-ex", "info registers",
                    "-ex", "x/10i $pc",  # disassembly at crash point
                    "-ex", "quit",
                    "--args", str(binary_path),
                ]
                with open(crash_file, "rb") as cf:
                    result = subprocess.run(
                        gdb_cmd, stdin=cf,
                        capture_output=True, text=True, timeout=30,
                    )
                gdb_output = result.stdout or ""
                finding["reasoning"] = gdb_output[-2000:] if gdb_output else ""

                # Detect exploitability indicators
                if "SIGSEGV" in gdb_output or "SIGABRT" in gdb_output:
                    finding["is_exploitable"] = True
                    finding["severity"] = "critical"
                if "stack smashing" in gdb_output.lower():
                    finding["vuln_type"] = "stack_buffer_overflow"
                    finding["cwe_id"] = "CWE-121"
                elif "heap" in gdb_output.lower() and "corrupt" in gdb_output.lower():
                    finding["vuln_type"] = "heap_corruption"
                    finding["cwe_id"] = "CWE-122"
                elif "free()" in gdb_output or "double free" in gdb_output.lower():
                    finding["vuln_type"] = "double_free"
                    finding["cwe_id"] = "CWE-415"
                elif "SIGSEGV" in gdb_output:
                    finding["vuln_type"] = "null_pointer_deref_or_oob"
                    finding["cwe_id"] = "CWE-476"

            except Exception as exc:
                logger.debug("GDB analysis failed: %s", exc)

        # ── rr: record-and-replay for reverse execution analysis ─────
        # rr records the exact execution leading to the crash, then we can
        # rewind to find where the bad data originated. Extremely useful for
        # UAF, double-free, and complex memory corruption bugs.
        if rr_bin:
            try:
                rr_trace_dir = crash_analysis_dir / f"rr_trace_{idx}"
                # Record the crash
                record_cmd = [rr_bin, "record", "-o", str(rr_trace_dir), str(binary_path)]
                with open(crash_file, "rb") as cf:
                    record_result = subprocess.run(
                        record_cmd, stdin=cf,
                        capture_output=True, text=True, timeout=60,
                    )

                if rr_trace_dir.exists():
                    # Replay with backtrace at crash + rewind to find root cause
                    replay_cmd = [
                        rr_bin, "replay", "-o",
                        "-ex=continue",        # run to crash
                        "-ex=bt",              # backtrace at crash
                        "-ex=info registers",  # registers at crash
                        "-ex=reverse-continue",# rewind to last breakpoint/signal
                        "-ex=bt",              # backtrace at earlier point
                        "-ex=quit",
                        str(rr_trace_dir),
                    ]
                    replay_result = subprocess.run(
                        replay_cmd, capture_output=True, text=True, timeout=60,
                    )
                    rr_output = (replay_result.stdout or "") + "\n" + (replay_result.stderr or "")

                    if rr_output.strip():
                        # Append rr findings to the reasoning
                        rr_summary = rr_output[-2000:]
                        existing = finding.get("reasoning", "")
                        finding["reasoning"] = (
                            f"{existing}\n\n── rr reverse execution ──\n{rr_summary}"
                            if existing else
                            f"── rr reverse execution ──\n{rr_summary}"
                        )
                        # Save full trace to disk for later manual inspection
                        (crash_analysis_dir / f"rr_analysis_{idx}.txt").write_text(
                            rr_output, encoding="utf-8"
                        )
                        finding["rr_trace_path"] = str(rr_trace_dir)
                        logger.info("rr analysis recorded for %s", crash_file.name)

            except Exception as exc:
                logger.debug("rr analysis failed: %s", exc)

        # ── Valgrind analysis: memory errors, leaks ─────────────────
        if valgrind_bin:
            try:
                val_cmd = [
                    valgrind_bin,
                    "--tool=memcheck",
                    "--leak-check=full",
                    "--show-leak-kinds=all",
                    "--track-origins=yes",  # track where uninitialised values came from
                    "--error-exitcode=99",
                    str(binary_path),
                ]
                with open(crash_file, "rb") as cf:
                    result = subprocess.run(
                        val_cmd, stdin=cf,
                        capture_output=True, text=True, timeout=60,
                    )
                val_output = result.stderr or ""
                finding["dataflow_summary"] = val_output[-2000:] if val_output else ""

                # Enrich vuln_type based on valgrind output
                if "Invalid read" in val_output:
                    finding["vuln_type"] = finding.get("vuln_type") or "out_of_bounds_read"
                    finding["cwe_id"] = finding.get("cwe_id") or "CWE-125"
                elif "Invalid write" in val_output:
                    finding["vuln_type"] = finding.get("vuln_type") or "out_of_bounds_write"
                    finding["cwe_id"] = finding.get("cwe_id") or "CWE-787"
                elif "Use of uninitialised" in val_output:
                    finding["vuln_type"] = finding.get("vuln_type") or "uninitialized_use"
                    finding["cwe_id"] = finding.get("cwe_id") or "CWE-457"

                # Save full valgrind log
                (crash_analysis_dir / f"valgrind_{idx}.log").write_text(
                    val_output, encoding="utf-8"
                )

            except Exception as exc:
                logger.debug("Valgrind analysis failed: %s", exc)

        findings.append(finding)

    return findings


def _analyse_binary(binary_path: Path, out_dir: Path) -> list:
    """Reverse-engineer a binary using gdb to find functions and potential issues."""
    findings = []
    gdb_bin = shutil.which("gdb")
    if not gdb_bin:
        logger.warning("gdb not found — skipping binary analysis")
        return findings

    try:
        # List functions
        result = subprocess.run(
            [gdb_bin, "-batch", "-ex", "info functions", "-ex", "quit", str(binary_path)],
            capture_output=True, text=True, timeout=30,
        )

        # Look for dangerous function calls
        dangerous = ["strcpy", "strcat", "sprintf", "gets", "scanf",
                      "vsprintf", "sscanf", "system", "popen", "execve"]
        for func in dangerous:
            if func in result.stdout:
                findings.append({
                    "rule_id": f"dangerous-function-{func}",
                    "file_path": str(binary_path),
                    "start_line": 0,
                    "end_line": 0,
                    "message": f"Binary uses dangerous function: {func}()",
                    "tool": "gdb-analysis",
                    "severity": "high",
                    "vuln_type": "dangerous_function",
                    "cwe_id": "CWE-120" if func in ("strcpy", "strcat", "sprintf", "gets") else "CWE-78",
                    "is_exploitable": True,
                    "sources": ["gdb-analysis"],
                    "reasoning": f"Function {func}() is known to be unsafe and can lead to "
                                 f"buffer overflows or command injection.",
                })

    except Exception as exc:
        logger.warning("Binary analysis failed: %s", exc)

    return findings


# ═══════════════════════════════════════════════════════════════════
# QEMU FIRMWARE EMULATION
# ═══════════════════════════════════════════════════════════════════

def _emulate_with_qemu(binary_path: Path, out_dir: Path) -> list:
    """
    Attempt to run a binary under QEMU user-mode emulation.

    Automatically detects the binary's architecture and picks the right
    qemu-<arch> user-mode emulator. Useful for firmware binaries compiled
    for ARM, MIPS, PPC, etc. that can't run natively on the scanning host.

    Returns findings for any emulation-detected issues (crashes, illegal
    instructions, unmapped syscalls).
    """
    findings = []

    # ── Detect binary architecture ──────────────────────────────────
    arch = _detect_binary_arch(binary_path)
    if not arch:
        logger.warning("Could not detect binary architecture — skipping QEMU emulation")
        print("  ⚠ Could not detect binary architecture")
        return findings

    logger.info("Detected architecture: %s", arch)
    print(f"  Architecture: {arch}")

    # ── Map arch to qemu-<arch> binary ──────────────────────────────
    # Native arch: don't need QEMU (but still do a quick smoke test)
    import platform
    host_arch = platform.machine()
    _ARCH_TO_QEMU = {
        "arm": "qemu-arm",
        "aarch64": "qemu-aarch64",
        "mips": "qemu-mips",
        "mipsel": "qemu-mipsel",
        "mips64": "qemu-mips64",
        "ppc": "qemu-ppc",
        "ppc64": "qemu-ppc64",
        "i386": "qemu-i386",
        "x86_64": "qemu-x86_64",
        "riscv64": "qemu-riscv64",
        "sparc": "qemu-sparc",
    }
    qemu_binary_name = _ARCH_TO_QEMU.get(arch.lower())
    if not qemu_binary_name:
        logger.warning("No QEMU binary mapping for architecture: %s", arch)
        print(f"  ⚠ Unsupported architecture for QEMU: {arch}")
        return findings

    # Try in order: qemu-<arch>, qemu-<arch>-static, qemu-amd64-static (alias for x86_64)
    candidates = [qemu_binary_name, f"{qemu_binary_name}-static"]
    if arch.lower() == "x86_64":
        candidates.extend(["qemu-amd64", "qemu-amd64-static"])

    qemu_bin = None
    for name in candidates:
        found = shutil.which(name)
        if found:
            qemu_bin = found
            break

    if not qemu_bin:
        install_hint = f"sudo apt install qemu-user-static"
        logger.warning("QEMU binary not found: tried %s (install: %s)",
                       ", ".join(candidates), install_hint)
        print(f"  ⚠ QEMU not found (tried: {', '.join(candidates)})")
        print(f"    Install with: {install_hint}")
        return findings

    logger.info("Using QEMU emulator: %s", qemu_bin)
    print(f"  Emulator: {qemu_bin}")

    # ── Run the binary under QEMU with various probes ───────────────
    qemu_log_dir = out_dir / "qemu"
    qemu_log_dir.mkdir(parents=True, exist_ok=True)

    # Probe 1: Run with --help (safe, shouldn't crash)
    probes = [
        (["--help"], "help"),
        (["-h"], "short-help"),
        ([], "no-args"),
    ]

    for probe_args, probe_name in probes:
        try:
            cmd = [qemu_bin, "-strace", str(binary_path)] + probe_args
            env = {"QEMU_STRACE": "1", "PATH": "/usr/bin:/bin"}

            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=15,
                env=env,
            )

            # Save trace output for later inspection
            trace_file = qemu_log_dir / f"qemu_trace_{probe_name}.log"
            combined_output = f"=== STDOUT ===\n{result.stdout}\n\n=== STDERR ===\n{result.stderr}"
            trace_file.write_text(combined_output, encoding="utf-8")

            # Look for issues in the trace
            issues = _parse_qemu_output(result.stdout, result.stderr, result.returncode)
            for issue in issues:
                findings.append({
                    "rule_id": f"qemu-{issue['type']}-{probe_name}",
                    "file_path": str(binary_path),
                    "start_line": 0,
                    "end_line": 0,
                    "message": f"QEMU emulation ({probe_name}): {issue['description']}",
                    "tool": "qemu",
                    "severity": issue["severity"],
                    "level": issue["severity"],
                    "vuln_type": issue["type"],
                    "cwe_id": issue.get("cwe", ""),
                    "is_exploitable": issue.get("exploitable", False),
                    "confidence": "medium",
                    "sources": ["qemu"],
                    "reasoning": issue["detail"][:1500],
                })

            logger.info("QEMU probe '%s': %d issue(s)", probe_name, len(issues))

        except subprocess.TimeoutExpired:
            findings.append({
                "rule_id": f"qemu-hang-{probe_name}",
                "file_path": str(binary_path),
                "start_line": 0, "end_line": 0,
                "message": f"Binary hangs in QEMU with args: {probe_args}",
                "tool": "qemu",
                "severity": "medium",
                "vuln_type": "infinite_loop_or_hang",
                "sources": ["qemu"],
                "reasoning": f"Binary did not terminate within 15s under QEMU emulation.",
                "is_exploitable": False,
                "confidence": "medium",
            })
        except Exception as exc:
            logger.debug("QEMU probe '%s' failed: %s", probe_name, exc)

    return findings


def _detect_binary_arch(binary_path: Path) -> str:
    """
    Detect the architecture of an ELF binary by reading its header.
    Returns a short arch name like "arm", "aarch64", "mips", "x86_64", or "" if unknown.
    """
    try:
        with open(binary_path, "rb") as f:
            magic = f.read(4)
            if magic != b"\x7fELF":
                return ""
            # ELF class (1=32-bit, 2=64-bit) + endianness (1=little, 2=big)
            elf_class = f.read(1)
            elf_endian = f.read(1)
            # Skip to e_machine field (offset 0x12)
            f.seek(0x12)
            # 2 bytes, endian-dependent
            e_machine_bytes = f.read(2)
            if elf_endian == b"\x01":  # little-endian
                e_machine = int.from_bytes(e_machine_bytes, "little")
            else:
                e_machine = int.from_bytes(e_machine_bytes, "big")

        # Reference: https://refspecs.linuxfoundation.org/elf/gabi4+/ch4.eheader.html
        _EM_MAP = {
            0x03: "i386",
            0x3E: "x86_64",
            0x28: "arm",
            0xB7: "aarch64",
            0x08: "mips" if elf_endian == b"\x02" else "mipsel",
            0x14: "ppc",
            0x15: "ppc64",
            0xF3: "riscv64",
            0x02: "sparc",
        }
        return _EM_MAP.get(e_machine, "")
    except (OSError, IOError):
        return ""


def _parse_qemu_output(stdout: str, stderr: str, returncode: int) -> list:
    """
    Parse QEMU -strace output and return detected issues.
    """
    issues = []
    combined = stdout + "\n" + stderr

    # Signal indicators
    if "Segmentation fault" in combined or "SIGSEGV" in combined:
        issues.append({
            "type": "segfault",
            "severity": "critical",
            "description": "Binary segfaulted during emulation",
            "detail": combined[-1500:],
            "cwe": "CWE-476",
            "exploitable": True,
        })
    elif "Illegal instruction" in combined or "SIGILL" in combined:
        issues.append({
            "type": "illegal_instruction",
            "severity": "high",
            "description": "Illegal CPU instruction encountered",
            "detail": combined[-1500:],
            "cwe": "CWE-1023",
            "exploitable": False,
        })
    elif "Bus error" in combined or "SIGBUS" in combined:
        issues.append({
            "type": "bus_error",
            "severity": "high",
            "description": "Bus error (misaligned access)",
            "detail": combined[-1500:],
            "cwe": "CWE-1241",
        })
    elif "SIGABRT" in combined or "abort" in combined.lower():
        issues.append({
            "type": "abort",
            "severity": "medium",
            "description": "Binary aborted via SIGABRT",
            "detail": combined[-1500:],
        })

    # Unmapped syscalls (firmware-specific indicator)
    if "Unhandled syscall" in combined or "qemu: Unsupported syscall" in combined:
        import re as _re
        syscalls = _re.findall(r"(?:[Uu]nhandled|[Uu]nsupported)\s+syscall:?\s*(\d+)", combined)
        if not syscalls:
            syscalls = ["unknown"]
        for sc in list(set(syscalls))[:5]:  # dedupe, limit
            issues.append({
                "type": "unmapped_syscall",
                "severity": "low",
                "description": f"QEMU doesn't support syscall {sc} — binary may be relying on platform-specific features",
                "detail": combined[-1500:],
            })

    return issues


# ═══════════════════════════════════════════════════════════════════
# BUG TRACK URL — fetch & analyse external crash reports
# ═══════════════════════════════════════════════════════════════════

def _fetch_and_analyse_bug_url(bug_url: str, binary_path, out_dir: Path) -> list:
    """
    Fetch crash data or PoC from a URL and analyse it with gdb/rr.

    Supports:
    - Plain text URLs (copied crash dumps, stack traces)
    - Binary crash input files (will be fed to gdb if binary provided)
    - GitHub/GitLab issue pages (extract code blocks and attachments)

    Returns findings enriched with any analysis performed.
    """
    import urllib.request
    import urllib.parse
    import ssl
    import re as _re

    findings = []

    logger.info("Fetching bug track URL: %s", bug_url)
    print(f"  Fetching: {bug_url}")

    bug_dir = out_dir / "bug_track"
    bug_dir.mkdir(parents=True, exist_ok=True)

    # ── Download the content ────────────────────────────────────────
    try:
        req = urllib.request.Request(
            bug_url,
            headers={"User-Agent": "RAPTOR/2.0 Security Scanner"},
        )
        # Allow self-signed certs (common for internal bug trackers)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with urllib.request.urlopen(req, timeout=30, context=ctx) as resp:
            content = resp.read()
            content_type = resp.headers.get("Content-Type", "").lower()
    except Exception as exc:
        logger.error("Failed to fetch bug URL: %s", exc)
        print(f"  ✗ Fetch failed: {exc}")
        return [{
            "rule_id": "bug-url-fetch-failed",
            "file_path": bug_url,
            "start_line": 0, "end_line": 0,
            "message": f"Could not fetch bug track URL: {exc}",
            "tool": "bug-track-url",
            "severity": "info",
            "sources": ["bug-track-url"],
            "reasoning": str(exc),
            "is_exploitable": False,
        }]

    # ── Save raw content for later inspection ───────────────────────
    raw_file = bug_dir / "bug_raw_content.bin"
    raw_file.write_bytes(content)
    print(f"  Downloaded: {len(content)} bytes ({content_type or 'unknown type'})")

    # ── Decide how to analyse ───────────────────────────────────────
    is_text = (
        content_type.startswith("text/")
        or content_type.startswith("application/json")
        or content_type.startswith("application/xml")
        or not content.startswith(b"\x7fELF")  # not an ELF binary
        and all(b < 0x80 or b in (0x0a, 0x0d, 0x09) for b in content[:200])  # ASCII-ish
    )

    if is_text:
        try:
            text_content = content.decode("utf-8", errors="replace")
        except Exception:
            text_content = content.decode("latin-1", errors="replace")

        # Save as text
        (bug_dir / "bug_content.txt").write_text(text_content, encoding="utf-8")

        # Extract stack traces, register dumps, error messages
        findings.extend(_extract_from_bug_text(text_content, bug_url))

        # Extract attached code blocks (e.g. from GitHub issue pages)
        code_blocks = _re.findall(r"```[\w]*\n(.*?)\n```", text_content, _re.DOTALL)
        if code_blocks:
            print(f"  Found {len(code_blocks)} code block(s) in bug report")
            for i, block in enumerate(code_blocks[:5]):  # cap at 5
                # Save each as potential crash input
                input_file = bug_dir / f"extracted_input_{i}.bin"
                input_file.write_text(block, encoding="utf-8")

                # If we have a binary, try running it with this input
                if binary_path and binary_path.exists():
                    crash_finding = _test_input_on_binary(
                        binary_path, input_file, f"bug-url-block-{i}", bug_dir
                    )
                    if crash_finding:
                        findings.append(crash_finding)

    else:
        # Binary content — treat as a crash input
        print("  Binary content detected — testing against target binary")
        if binary_path and binary_path.exists():
            input_file = bug_dir / "bug_input.bin"
            input_file.write_bytes(content)
            crash_finding = _test_input_on_binary(
                binary_path, input_file, "bug-url-binary", bug_dir
            )
            if crash_finding:
                findings.append(crash_finding)
        else:
            findings.append({
                "rule_id": "bug-url-binary-no-target",
                "file_path": bug_url,
                "start_line": 0, "end_line": 0,
                "message": "Downloaded binary content but no target binary to test against",
                "tool": "bug-track-url",
                "severity": "info",
                "sources": ["bug-track-url"],
                "is_exploitable": False,
            })

    logger.info("Bug track URL analysis: %d finding(s)", len(findings))
    return findings


def _extract_from_bug_text(text: str, source_url: str) -> list:
    """Extract stack traces, register dumps, and error messages from bug report text."""
    import re as _re
    findings = []

    # Detect stack traces (common formats: addr2line, gdb, Python, Java)
    stack_trace_patterns = [
        (r"#\d+\s+0x[0-9a-fA-F]+\s+in\s+\S+", "gdb_backtrace"),
        (r'File\s+"[^"]+",\s+line\s+\d+', "python_traceback"),
        (r"at\s+\S+\.\S+\([^\)]+:\d+\)", "java_stacktrace"),
        (r"^\s*==\d+==\s+\S+", "asan_report"),  # AddressSanitizer
    ]

    for pattern, trace_type in stack_trace_patterns:
        matches = _re.findall(pattern, text, _re.MULTILINE)
        if matches:
            findings.append({
                "rule_id": f"bug-url-{trace_type}",
                "file_path": source_url,
                "start_line": 0, "end_line": 0,
                "message": f"Extracted {trace_type} from bug report ({len(matches)} frames)",
                "tool": "bug-track-url",
                "severity": "high",
                "vuln_type": "reported_crash",
                "is_exploitable": True,
                "confidence": "medium",
                "sources": ["bug-track-url"],
                "reasoning": "\n".join(matches[:20]),  # top 20 frames
                "attack_scenario": f"This crash was reported at: {source_url}",
            })
            break  # one trace pattern match is enough

    # Detect CVE references
    cve_matches = _re.findall(r"CVE-\d{4}-\d{4,7}", text)
    for cve in set(cve_matches):
        findings.append({
            "rule_id": f"bug-url-cve-ref",
            "file_path": source_url,
            "start_line": 0, "end_line": 0,
            "message": f"Bug report references {cve}",
            "tool": "bug-track-url",
            "severity": "high",
            "vuln_type": "known_cve",
            "cwe_id": "",
            "is_exploitable": True,
            "confidence": "high",
            "sources": ["bug-track-url"],
            "reasoning": f"Bug report at {source_url} references known vulnerability {cve}",
        })

    return findings


def _test_input_on_binary(binary_path: Path, input_file: Path, label: str, out_dir: Path) -> dict:
    """Feed an input file to the binary and see if it crashes. Analyse with gdb."""
    gdb_bin = shutil.which("gdb")
    if not gdb_bin:
        return None

    try:
        gdb_cmd = [
            gdb_bin, "-batch",
            "-ex", "run",
            "-ex", "bt full",
            "-ex", "info registers",
            "-ex", "quit",
            "--args", str(binary_path),
        ]
        with open(input_file, "rb") as f:
            result = subprocess.run(
                gdb_cmd, stdin=f,
                capture_output=True, text=True, timeout=30,
            )
        output = result.stdout or ""

        # Save full gdb output
        (out_dir / f"gdb_output_{label}.txt").write_text(output, encoding="utf-8")

        if "SIGSEGV" in output or "SIGABRT" in output or "SIGBUS" in output:
            return {
                "rule_id": f"reproduced-crash-{label}",
                "file_path": str(binary_path),
                "start_line": 0, "end_line": 0,
                "message": f"Reproduced crash from bug track URL input ({label})",
                "tool": "bug-track-url",
                "severity": "critical",
                "vuln_type": "reproduced_crash",
                "is_exploitable": True,
                "confidence": "high",
                "sources": ["bug-track-url", "gdb"],
                "reasoning": output[-2000:],
                "attack_scenario": f"Input file {input_file.name} reproduces the reported crash.",
            }
    except Exception as exc:
        logger.debug("Binary test failed: %s", exc)

    return None


if __name__ == "__main__":
    sys.exit(main())
