#!/usr/bin/env python3
"""
RAPTOR Fuzzing Mode

Binary fuzzing with AFL++ and LLM-powered crash analysis.

Usage:
    python3 raptor_fuzzing.py \\
        --binary /path/to/binary \\
        --duration 3600 \\
        --max-crashes 10

This is very much a work-in-progress!
"""

import argparse
import sys
import time
from pathlib import Path

# Add to path
sys.path.insert(0, str(Path(__file__).parent))

from core.json import save_json

from core.config import RaptorConfig
from core.logging import get_logger
from packages.fuzzing import AFLRunner, CrashCollector, CorpusManager
from packages.binary_analysis import CrashAnalyser
from packages.llm_analysis.crash_agent import CrashAnalysisAgent
from packages.autonomous import (
    FuzzingPlanner, FuzzingState, FuzzingMemory,
    MultiTurnAnalyser, ExploitValidator, GoalPlanner, CorpusGenerator
)

logger = get_logger()


# ---------------------------------------------------------------------------
# Phase 0: AFL++ instrumentation from source
# ---------------------------------------------------------------------------

def _instrument_from_source(
    repo_path: Path, out_dir: Path, args
) -> tuple:
    """
    Detect build system, recompile with AFL++ instrumentation, and find
    the resulting binary.

    Also auto-discovers corpus/ and *.dict files from the repo.

    Args:
        repo_path: Path to the source repository
        out_dir: Output directory for build artifacts
        args: Parsed CLI arguments (for --asan, --target-binary)

    Returns:
        (binary_path, corpus_dir, dict_path) — binary_path is None on failure
    """
    import shutil
    import subprocess as _sp
    import os as _os
    import stat as _stat

    print("\n" + "=" * 70)
    print("PHASE 0: AFL++ INSTRUMENTATION")
    print("=" * 70)

    logger.info("=" * 70)
    logger.info("PHASE 0: AFL++ INSTRUMENTATION FROM SOURCE")
    logger.info("=" * 70)
    logger.info("Repository: %s", repo_path)

    # ── Check AFL++ compiler availability ────────────────────────────────
    afl_cc = shutil.which("afl-clang-fast") or shutil.which("afl-gcc")
    afl_cxx = shutil.which("afl-clang-fast++") or shutil.which("afl-g++")

    if not afl_cc:
        logger.error(
            "AFL++ compiler not found. Install AFL++ and ensure afl-clang-fast "
            "or afl-gcc is on PATH.\n"
            "  Ubuntu/Debian: sudo apt install afl++\n"
            "  macOS: brew install aflplusplus"
        )
        print("✗ AFL++ compiler not found (need afl-clang-fast or afl-gcc)")
        return None, None, None

    logger.info("AFL++ compiler: %s", afl_cc)
    if afl_cxx:
        logger.info("AFL++ C++ compiler: %s", afl_cxx)

    # ── Detect build system ──────────────────────────────────────────────
    build_system, build_cmd, build_dir = _detect_fuzz_build(repo_path)
    if not build_cmd:
        logger.error("Could not detect build system in %s", repo_path)
        print("✗ No supported build system found (need Makefile, CMakeLists.txt, configure, or meson.build)")
        return None, None, None

    logger.info("Build system: %s", build_system)
    logger.info("Build command: %s", build_cmd)

    # ── Build with AFL++ instrumentation ─────────────────────────────────
    env = _os.environ.copy()
    env["CC"] = afl_cc
    if afl_cxx:
        env["CXX"] = afl_cxx

    # Enable ASAN if requested
    if getattr(args, 'asan', False):
        env["AFL_USE_ASAN"] = "1"
        logger.info("AddressSanitizer: ENABLED")
        print("  ASAN: enabled")
    else:
        logger.info("AddressSanitizer: disabled (use --asan to enable)")

    # Suppress AFL++ instrumentation banner noise
    env["AFL_QUIET"] = "1"

    build_out = out_dir / "build_log.txt"
    logger.info("Building with AFL++ instrumentation...")
    print(f"  Compiler: {afl_cc}")
    print(f"  Build system: {build_system}")
    print(f"  Building...")

    try:
        result = _sp.run(
            build_cmd,
            shell=True,
            cwd=str(build_dir),
            env=env,
            capture_output=True,
            text=True,
            timeout=300,  # 5 minute build timeout
        )

        # Save build log
        build_out.write_text(
            f"=== STDOUT ===\n{result.stdout}\n\n=== STDERR ===\n{result.stderr}\n",
            encoding="utf-8",
        )

        if result.returncode != 0:
            logger.error("Build failed (exit %d). See %s", result.returncode, build_out)
            # Show last 20 lines of stderr for quick diagnosis
            stderr_lines = result.stderr.strip().splitlines()
            for line in stderr_lines[-20:]:
                logger.error("  %s", line)
            print(f"✗ Build failed (exit {result.returncode}). Check {build_out}")
            return None, None, None

        logger.info("✓ Build succeeded")
        print("  ✓ Build succeeded")

    except _sp.TimeoutExpired:
        logger.error("Build timed out after 300s")
        print("✗ Build timed out (5 min limit)")
        return None, None, None
    except Exception as exc:
        logger.error("Build error: %s", exc)
        print(f"✗ Build error: {exc}")
        return None, None, None

    # ── Find the instrumented binary ─────────────────────────────────────
    target_name = getattr(args, 'target_binary', None)
    binary_path = _find_instrumented_binary(repo_path, build_dir, target_name)

    if not binary_path:
        logger.error("Could not find instrumented binary after build")
        print("✗ No ELF binary found after build. Use --target-binary <name> to specify.")
        return None, None, None

    # Ensure executable
    binary_path.chmod(binary_path.stat().st_mode | 0o111)
    logger.info("✓ Instrumented binary: %s", binary_path)
    print(f"  ✓ Binary: {binary_path.relative_to(repo_path) if binary_path.is_relative_to(repo_path) else binary_path}")

    # ── Auto-discover corpus ─────────────────────────────────────────────
    corpus_dir = None
    for candidate in ("corpus", "seeds", "testcases", "inputs", "in"):
        corpus_candidate = repo_path / candidate
        if corpus_candidate.is_dir() and any(corpus_candidate.iterdir()):
            corpus_dir = corpus_candidate
            logger.info("✓ Found corpus: %s/ (%d files)",
                        candidate, sum(1 for _ in corpus_candidate.iterdir()))
            print(f"  ✓ Corpus: {candidate}/ ({sum(1 for _ in corpus_candidate.iterdir())} seed files)")
            break

    if not corpus_dir:
        logger.info("No corpus directory found — AFL++ will use a default seed")
        print("  ℹ No corpus/ directory — will use default seeds")

    # ── Auto-discover dictionary ─────────────────────────────────────────
    dict_path = None
    for df in sorted(repo_path.glob("*.dict")):
        dict_path = df
        logger.info("✓ Found dictionary: %s", df.name)
        print(f"  ✓ Dictionary: {df.name}")
        break
    # Also check common locations
    if not dict_path:
        for candidate in ("dictionary.dict", "dict/fuzzing.dict", "fuzz.dict"):
            df = repo_path / candidate
            if df.exists():
                dict_path = df
                logger.info("✓ Found dictionary: %s", candidate)
                print(f"  ✓ Dictionary: {candidate}")
                break

    print()
    return binary_path, corpus_dir, dict_path


def _detect_fuzz_build(repo_path: Path) -> tuple:
    """
    Detect build system and return (system_name, build_command, build_dir).
    Returns (None, None, None) if no supported build system found.
    """
    # Priority order: Makefile > CMake > autotools > meson > bare gcc
    if (repo_path / "Makefile").exists() or (repo_path / "makefile").exists():
        return "make", "make clean 2>/dev/null; make", repo_path

    if (repo_path / "CMakeLists.txt").exists():
        build_dir = repo_path / "build"
        build_dir.mkdir(exist_ok=True)
        return "cmake", f"cmake -S {repo_path} -B {build_dir} && cmake --build {build_dir}", build_dir

    if (repo_path / "configure").exists():
        return "autotools", "./configure && make", repo_path

    if (repo_path / "configure.ac").exists() or (repo_path / "configure.in").exists():
        return "autotools", "autoreconf -i && ./configure && make", repo_path

    if (repo_path / "meson.build").exists():
        build_dir = repo_path / "builddir"
        return "meson", f"meson setup {build_dir} && meson compile -C {build_dir}", repo_path

    # Fallback: look for a single .c file and compile it directly
    c_files = list(repo_path.glob("*.c"))
    if len(c_files) == 1:
        stem = c_files[0].stem
        return "gcc", f"$CC -o {stem} {c_files[0].name}", repo_path
    elif c_files:
        # Multiple .c files — try compiling all into one binary
        names = " ".join(f.name for f in c_files)
        return "gcc", f"$CC -o fuzz_target {names}", repo_path

    return None, None, None


def _find_instrumented_binary(
    repo_path: Path, build_dir: Path, target_name: str = None,
) -> Path:
    """
    Find the ELF binary produced by the build.

    If target_name is specified, look for that name.
    Otherwise, find all ELF binaries created/modified during the build
    and pick the most likely fuzz target.
    """
    import os as _os

    # If user specified a target name, look for it
    if target_name:
        for search_dir in (build_dir, repo_path):
            for candidate in search_dir.rglob(target_name):
                if candidate.is_file() and _is_elf(candidate):
                    return candidate
        # Also check without path
        candidate = build_dir / target_name
        if candidate.exists() and _is_elf(candidate):
            return candidate
        candidate = repo_path / target_name
        if candidate.exists() and _is_elf(candidate):
            return candidate
        return None

    # Auto-discover: find all ELF executables in repo and build dirs
    candidates = []
    search_dirs = {repo_path}
    if build_dir != repo_path:
        search_dirs.add(build_dir)

    for search_dir in search_dirs:
        for f in search_dir.rglob("*"):
            if not f.is_file():
                continue
            # Skip common non-targets
            if f.suffix in (".o", ".a", ".so", ".dylib", ".py", ".sh", ".txt", ".md", ".h", ".c", ".cpp"):
                continue
            if any(skip in f.parts for skip in ("__pycache__", ".git", "node_modules", "corpus", "seeds")):
                continue
            if _is_elf(f):
                candidates.append(f)

    if not candidates:
        return None

    if len(candidates) == 1:
        return candidates[0]

    # Multiple binaries — prefer ones with "fuzz" in the name, then largest
    for c in candidates:
        if "fuzz" in c.name.lower():
            return c

    # Return the largest binary (most likely the main target)
    return max(candidates, key=lambda c: c.stat().st_size)


def _is_elf(path: Path) -> bool:
    """Check if a file is an ELF binary."""
    try:
        with open(path, "rb") as f:
            return f.read(4) == b"\x7fELF"
    except (OSError, IOError):
        return False


def _detect_input_mode(binary_path: Path) -> str:
    """
    Probe whether a binary reads from stdin or expects file arguments.

    Strategy:
    1. Check --help / usage output for file argument patterns
    2. Run the binary with stdin closed — if it prints a usage message
       mentioning filenames, it expects file args, not stdin
    3. Check common tool names known to use file args

    Returns "stdin" or "file".
    """
    import subprocess as _sp

    binary_name = binary_path.name.lower()

    # ── Known file-argument tools (fast path) ────────────────────────────
    _FILE_ARG_BINARIES = {
        "lame", "ffmpeg", "ffprobe", "objdump", "readelf", "nm",
        "convert", "identify", "tiff2pdf", "tiffcp",
        "exiv2", "djpeg", "cjpeg", "pngfix", "optipng",
        "xmllint", "xsltproc", "jq",
        "file", "strings", "strip", "objcopy",
        "nasm", "yasm", "as",
        "bison", "flex", "yacc",
        "unzip", "gzip", "bzip2", "xz", "zstd",
        "tar", "cpio", "ar",
        "pdf2txt", "pdftotext", "mutool",
    }
    if binary_name in _FILE_ARG_BINARIES:
        logger.info("Known file-argument binary: %s → using file input mode", binary_name)
        return "file"

    # ── Probe --help output for file argument patterns ───────────────────
    for help_flag in ("--help", "-h", "-help"):
        try:
            result = _sp.run(
                [str(binary_path), help_flag],
                capture_output=True,
                text=True,
                timeout=5,
                stdin=_sp.DEVNULL,
            )
            output = (result.stdout + result.stderr).lower()

            # Look for patterns indicating file arguments
            _FILE_PATTERNS = [
                "input file", "input_file", "infile",
                "output file", "output_file", "outfile",
                "<filename", "<file>", "<input>",
                "[file]", "[input]", "[filename]",
                "usage:", "synopsis:",
            ]
            file_hints = sum(1 for p in _FILE_PATTERNS if p in output)

            # Look for patterns indicating stdin
            _STDIN_PATTERNS = [
                "reads from stdin", "standard input", "read from stdin",
                "reads stdin", "pipe", "< input",
            ]
            stdin_hints = sum(1 for p in _STDIN_PATTERNS if p in output)

            if file_hints > stdin_hints and file_hints >= 2:
                logger.info("Help output suggests file-argument mode (%d file hints vs %d stdin hints)",
                            file_hints, stdin_hints)
                return "file"
            if stdin_hints > file_hints:
                logger.info("Help output suggests stdin mode (%d stdin hints vs %d file hints)",
                            stdin_hints, file_hints)
                return "stdin"

        except (_sp.TimeoutExpired, OSError):
            continue

    # ── Probe: run with empty stdin, check if it errors about missing file ─
    try:
        result = _sp.run(
            [str(binary_path)],
            capture_output=True,
            text=True,
            timeout=3,
            stdin=_sp.DEVNULL,
        )
        output = (result.stdout + result.stderr).lower()
        # If the binary complained about missing input file, it wants file args
        if any(phrase in output for phrase in (
            "no input file", "missing input", "no file", "nothing to do",
            "usage:", "no input", "specify input", "expected file",
            "requires an argument", "no arguments",
        )):
            logger.info("Binary complained about missing file argument → file mode")
            return "file"
    except (_sp.TimeoutExpired, OSError):
        pass

    # Default to stdin
    return "stdin"


def main() -> None:
    ap = argparse.ArgumentParser(
        description="RAPTOR Fuzzing Mode - Binary fuzzing with LLM analysis",
        epilog="""
Two modes of operation:

  Source mode (--repo):
    Upload a C/C++ source repository. RAPTOR will automatically:
    - Detect the build system (Makefile, CMake, autotools, meson)
    - Recompile with AFL++ instrumentation (afl-clang-fast)
    - Optionally enable AddressSanitizer (ASAN)
    - Find the resulting binary
    - Use corpus/ directory and *.dict files if present in the repo

  Binary mode (--binary):
    Provide a pre-compiled binary (must be instrumented with AFL++).

  Repo structure for source mode:
    project/
    ├── src/            # or Makefile, CMakeLists.txt, etc.
    ├── corpus/         # (optional) seed inputs for AFL++
    ├── dictionary.dict # (optional) AFL++ dictionary
    └── Makefile        # build system
""",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Input: either --repo (source) or --binary (pre-compiled)
    input_group = ap.add_mutually_exclusive_group(required=True)
    input_group.add_argument("--repo", help="Path to C/C++ source repository (will be instrumented with AFL++)")
    input_group.add_argument("--binary", help="Path to pre-instrumented binary to fuzz")

    ap.add_argument("--corpus", help="Path to seed corpus directory (auto-detected from repo/corpus/ if not set)")
    ap.add_argument("--duration", type=int, default=3600, help="Fuzzing duration in seconds (default: 3600)")
    ap.add_argument("--parallel", type=int, default=1, help="Number of parallel AFL instances (default: 1)")
    ap.add_argument("--max-crashes", type=int, default=10, help="Maximum crashes to analyse (default: 10)")
    ap.add_argument("--timeout", type=int, default=1000, help="Timeout per execution in ms (default: 1000)")
    ap.add_argument("--out", help="Output directory (default: out/fuzz_<binary_name>)")
    ap.add_argument("--dict", help="Path to AFL dictionary file for structured input fuzzing")
    ap.add_argument("--input-mode", choices=["stdin", "file"], default="stdin", help="Input mode: stdin (default) or file (uses @@)")
    ap.add_argument("--check-sanitizers", action="store_true", help="Check if binary is compiled with sanitizers (ASAN, etc.)")
    ap.add_argument("--recompile-guide", action="store_true", help="Show guide for recompiling binary with AFL instrumentation and sanitizers")
    ap.add_argument("--use-showmap", action="store_true", help="Run afl-showmap after fuzzing for coverage analysis")
    ap.add_argument("--autonomous", action="store_true", help="Enable autonomous mode with intelligent decision-making and learning")
    ap.add_argument("--memory-file", help="Path to memory file for learning persistence (default: ~/.raptor/fuzzing_memory.json)")
    ap.add_argument("--goal", help="High-level goal to achieve (e.g., 'find heap overflow', 'target parser code')")
    ap.add_argument("--asan", action="store_true", help="Enable AddressSanitizer when instrumenting from source (--repo mode)")
    ap.add_argument("--target-binary", help="Name of the binary to fuzz after building (if repo produces multiple binaries)")

    args = ap.parse_args()

    # ========================================================================
    # PHASE 0: SOURCE INSTRUMENTATION (--repo mode only)
    # ========================================================================
    if args.repo:
        repo_path = Path(args.repo).resolve()
        if not repo_path.exists():
            logger.error("Repository not found: %s", repo_path)
            sys.exit(1)

        out_dir = Path(args.out) if args.out else Path(f"out/fuzz_{repo_path.name}_{int(time.time())}")
        out_dir.mkdir(parents=True, exist_ok=True)

        binary_path, corpus_dir, dict_path = _instrument_from_source(
            repo_path, out_dir, args
        )

        if binary_path is None:
            logger.error("Instrumentation failed — cannot proceed to fuzzing")
            sys.exit(1)

        # Use auto-detected corpus/dict unless user overrode them
        if args.corpus:
            corpus_dir = Path(args.corpus)
        if args.dict:
            dict_path = Path(args.dict)

    else:
        binary_path = Path(args.binary).resolve()
        if not binary_path.exists():
            logger.error("Binary not found: %s", binary_path)
            sys.exit(1)

        corpus_dir = Path(args.corpus) if args.corpus else None
        dict_path = Path(args.dict) if args.dict else None
        out_dir = Path(args.out) if args.out else Path(f"out/fuzz_{binary_path.stem}_{int(time.time())}")
        out_dir.mkdir(parents=True, exist_ok=True)

    logger.info("=" * 70)
    logger.info("RAPTOR FUZZING WORKFLOW STARTED")
    logger.info("=" * 70)
    logger.info(f"Binary: {binary_path.name}")
    logger.info(f"Full path: {binary_path}")
    logger.info(f"Output: {out_dir}")
    logger.info(f"Duration: {args.duration}s ({args.duration/60:.1f} minutes)")
    logger.info(f"Max crashes to analyse: {args.max_crashes}")
    logger.info(f"Input mode: {args.input_mode}")
    if args.dict:
        logger.info(f"Dictionary: {args.dict}")
    logger.info(f"Sanitizer check: {'enabled' if args.check_sanitizers else 'disabled'}")
    logger.info(f"Recompile guide: {'will be shown' if args.recompile_guide else 'disabled'}")
    logger.info(f"Coverage analysis: {'enabled' if args.use_showmap else 'disabled'}")

    # ── Auto-detect input mode if user didn't explicitly set it ──────────
    # Many binaries (lame, ffmpeg, objdump, etc.) read from file arguments,
    # not stdin. If the user left input-mode at the default ("stdin"), probe
    # the binary to see if it actually reads from stdin. If not, switch to
    # file mode so AFL uses @@ substitution.
    if args.input_mode == "stdin":
        detected_mode = _detect_input_mode(binary_path)
        if detected_mode == "file":
            args.input_mode = "file"
            logger.info("Auto-detected input mode: file (binary doesn't read stdin)")
            print(f"  ℹ Auto-detected input mode: file (using @@ substitution)")

    # ========================================================================
    # AUTONOMOUS SYSTEM INITIALIZATION
    # ========================================================================
    memory = None
    planner = None
    multi_turn = None
    exploit_validator = None
    goal_planner = None

    if args.autonomous:
        logger.info("=" * 70)
        logger.info("AUTONOMOUS MODE ENABLED")
        logger.info("=" * 70)

        # Initialize fuzzing memory for learning
        memory_file = Path(args.memory_file) if args.memory_file else None
        memory = FuzzingMemory(memory_file)

        # Initialize autonomous planner
        planner = FuzzingPlanner(memory=memory)

        # Initialize exploit validator
        exploit_validator = ExploitValidator(work_dir=out_dir / "validation")

        # Initialize goal-directed planner if goal specified
        if args.goal:
            goal_planner = GoalPlanner()
            goal = goal_planner.create_goal_from_user_input(args.goal)
            goal_planner.set_goal(goal)
            logger.info(f"Goal-directed fuzzing enabled: {goal.description}")

        # Log memory statistics
        stats = memory.get_statistics()
        logger.info(f"Loaded fuzzing memory: {stats['total_knowledge']} knowledge entries")
        logger.info(f"Past campaigns: {stats['total_campaigns']}")
        if stats['total_knowledge'] > 0:
            logger.info(f"Average confidence: {stats['average_confidence']:.2f}")

        # Check for past strategies for this binary
        import hashlib
        binary_hash = hashlib.sha256(binary_path.read_bytes()).hexdigest()[:16]
        best_strategy = memory.get_best_strategy(binary_hash)
        if best_strategy:
            logger.info(f"✨ Found best strategy from memory: {best_strategy}")

        # Generate autonomous corpus if no corpus provided
        if not corpus_dir:
            logger.info("No corpus provided - using autonomous corpus generation")
            corpus_generator = CorpusGenerator(
                binary_path=binary_path,
                memory=memory,
                goal=goal_planner.current_goal if goal_planner else None
            )

            # Generate corpus in output directory
            autonomous_corpus_dir = out_dir / "autonomous_corpus"
            num_seeds = corpus_generator.generate_autonomous_corpus(
                corpus_dir=autonomous_corpus_dir,
                max_seeds=30
            )

            corpus_dir = autonomous_corpus_dir
            logger.info(f"✨ Autonomous corpus generated: {num_seeds} intelligent seeds")

    # ========================================================================
    # PHASE 1: FUZZING WITH AFL++
    # ========================================================================
    print("\n" + "=" * 70)
    print("PHASE 1: AFL++ FUZZING")
    print("=" * 70)

    try:
        afl_runner = AFLRunner(
            binary_path=binary_path,
            corpus_dir=corpus_dir,
            output_dir=out_dir / "afl_output",
            dict_path=dict_path,
            input_mode=args.input_mode,
            check_sanitizers=args.check_sanitizers,
            recompile_guide=args.recompile_guide,
            use_showmap=args.use_showmap,
        )

        num_crashes, crashes_dir = afl_runner.run_fuzzing(
            duration=args.duration,
            parallel_jobs=args.parallel,
            timeout_ms=args.timeout,
            max_crashes=args.max_crashes,
        )

        print(f"\n✓ Fuzzing complete:")
        print(f"  - Duration: {args.duration}s")
        print(f"  - Unique crashes: {num_crashes}")
        print(f"  - Crashes dir: {crashes_dir}")

        if num_crashes == 0:
            print("\nNo crashes found. Try:")
            print("    - Increasing duration (--duration)")
            print("    - Better seed corpus (--corpus)")
            print("    - Check if binary is working (./binary < test_input)")
            sys.exit(0)

    except Exception as e:
        logger.error(f"Fuzzing failed: {e}")
        print(f"\n✗ Fuzzing failed: {e}")
        sys.exit(1)

    # ========================================================================
    # PHASE 2: CRASH ANALYSIS WITH LLM
    # ========================================================================
    print("\n" + "=" * 70)
    print("PHASE 2: AUTONOMOUS CRASH ANALYSIS")
    print("=" * 70)

    try:
        # Collect crashes
        collector = CrashCollector(crashes_dir)
        crashes = collector.collect_crashes(max_crashes=args.max_crashes)
        ranked_crashes = collector.rank_crashes_by_exploitability(crashes)

        print(f"\nCollected {len(crashes)} unique crashes")
        print(f"   Analysing top {min(len(crashes), args.max_crashes)}")

        # Analyse crashes
        crash_analyser = CrashAnalyser(binary_path)
        llm_agent = CrashAnalysisAgent(
            binary_path=binary_path,
            out_dir=out_dir / "analysis",
        )

        # Initialize multi-turn analyser if autonomous mode
        if args.autonomous:
            multi_turn = MultiTurnAnalyser(llm_client=llm_agent.llm, memory=memory)
            logger.info("Multi-turn analyser initialized for deeper analysis")

        # Use autonomous crash prioritization if available
        if args.autonomous and planner:
            logger.info("Using autonomous crash prioritization...")
            # Create dummy state for prioritization
            dummy_state = FuzzingState(
                start_time=time.time(),
                current_time=time.time(),
                total_crashes=len(crashes),
                unique_crashes=len(crashes),
            )
            ranked_crashes = planner.recommend_crash_priority(ranked_crashes, dummy_state)

        # Further prioritize based on goal if set
        if args.autonomous and goal_planner:
            logger.info("Applying goal-directed crash prioritization...")
            ranked_crashes = goal_planner.prioritize_crashes_for_goal(ranked_crashes)

        analysed = 0
        exploitable = 0
        exploits_generated = 0
        seen_stack_hashes = set()  # Track stack hashes for deduplication
        skipped_duplicates = 0

        for idx, crash in enumerate(ranked_crashes[:args.max_crashes], 1):
            print(f"\n{'█' * 70}")
            print(f"CRASH {idx}/{min(len(crashes), args.max_crashes)}")
            print(f"{'█' * 70}")

            # Get crash context with GDB
            crash_context = crash_analyser.analyse_crash(
                crash_id=crash.crash_id,
                input_file=crash.input_file,
                signal=crash.signal or "unknown",
            )

            # Deduplicate by stack hash
            if crash_context.stack_hash and crash_context.stack_hash in seen_stack_hashes:
                logger.info(f"⊘ Skipping duplicate crash (stack hash: {crash_context.stack_hash})")
                print(f"⊘ Duplicate crash - same stack trace as previous crash")
                skipped_duplicates += 1
                continue

            if crash_context.stack_hash:
                seen_stack_hashes.add(crash_context.stack_hash)

            # Classify crash type
            crash_context.crash_type = crash_analyser.classify_crash_type(crash_context)
            logger.info(f"Crash type (heuristic): {crash_context.crash_type}")

            # LLM analysis - use multi-turn if autonomous mode
            if args.autonomous and multi_turn:
                # Deep multi-turn analysis
                deep_analysis = multi_turn.analyse_crash_deeply(crash_context, max_turns=3)
                logger.info(f"Multi-turn analysis confidence: {deep_analysis['confidence']:.2f}")

                # Update crash context with deep analysis
                crash_context.vulnerability_type = deep_analysis.get('vulnerability_type', crash_context.crash_type)
                if deep_analysis.get('exploitability') in ['high', 'medium']:
                    crash_context.exploitability = 'exploitable'
                else:
                    crash_context.exploitability = 'not_exploitable'

                analysed += 1

                # Record crash pattern in memory
                if memory:
                    is_exploitable = crash_context.exploitability == 'exploitable'
                    memory.record_crash_pattern(
                        signal=crash_context.signal,
                        function=crash_context.function_name or "unknown",
                        binary_hash=binary_hash,
                        exploitable=is_exploitable
                    )
            else:
                # Standard single-shot analysis
                if llm_agent.analyse_crash(crash_context):
                    analysed += 1

            # Generate exploit if exploitable
            if crash_context.exploitability == "exploitable":
                exploitable += 1

                # Check mitigations before attempting exploit generation
                if exploit_validator:
                    vuln_type = getattr(crash_context, 'vulnerability_type', None) or \
                                getattr(crash_context, 'crash_type', None)
                    viable, reason = exploit_validator.check_mitigations(binary_path, vuln_type)
                    if not viable:
                        logger.warning(f"Mitigation check: {reason}")
                        logger.warning("Exploit generation may fail - proceeding anyway")

                # Generate exploit
                if llm_agent.generate_exploit(crash_context):
                    exploits_generated += 1

                    # Validate and refine exploit if autonomous mode
                    if args.autonomous and exploit_validator and multi_turn:
                        logger.info("Validating and refining exploit...")

                        # Get the generated exploit code
                        exploit_file = out_dir / "analysis" / "exploits" / f"{crash.crash_id}_exploit.cpp"
                        if exploit_file.exists():
                            exploit_code = exploit_file.read_text()

                            # Validate and iteratively refine
                            success, refined_code, _refined_binary = exploit_validator.validate_and_refine(
                                exploit_code=exploit_code,
                                exploit_name=f"{crash.crash_id}_refined",
                                crash_context=crash_context,
                                multi_turn_analyser=multi_turn,
                                max_iterations=3
                            )

                            # If refined version is better, save it
                            if success and refined_code:
                                refined_file = out_dir / "analysis" / "exploits" / f"{crash.crash_id}_exploit_validated.c"
                                refined_file.write_text(refined_code)
                                logger.info(f"✓ Validated exploit saved: {refined_file}")

                                # Update memory with success
                                if memory:
                                    memory.record_exploit_technique(
                                        technique="validated_exploit",
                                        crash_type=crash_context.crash_type,
                                        binary_characteristics={},
                                        success=True
                                    )
                            elif refined_code:
                                # Refinement attempted but failed - save best attempt
                                refined_file = out_dir / "analysis" / "exploits" / f"{crash.crash_id}_exploit_best_attempt.c"
                                refined_file.write_text(refined_code)
                                logger.warning(f"⚠ Best attempt exploit saved: {refined_file}")

                                # Update memory with failure
                                if memory:
                                    memory.record_exploit_technique(
                                        technique="generated_exploit",
                                        crash_type=crash_context.crash_type,
                                        binary_characteristics={},
                                        success=False
                                    )
                    elif args.autonomous and memory:
                        # Record exploit technique in memory (without validation)
                        memory.record_exploit_technique(
                            technique="generated_exploit",
                            crash_type=crash_context.crash_type,
                            binary_characteristics={},
                            success=True  # Assumed success without validation
                        )

            print(f"\nProgress: {analysed}/{len(ranked_crashes[:args.max_crashes])} analysed, "
                  f"{exploitable} exploitable, "
                  f"{exploits_generated} exploits, "
                  f"{skipped_duplicates} duplicates skipped")

        print("\n✓ Analysis complete:")
        print(f"  - analysed: {analysed}")
        print(f"  - Exploitable: {exploitable}")
        print(f"  - Exploits generated: {exploits_generated}")

    except Exception as e:
        logger.error(f"Crash analysis failed: {e}")
        print(f"\n✗ Analysis failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

    # ========================================================================
    # SUMMARY
    # ========================================================================
    print("\n" + "=" * 70)
    print("RAPTOR FUZZING COMPLETE")
    print("=" * 70)
    print(f"\n Summary:")
    print(f"   Total crashes: {num_crashes}")
    print(f"   analysed: {analysed}")
    print(f"   Exploitable: {exploitable}")
    print(f"   Exploits generated: {exploits_generated}")

    print(f"\n Outputs:")
    print(f"   AFL output: {out_dir / 'afl_output'}")
    print(f"   Crashes: {crashes_dir}")
    print(f"   Analysis: {out_dir / 'analysis'}")
    print(f"   Exploits: {out_dir / 'analysis' / 'exploits'}")

    # Save summary report
    report = {
        "binary": str(binary_path),
        "duration": args.duration,
        "total_crashes": num_crashes,
        "analysed": analysed,
        "exploitable": exploitable,
        "exploits_generated": exploits_generated,
        "llm_stats": llm_agent.llm.get_stats(),
    }

    # Add autonomous stats if enabled
    if args.autonomous:
        report["autonomous"] = {
            "memory_stats": memory.get_statistics() if memory else {},
            "planner_decisions": planner.get_decision_summary() if planner else {},
            "multi_turn_dialogues": multi_turn.get_dialogue_summary() if multi_turn else {},
            "goal_summary": goal_planner.get_summary() if goal_planner else None,
        }

        # Record this campaign in memory for future learning
        if memory:
            import hashlib
            binary_hash = hashlib.sha256(binary_path.read_bytes()).hexdigest()[:16]
            memory.record_campaign({
                "binary_name": binary_path.name,
                "binary_hash": binary_hash,
                "duration": args.duration,
                "total_crashes": num_crashes,
                "exploitable_crashes": exploitable,
                "exploits_generated": exploits_generated,
            })

            # Record strategy success
            memory.record_strategy_success(
                strategy_name="default",
                binary_hash=binary_hash,
                crashes_found=num_crashes,
                exploitable_crashes=exploitable
            )

            logger.info("Campaign recorded in memory for future learning")

    report_file = out_dir / "fuzzing_report.json"
    save_json(report_file, report)

    print(f"   Report: {report_file}")

    if args.autonomous and memory:
        print(f"\n Autonomous Learning:")
        stats = memory.get_statistics()
        print(f"   Knowledge entries: {stats['total_knowledge']}")
        print(f"   Average confidence: {stats['average_confidence']:.2f}")
        print(f"   Total campaigns: {stats['total_campaigns']}")

    print("\n" + "=" * 70)
    print("✨ Review exploits and test in isolated environment")
    print("=" * 70)


if __name__ == "__main__":
    main()
