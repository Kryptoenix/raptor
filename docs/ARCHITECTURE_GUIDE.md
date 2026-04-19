# RAPTOR Architecture Guide

> Reference for understanding the code flow, extending functionality, or debugging issues.

---

## RAPTOR v2 Architecture

RAPTOR v2 reorganises the app around **2 modes** (Web App / Binary) with **2 phases** (Discovery / Validation), while keeping all legacy modes functional.

```
┌─────────────────────────────────────────────────────────────┐
│                     web_server.py                            │
│  Flask UI: 2 mode cards, toggle switches, URL inputs         │
│  Pipeline animation: Discovery → Analysis →                  │
│                      Exploitation → Patching → Presenting   │
│                                                              │
│  /upload → run_job() thread:                                 │
│    Step 1: safe_extract_zip() (restores +x on ELFs)         │
│    Step 2: mkdir exploits/ patches/                          │
│    Step 3: build raptor.py <mode> command with toggles      │
│    Step 4: subprocess → raptor.py                            │
│    Step 5: (legacy only) _run_llmscan_phase()                │
│    Step 6: set final status                                  │
└──────────────────────────┬───────────────────────────────────┘
                           │ subprocess
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                       raptor.py                              │
│  CLI dispatcher                                              │
│                                                              │
│  v2 modes:                                                   │
│    webapp   → raptor_webapp.py                               │
│    binary   → raptor_binary.py                               │
│                                                              │
│  Legacy modes (still work):                                  │
│    scan, agentic, codeql, llmscan, fuzz                      │
└─────────────────────────────────────────────────────────────┘
```

## v2 Pipeline Flow

```
┌───────────────────────────────────────────────────────────┐
│              raptor_webapp.py / raptor_binary.py          │
│                                                           │
│  ┌─────────────────────────────────────────────────┐    │
│  │  PHASE 1: DISCOVERY  (packages/discovery/)      │    │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐     │    │
│  │  │TruffleHog│  │ Semgrep  │  │  CodeQL  │     │    │
│  │  └────┬─────┘  └────┬─────┘  └────┬─────┘     │    │
│  │       │             │             │            │    │
│  │       └─────────────┴─────────────┘            │    │
│  │                     │                           │    │
│  │                     ▼                           │    │
│  │              ┌──────────────┐                   │    │
│  │              │   LLMScan    │                   │    │
│  │              │  (strategy:  │                   │    │
│  │              │ webapp/bin)  │                   │    │
│  │              └──────┬───────┘                   │    │
│  │                     ▼                           │    │
│  │        ┌─────────────────────────┐             │    │
│  │        │ discovery_findings.json │             │    │
│  │        └────────────┬────────────┘             │    │
│  └─────────────────────┼───────────────────────────┘    │
│                        ▼                                 │
│  ┌─────────────────────────────────────────────────┐    │
│  │  (BINARY ONLY) PHASE 2: FUZZING                 │    │
│  │    Compile → Instrument AFL++ → Fuzz →          │    │
│  │    Crash analysis (gdb + valgrind)              │    │
│  └─────────────────────┬───────────────────────────┘    │
│                        ▼                                 │
│  ┌─────────────────────────────────────────────────┐    │
│  │  PHASE N: VALIDATION  (packages/validation/)    │    │
│  │                                                  │    │
│  │  1. Deduplicate across all tool outputs         │    │
│  │  2. For each finding:                            │    │
│  │     • Extract vuln_code + surrounding_context   │    │
│  │     • TruffleHog → credential impact            │    │
│  │     • LLM → exploit PoC + patch + remediation   │    │
│  │  3. (Web) Live testing: nmap, gobuster, sqlmap  │    │
│  │                                                  │    │
│  └─────────────────────┬───────────────────────────┘    │
│                        ▼                                 │
│            ┌──────────────────────┐                     │
│            │  merged_report.json  │                     │
│            └──────────────────────┘                     │
└───────────────────────────────────────────────────────────┘
```

## Unified Finding Schema (28 fields)

Every finding from every tool gets enriched to this schema in the validation phase:

```python
FINDING_SCHEMA_FIELDS = [
    # Core identification
    "rule_id", "file_path", "start_line", "end_line",
    "message", "tool", "severity", "level",
    "vuln_type", "cwe_id", "confidence",

    # Validation
    "is_true_positive", "is_exploitable", "exploitability_score",
    "ruling", "cvss_score_estimate", "cvss_vector",

    # Analysis
    "reasoning", "attack_scenario", "impact",
    "remediation", "dataflow_summary",
    "false_positive_reason",  # optional

    # Code artifacts
    "exploit_code", "patch_code",
    "vuln_code",              # 1-3 lines where bug resides
    "surrounding_context",    # lines around vulnerable code

    "sources",  # list of tools that found this finding
]
```

## Web UI Flow

```
User uploads ZIP + selects:
┌─────────────────────────────────────┐
│  [🌐 Web App]      [🔧 Binary]      │  ← mode cards
├─────────────────────────────────────┤
│  [✓] Semgrep    [✗] CodeQL         │  ← tool toggles
│  [✓] TruffleHog [✓] LLMScan        │
│  [ ] Fuzzing (binary only)         │
├─────────────────────────────────────┤
│  🎯 APP URL    (webapp)            │  ← conditional inputs
│  🔀 PROXY URL  (webapp)            │
│  🐛 BUG TRACK  (binary)            │
└─────────────────────────────────────┘
         │
         ▼ JS translates toggles to
          --no-<tool> and --app-url etc.
         │
         ▼
[POST /upload] → run_job thread → raptor.py webapp/binary

Results page:
┌──────────────────────────────────────┐
│  🚀 Pipeline                         │
│  ● Discovery → ● Analysis →          │
│  ○ Exploitation → ○ Patching →      │  ← animated, updates from log
│  ○ Presenting                        │
├──────────────────────────────────────┤
│  📊 Summary                          │
│  Findings: 12 | Exploitable: 5 ...   │
├──────────────────────────────────────┤
│  🔍 Findings                         │
│  [filters] [search]                  │
│  ── each finding shows ──            │
│    • Vulnerable Code (highlighted)  │
│    • Surrounding Context            │
│    • Attack Scenario                │
│    • Exploit PoC (code block)       │
│    • Patch (diff/code)              │
│    • Remediation, CWE, CVSS, ...    │
├──────────────────────────────────────┤
│  📋 Log Output (live)                │
└──────────────────────────────────────┘
```

---

## High-Level Overview

RAPTOR has **5 analysis modes** served through a **web UI** (`web_server.py`) or **CLI** (`raptor.py`). Each mode runs a different pipeline but they share common infrastructure (LLM client, SARIF parsing, reporting).

```
┌─────────────────────────────────────────────────────────┐
│                    web_server.py                         │
│  Flask app — upload ZIP, select mode, view results      │
│                                                         │
│  /upload → run_job() thread:                            │
│    Step 1: safe_extract_zip()                           │
│    Step 2: mkdir exploits/ patches/                     │
│    Step 3: build raptor.py <mode> command               │
│    Step 4: subprocess → raptor.py                       │
│    Step 5: _run_llmscan_phase() (scan/agentic/codeql)   │
│    Step 6: set final status                             │
│                                                         │
│  /results/<id> → collect_results() + build_summary()    │
└───────────────────────┬─────────────────────────────────┘
                        │ subprocess
                        ▼
┌─────────────────────────────────────────────────────────┐
│                      raptor.py                           │
│  CLI dispatcher — routes to mode handler                 │
│                                                         │
│  scan     → packages/static-analysis/scanner.py          │
│  agentic  → raptor_agentic.py                            │
│  codeql   → raptor_codeql.py                             │
│  llmscan  → raptor_llmscan.py                            │
│  fuzz     → raptor_fuzzing.py                            │
└─────────────────────────────────────────────────────────┘
```

---

## Mode Pipelines

### 1. `scan` — Semgrep + LLM Direct-Code Scan

```
raptor.py scan
  │
  ├─ packages/static-analysis/scanner.py
  │    └─ Runs Semgrep with engine/semgrep/rules/*.yaml
  │    └─ Outputs: SARIF files
  │
  └─ (web_server Step 5) _run_llmscan_phase()
       └─ packages/llm_scan/  ← LLM scanner (see §LLMScan below)
       └─ Merges LLM findings + SARIF → merged_report.json
```

**When to modify:** Adding Semgrep rules → `engine/semgrep/rules/`. Changing how SARIF is parsed → `core/sarif/parser.py`.

---

### 2. `agentic` — Full Autonomous Pipeline

The richest mode. Runs everything.

```
raptor_agentic.py
  │
  ├─ Phase 0: Pre-exploit mitigation analysis (optional)
  │    └─ packages/exploit_feasibility/
  │
  ├─ Phase 1: CODE SCANNING
  │    ├─ Semgrep (parallel)  → SARIF files
  │    └─ CodeQL  (parallel)  → SARIF files
  │         └─ packages/codeql/agent.py (see §CodeQL below)
  │
  ├─ Phase 2: EXPLOITABILITY VALIDATION
  │    └─ packages/exploitability_validation/
  │    └─ Deduplicates SARIF findings, filters noise
  │    └─ Input: N findings → Output: M unique findings (M ≤ N)
  │
  ├─ Phase 3: AUTONOMOUS ANALYSIS (prep)
  │    └─ packages/llm_analysis/agent.py
  │    └─ Reads validated findings, prepares for LLM analysis
  │
  ├─ Phase 4: AGENTIC ORCHESTRATION
  │    └─ packages/llm_analysis/orchestrator.py
  │    └─ packages/llm_analysis/dispatch.py / cc_dispatch.py
  │    └─ For each finding: LLM analysis → exploit gen → patch gen
  │    └─ Output: orchestrated_report.json
  │
  ├─ Phase 5: LLM DIRECT-CODE SCAN
  │    └─ packages/llm_scan/ (same as llmscan mode)
  │    └─ Output: merged_report.json
  │
  └─ FINAL REPORT
       └─ raptor_agentic_report.json (master summary)
       └─ agentic-report.md (human-readable)
```

**When to modify:** Adding a new analysis phase → insert between existing phases in `raptor_agentic.py:main()`. Changing LLM prompts for finding analysis → `packages/llm_analysis/prompts/`. Changing orchestration logic → `packages/llm_analysis/orchestrator.py`.

---

### 3. `codeql` — CodeQL + LLM Analysis

```
raptor_codeql.py
  │
  ├─ Phase 1: CODEQL SCANNING
  │    └─ packages/codeql/agent.py (see §CodeQL below)
  │
  ├─ Phase 2: AUTONOMOUS ANALYSIS
  │    └─ packages/codeql/autonomous_analyzer.py
  │    └─ For each finding: LLM deep analysis + exploit gen
  │
  └─ (web_server Step 5) _run_llmscan_phase()
       └─ Merges LLM scan findings with CodeQL SARIF
```

**When to modify:** CodeQL query suites → `engine/codeql/suites/`. Build system detection → `packages/codeql/build_detector.py`. Language detection → `packages/codeql/language_detector.py`.

---

### 4. `llmscan` — LLM Direct-Code Scanner (standalone)

```
raptor_llmscan.py
  │
  ├─ Phase 1: LLM SCAN
  │    └─ LLMScanner.scan() (see §LLMScan below)
  │
  ├─ Phase 2: LOAD SARIF (if --sarif provided)
  │    └─ merger.load_sarif_findings()
  │
  └─ Phase 3: MERGE & DEDUPLICATE
       └─ merger.merge_findings()
       └─ Output: merged_report.json
```

**Note:** When triggered via web_server, `llmscan` mode does NOT run `_run_llmscan_phase()` in Step 5 (would duplicate). The guard is at `web_server.py:885`: `if job.mode in {"scan", "agentic", "codeql"}` — llmscan is excluded.

---

### 5. `fuzz` — AFL++ Binary Fuzzing

```
raptor_fuzzing.py
  │
  ├─ Phase 0: SOURCE INSTRUMENTATION (--repo mode only)
  │    └─ _detect_fuzz_build() — finds Makefile/CMake/autotools/meson
  │    └─ Compiles with CC=afl-clang-fast
  │    └─ _find_instrumented_binary() — locates ELF output
  │    └─ _detect_input_mode() — stdin vs file (@@)
  │    └─ Auto-discovers corpus/ and *.dict from repo
  │
  ├─ Phase 1: AFL++ FUZZING
  │    └─ packages/fuzzing/afl_runner.py
  │    └─ Monitors crashes, logs stats every 60s
  │
  └─ Phase 2: CRASH ANALYSIS
       └─ packages/binary_analysis/crash_analyser.py
       └─ packages/llm_analysis/crash_agent.py
       └─ Autonomous mode: packages/autonomous/ (planner, memory, goals)
```

**When to modify:** Build system detection → `_detect_fuzz_build()` in `raptor_fuzzing.py`. AFL++ flags/env → `packages/fuzzing/afl_runner.py:_build_afl_command()` and `_get_afl_env()`. Input mode detection → `_detect_input_mode()` in `raptor_fuzzing.py`.

---

## §LLMScan — Core LLM Scanning Pipeline

This is the most frequently modified subsystem. Located in `packages/llm_scan/`.

```
LLMScanner.scan()                          [scanner.py]
  │
  ├─ _build_context_index()
  │    Indexes all scannable files by stem name
  │    Logs tier breakdown (T1/T2/T3)
  │
  ├─ walk_repo()                            [chunker.py]
  │    ├─ Collects ALL scannable files
  │    ├─ _security_tier() assigns T1/T2/T3
  │    │    T1 (always scan): controllers, configs, templates, auth, .env
  │    │    T2 (budget fill): models, services, repos, DB, crypto
  │    │    T3 (remainder):   everything else
  │    ├─ Sorts by tier → then by file size (smallest first)
  │    ├─ T1 files bypass max_files cap
  │    └─ For each file: chunk_file()
  │         Small files (≤300 lines): single chunk
  │         Structured: split at function/class boundaries
  │         Large: sliding window (250 lines, 40 overlap)
  │
  └─ For each chunk:
       ├─ _gather_related_context()
       │    Finds related files (repos, models, services) by identifier matching
       │    Budget: 2000 chars max
       │
       ├─ _scan_chunk()
       │    ├─ _build_chunk_prompt() — file hints + code + related context
       │    ├─ LLM.generate(system_prompt, chunk_prompt, max_tokens=8192)
       │    ├─ _parse_response() — JSON extraction + validation
       │    │    ├─ Direct JSON parse
       │    │    ├─ Regex extraction fallback
       │    │    ├─ _salvage_truncated_json() — brace-matching recovery
       │    │    ├─ Quality gate: reject empty findings (no message + no reasoning)
       │    │    └─ Per-chunk cap: MAX_FINDINGS_PER_CHUNK = 15
       │    │
       │    └─ TRUNCATION RETRY (if parse returned 0 but raw has '{'):
       │         Resends with compact prompt (minimal system prompt,
       │         no related context, asks for ≤30-word fields)
       │
       └─ Collect findings → llmscan_findings.json
```

### Key files to modify:

| What | Where |
|------|-------|
| System prompt (what LLM looks for) | `scanner.py:SECURITY_SYSTEM_PROMPT` |
| Per-chunk prompt (file hints, context) | `scanner.py:_build_chunk_prompt()` |
| File type support (.html, .scala, etc.) | `chunker.py:SCANNABLE_EXTENSIONS` + `_EXT_LANG` |
| File prioritisation patterns | `chunker.py:_TIER1_PATH_PATTERNS` / `_TIER2_PATH_PATTERNS` |
| Chunk size limits | `chunker.py:MAX_CHUNK_LINES` / `WINDOW_LINES` / `OVERLAP_LINES` |
| Finding quality filter | `scanner.py:_parse_response()` quality gate |
| Hallucination cap | `scanner.py:MAX_FINDINGS_PER_CHUNK` |
| Truncation recovery | `scanner.py:_salvage_truncated_json()` |
| Truncation retry | `scanner.py:_scan_chunk()` compact retry block |
| Finding deduplication | `merger.py:merge_findings()` |
| Path normalisation (SARIF vs LLM paths) | `merger.py:_norm_path()` |

---

## §CodeQL — Database Creation Pipeline

Located in `packages/codeql/`.

```
CodeQLAgent.run_autonomous_analysis()      [agent.py]
  │
  ├─ Phase 1: language_detector.py
  │    Auto-detects languages from file extensions + content
  │
  ├─ Phase 2: build_detector.py
  │    Interpreted languages (Python, JS, Ruby, TS):
  │      → no-build mode (CodeQL extracts source directly)
  │    Compiled languages (Java, C, C++, Go, C#):
  │      → detect Maven/Gradle/Make/CMake → build command
  │
  ├─ Phase 3: database_manager.py
  │    Creates CodeQL databases (parallel)
  │    Handles build scripts, timeouts, cleanup
  │
  ├─ Phase 4: query_runner.py
  │    Runs security-and-quality query suites
  │    Downloads query packs if missing
  │    Output: SARIF files
  │
  └─ Phase 5: Report generation
```

---

## §Web Server — Results Display

```
collect_results()                          [web_server.py]
  │
  ├─ Priority 1: orchestrated_report.json
  │    (agentic mode: has LLM analysis, exploits, patches)
  │
  ├─ Priority 1b: SUPPLEMENT from merged_report.json
  │    Adds LLM-only findings (sources=["llmscan"]) not
  │    already in orchestrated results (dedup by file+line+rule)
  │
  ├─ Priority 2: merged_report.json (standalone, if no orchestrated)
  │
  ├─ Priority 3: raptor_agentic_report.json (summary fallback)
  │
  ├─ Priority 4: autonomous_analysis_report.json
  │
  ├─ Priority 5: Loose exploit files from exploits/ dirs
  │
  └─ Priority 6: Loose patch files from patches/ dirs

build_summary()
  └─ Pulls counts from _raw_json (orchestrated > merged > agentic)
  └─ total_findings overridden if supplemented findings > reported count
```

---

## §LLM Client — Provider Abstraction

Located in `packages/llm_analysis/llm/`.

```
LLMClient                                 [client.py]
  │
  ├─ config.py: LLMConfig
  │    Auto-detects: Anthropic API key, OpenAI key, Ollama server
  │    Model selection: primary → fallback (same tier only)
  │    Budget tracking, caching, retry logic
  │
  ├─ providers.py: Provider implementations
  │    ├─ OllamaProvider (OpenAI-compatible /v1 endpoint)
  │    ├─ AnthropicProvider
  │    ├─ OpenAIProvider
  │    └─ GoogleProvider
  │
  ├─ detection.py: detect_llm_availability()
  │    Checks env vars, config files, Ollama connectivity
  │
  └─ model_data.py: MODEL_LIMITS
       Token limits, costs per model
```

**Key:** `_warned_local_model` flag prevents "exploit PoCs unreliable" spam. Set once per LLMClient instance.

---

## §Merger — Finding Deduplication

Located in `packages/llm_scan/merger.py`.

```
merge_findings(llm_findings, sarif_findings)
  │
  ├─ normalise_finding() — unified schema for all sources
  │
  ├─ _norm_path() — path normalisation
  │    Handles: absolute vs relative, SARIF vs LLM paths
  │    Strategy: find repo markers (src/, templates/, static/),
  │    strip prefix. Fallback: filename only.
  │
  ├─ Union-find clustering
  │    Two findings = duplicate when:
  │    1. Same normalised file path
  │    2. Overlapping line ranges
  │    3. _similarity() ≥ 0.5 (vuln_type, CWE, rule_id match)
  │
  └─ Merge clusters: keep richest finding, supplement from others
```

---

## §Exploit Feasibility — Mitigation Analysis

Located in `packages/exploit_feasibility/`.

```
check_exploit_viability(binary_path, vuln_type)   [api.py]
  │
  ├─ _get_profile_for_vuln_type()
  │    Web vulns (SQLi, XSS, SSRF, etc.) → WebApplicationStrategy
  │      → Skips memory mitigation checks entirely
  │    CodeQL rule IDs (py/sql-injection) → pattern matching
  │      → Web language prefixes (py/, js/, rb/) → web profile
  │    Binary/memory vulns → LocalBinaryStrategy
  │      → glibc, kernel, compiler, ASLR, NX checks
  │
  └─ FeasibilityAnalyzer.full_analysis()          [analyzer.py]
```

**Key fix:** CodeQL rule IDs like `py/flask-debug` are now matched to web profile via `_CODEQL_WEB_PATTERNS` and language prefix detection, preventing irrelevant binary analysis on web vulns.

---

## Directory Structure

```
raptor/
├── raptor.py                  # CLI dispatcher (all modes)
├── raptor_agentic.py          # Agentic pipeline
├── raptor_codeql.py           # CodeQL pipeline
├── raptor_fuzzing.py          # Fuzz pipeline (Phase 0 instrumentation)
├── raptor_llmscan.py          # LLMScan standalone pipeline
├── web_server.py              # Flask web UI + job runner
│
├── core/                      # Shared infrastructure
│   ├── config.py              # RaptorConfig (paths, timeouts, env)
│   ├── logging.py             # RaptorLogger (supports %s-style args)
│   ├── json/                  # JSON load/save utilities
│   ├── sarif/                 # SARIF parser
│   ├── reporting/             # Console tables, markdown reports
│   ├── inventory/             # Code inventory builder
│   └── project/               # Project management (findings, diff)
│
├── packages/
│   ├── llm_scan/              # LLM direct-code scanner
│   │   ├── scanner.py         # LLMScanner class + prompts
│   │   ├── chunker.py         # File walking, chunking, tiering
│   │   └── merger.py          # Finding merge + dedup + path norm
│   │
│   ├── llm_analysis/          # LLM finding analysis
│   │   ├── llm/               # LLM client, providers, config
│   │   ├── agent.py           # Analysis agent
│   │   ├── orchestrator.py    # Parallel orchestration
│   │   ├── dispatch.py        # Task dispatch
│   │   ├── crash_agent.py     # Crash analysis for fuzz mode
│   │   └── prompts/           # LLM prompt templates
│   │
│   ├── codeql/                # CodeQL integration
│   │   ├── agent.py           # Orchestrates full CodeQL pipeline
│   │   ├── build_detector.py  # Build system detection (interpreted = no-build)
│   │   ├── database_manager.py# DB creation + parallel execution
│   │   ├── language_detector.py
│   │   ├── query_runner.py    # Query execution + SARIF output
│   │   └── autonomous_analyzer.py  # LLM analysis of CodeQL findings
│   │
│   ├── fuzzing/               # AFL++ integration
│   │   ├── afl_runner.py      # AFL command builder, env, monitoring
│   │   ├── corpus_manager.py  # Seed corpus management
│   │   └── crash_collector.py # Crash dedup + collection
│   │
│   ├── exploit_feasibility/   # Mitigation analysis
│   │   ├── api.py             # Public API + vuln-type → profile routing
│   │   ├── analyzer.py        # Full analysis (glibc, kernel, binary)
│   │   └── profiles.py        # LocalBinary vs WebApp strategies
│   │
│   ├── exploitability_validation/  # Finding validation + dedup
│   ├── autonomous/            # Autonomous fuzzing (planner, memory, goals)
│   ├── binary_analysis/       # Crash analysis, debugger integration
│   └── static-analysis/       # Semgrep scanner wrapper
│
├── engine/
│   ├── semgrep/rules/         # Custom Semgrep rules (YAML)
│   └── codeql/suites/         # CodeQL query suite configs
│
└── templates/
    └── results.html           # Jinja2 template for web results page
```

---

## Common Modification Scenarios

### "I want to add support for a new language (e.g., Dart)"
1. `chunker.py`: Add `.dart` to `_EXT_LANG` and `SCANNABLE_EXTENSIONS`
2. `chunker.py`: Add `"dart"` structural patterns to `_STRUCTURE_PATTERNS`
3. `build_detector.py`: Add `"dart"` to `INTERPRETED_LANGUAGES` if applicable

### "I want to change what the LLM scanner looks for"
1. `scanner.py`: Edit `SECURITY_SYSTEM_PROMPT` — keep it short (< 20 lines for local models)
2. `scanner.py`: Edit `_build_chunk_prompt()` file hints for targeted guidance

### "I want to add a new analysis mode"
1. Create `raptor_newmode.py` with a `main()` function
2. `raptor.py`: Add `mode_newmode()` handler + entry in `mode_handlers` dict
3. `web_server.py`: Add to `ALLOWED_MODES`, add UI radio button in `INDEX_HTML`
4. `web_server.py`: Handle in `run_job()` Step 3 command builder

### "LLM findings are being missed (truncation)"
1. Check `scanner.py:_scan_chunk()` — compact retry should trigger
2. If retry also truncates: reduce `SECURITY_SYSTEM_PROMPT` length
3. Increase `max_tokens` in `_scan_chunk()` (if model supports it)
4. Reduce `MAX_CHUNK_LINES` in `chunker.py` (smaller input = more output budget)

### "Findings from LLM scan don't show in web UI"
1. Check `web_server.py:collect_results()` — Priority 1b supplements orchestrated with LLM-only
2. Check `merger.py:_norm_path()` — paths must normalise to same string
3. Check `web_server.py:build_summary()` — `total_findings` must reflect supplemented count

### "AFL++ won't start"
1. Check `afl_runner.py:_get_afl_env()` — environment variables for common issues
2. Check `afl_runner.py:_scan_chunk()` early exit detection (2s startup check)
3. Check `raptor_fuzzing.py:_detect_input_mode()` — stdin vs file mode

### "CodeQL fails to create database"
1. Check `build_detector.py:INTERPRETED_LANGUAGES` — Python/JS/Ruby/TS should be no-build
2. Check `build_detector.py:detect_build_system()` — returns no-build for interpreted
3. Check `database_manager.py` — empty command skips `--command` flag
