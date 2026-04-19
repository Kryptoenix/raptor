```text
╔═══════════════════════════════════════════════════════════════════════════╗
║                                                                           ║
║             ██████╗  █████╗ ██████╗ ████████╗ ██████╗ ██████╗             ║
║             ██╔══██╗██╔══██╗██╔══██╗╚══██╔══╝██╔═══██╗██╔══██╗            ║
║             ██████╔╝███████║██████╔╝   ██║   ██║   ██║██████╔╝            ║
║             ██╔══██╗██╔══██║██╔═══╝    ██║   ██║   ██║██╔══██╗            ║
║             ██║  ██║██║  ██║██║        ██║   ╚██████╔╝██║  ██║            ║
║             ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝        ╚═╝    ╚═════╝ ╚═╝  ╚═╝            ║
║                                                                           ║
║                         ██╗   ██╗██████╗                                  ║
║                         ██║   ██║╚════██╗                                 ║
║                         ██║   ██║ █████╔╝                                 ║
║                         ╚██╗ ██╔╝██╔═══╝                                  ║
║                          ╚████╔╝ ███████╗                                 ║
║                           ╚═══╝  ╚══════╝                                 ║
║                                                                           ║
║             Autonomous Security Analysis Framework                        ║
║                                                                           ║
╚═══════════════════════════════════════════════════════════════════════════╝
```

**RAPTOR V2** is an autonomous security analysis framework that combines static analysis, LLM-powered code review, secrets scanning, and binary fuzzing into a unified pipeline. Upload a source code repository, select a mode, and RAPTOR handles discovery, validation, exploit generation, and patch creation — all from a single web interface or CLI.

---

## Features

### Two Analysis Modes

| Mode | Target | Discovery Tools | Validation |
|------|--------|-----------------|------------|
| **Web App** | Web applications (Flask, Django, Spring, Express, Rails, ASP.NET, etc.) | Semgrep + CodeQL + TruffleHog + LLMScan | Exploit PoC + patch + remediation. Optional live testing with nmap, gobuster, sqlmap. |
| **Binary** | C/C++ applications, firmware, compiled binaries | Semgrep + CodeQL + TruffleHog + LLMScan + AFL++ fuzzing | Crash analysis with gdb, rr, valgrind. QEMU firmware emulation. |

### Discovery Phase

- **Semgrep** — fast static analysis with custom and community rules
- **CodeQL** — deep semantic analysis (auto-detects language and build system)
- **TruffleHog** — scans for hardcoded secrets, API keys, passwords, tokens
- **LLMScan** — AI-powered code review that reads source code directly and finds vulnerabilities that rule-based tools miss (SQL injection, XSS, CSRF, deserialization, path traversal, SSRF, command injection, memory corruption, and more)
- Each tool is **independently toggleable** — enable only what you need
- **Reflexive retry loop** — if a tool fails, RAPTOR retries automatically
- **README-aware** — reads the project README before analysis for context

### Validation Phase

- **Deduplication** — merges overlapping findings across all tools
- **Source extraction** — extracts `vuln_code` (the exact vulnerable lines) and `surrounding_context` (neighbouring lines with line numbers)
- **LLM-powered exploit + patch generation** — for each finding, generates a working proof-of-concept and a fixed version of the code
- **TruffleHog credential impact** — shows exactly how a discovered secret can be abused (e.g., `mysql -u root -p'<found_password>' -h <host>`)
- **28-field unified finding schema** — every finding includes rule_id, file_path, CWE, CVSS, severity, exploit_code, patch_code, vuln_code, remediation, and more

### Web App Mode Extras

- **APP URL testing** — test discovered findings against a live target using nmap (port scan), gobuster (directory brute-force), and sqlmap (SQL injection validation)
- **Proxy support** — route all outbound requests through Burp Suite, ZAP, or any HTTP proxy

### Binary Mode Extras

- **Source → Binary pipeline** — automatically detects build system (Makefile, CMake, autotools, meson), compiles with AFL++ instrumentation (`afl-clang-fast`), and fuzzes the result
- **Pre-compiled binary** — accepts an existing binary for fuzzing and reverse engineering
- **Input mode detection** — automatically determines if the binary reads from stdin or file arguments
- **Crash analysis** — parses crashes with gdb (backtrace, registers, disassembly), rr (reverse execution for root cause analysis), and valgrind (memory errors, leaks)
- **QEMU emulation** — runs cross-architecture binaries (ARM, MIPS, AARCH64, etc.) under QEMU user-mode emulation
- **Bug Track URL** — fetches crash reports or PoC from a URL, extracts stack traces and CVE references, and tests them against the binary

### Web Interface

- **Two mode cards** — Web App or Binary, click to select
- **Toggle switches** — enable/disable each tool individually (Semgrep, CodeQL, TruffleHog, LLMScan, Fuzzing)
- **Pipeline animation** — GitHub Actions-style progress indicator: Discovery → Analysis → Exploitation → Patching → Presenting
- **Live log streaming** — watch the analysis in real time
- **Finding details** — expandable cards with vulnerable code (red-highlighted), surrounding context, exploit PoC, patch, reasoning, attack scenario, CVSS, CWE
- **Export** — download reports as JSON or PDF

---

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/Kryptoenix/raptor.git
cd raptor
```

### 2. Install Python Dependencies

```bash
pipenv shell
pip install -r requirements.txt
```

Required packages: `flask`, `requests`, `pydantic`, `instructor`, `tabulate`.

### 3. Install an LLM Provider

RAPTOR needs at least one LLM provider for AI-powered scanning and exploit generation. Choose one:

**Option A: Ollama (local, free, recommended for getting started)**

```bash
# Install Ollama
curl -fsSL https://ollama.ai/install.sh | sh

# Pull a model
ollama pull gemma3:4b         
# or
ollama pull llama3.1:8b       
# or
ollama pull gemma4:e2b         
```

Ollama runs locally — no API keys needed. RAPTOR auto-detects it on `http://localhost:11434`.

**Option B: Cloud LLM (Anthropic, OpenAI, or Google)**

```bash
# Anthropic Claude 
export ANTHROPIC_API_KEY="sk-ant-..."

# OpenAI GPT
export OPENAI_API_KEY="sk-..."

# Google Gemini
export GOOGLE_API_KEY="AI..."
```

Install the corresponding SDK:

```bash
pip install anthropic    # for Claude
pip install openai       # for GPT / Ollama
pip install google-genai # for Gemini
```

### 4. Install External Tools (optional, enhances results)

Each tool is optional — RAPTOR skips any that aren't installed.

```bash
# Static analysis 
pip install semgrep

# Secrets scanning 
pip install trufflehog

# Deep static analysis
# Download from https://github.com/github/codeql-cli-binaries/releases
# Add to PATH

# Binary analysis
sudo apt install gdb valgrind    # crash analysis
sudo apt install afl++           # fuzzing (or build from source)
sudo apt install rr              # reverse debugging (Linux x86/x86_64)

# Cross-architecture emulation
sudo apt install qemu-user-static

# Web app live testing
sudo apt install nmap
sudo apt install gobuster
sudo apt install sqlmap
```

### 5. Verify Installation

```bash
python3 raptor.py
```

You should see the help output listing all available modes.

---

## Usage

### Web Interface (recommended)

```bash
python3 web_server.py --host 0.0.0.0 --port 5000
```

Open `http://localhost:5000` in your browser. Upload a ZIP of your target repository, select a mode, toggle the tools you want, and click "Start Analysis".

### CLI — Web App Mode

```bash
# Full scan with all tools
python3 raptor.py webapp --repo /path/to/webapp

# Semgrep + LLMScan only (skip CodeQL and TruffleHog)
python3 raptor.py webapp --repo /path/to/webapp --no-codeql --no-trufflehog

# With live testing against a running app
python3 raptor.py webapp --repo /path/to/webapp --app-url https://target.com

# With proxy (Burp Suite)
python3 raptor.py webapp --repo /path/to/webapp --app-url https://target.com --proxy-url http://127.0.0.1:8080
```

### CLI — Binary Mode

```bash
# Source code → compile → instrument → fuzz → analyse
python3 raptor.py binary --repo /path/to/c-project --fuzz --asan

# Pre-compiled binary → fuzz → analyse
python3 raptor.py binary --binary /path/to/binary --fuzz --duration 600

# Source code scan only (no fuzzing)
python3 raptor.py binary --repo /path/to/c-project

# With QEMU emulation (for ARM/MIPS firmware)
python3 raptor.py binary --binary /path/to/firmware --emulate

# Analyse a crash from a bug tracker
python3 raptor.py binary --binary /path/to/binary --bug-track-url https://bugs.example.com/issue/1234
```

### CLI — Legacy Modes

The original modes still work:

```bash
python3 raptor.py scan --repo /path/to/code              # Semgrep only
python3 raptor.py agentic --repo /path/to/code            # Full autonomous
python3 raptor.py codeql --repo /path/to/code             # CodeQL only
python3 raptor.py llmscan --repo /path/to/code            # LLMScan only
python3 raptor.py fuzz --repo /path/to/c-project          # AFL++ only
python3 raptor.py fuzz --binary /path/to/binary           # AFL++ on binary
```

---

## Repository Structure for Fuzzing

When using binary mode with `--repo`, RAPTOR expects a C/C++ project with a build system. It automatically detects and uses the following:

```
your-project/
├── Makefile              # or CMakeLists.txt, configure, meson.build
├── src/
│   └── *.c / *.cpp       # source files
├── corpus/               # (optional) seed inputs for AFL++
│   ├── sample1.bin       #   also checks: seeds/, testcases/, inputs/, in/
│   └── sample2.txt
└── dictionary.dict       # (optional) AFL++ dictionary
                          #   also checks: *.dict, dict/*.dict
```

RAPTOR will:
1. Detect the build system (Makefile → CMake → autotools → meson → single `.c` fallback)
2. Compile with `CC=afl-clang-fast` for instrumentation
3. Find the resulting ELF binary (prefers names containing "fuzz", else largest)
4. Auto-detect input mode (stdin vs file arguments)
5. Start fuzzing with auto-discovered corpus and dictionary

---

## Finding Schema

Every finding is enriched to a 28-field schema:

```
rule_id                   Short identifier (e.g., "sqli-string-concat")
file_path                 Relative path to the vulnerable file
start_line / end_line     Line range of the vulnerability
message                   One-sentence description
tool                      Which tool found it (semgrep, codeql, trufflehog, llmscan, afl++)
severity                  critical / high / medium / low
vuln_type                 Category (sql_injection, xss, buffer_overflow, etc.)
cwe_id                    CWE identifier (e.g., "CWE-89")
confidence                high / medium / low
is_true_positive          Boolean
is_exploitable            Boolean
exploitability_score      0.0–1.0
ruling                    Validation result (e.g., "confirmed-by-sqlmap")
cvss_score_estimate       Numeric CVSS score
cvss_vector               CVSS 3.1 vector string
reasoning                 Why this is exploitable (cites code)
attack_scenario           Step-by-step exploitation
impact                    What an attacker achieves
remediation               How to fix it
dataflow_summary          Source → transform → sink
exploit_code              Working proof-of-concept
patch_code                Fixed version of the code
vuln_code                 The 1-3 lines where the bug resides
surrounding_context       Lines around the vulnerable code (with line numbers)
sources                   List of tools that detected this finding
```

---

## Configuration

### LLM Models

RAPTOR auto-detects available LLM providers. To override model selection, create a `models.json` in the RAPTOR root:

```json
{
  "primary": {
    "provider": "ollama",
    "model": "gemma4:e2b"
  },
  "fallback": [
    {
      "provider": "ollama",
      "model": "llama3.1:8b"
    }
  ]
}
```

### Environment Variables

| Variable | Description |
|----------|-------------|
| `ANTHROPIC_API_KEY` | Anthropic Claude API key |
| `OPENAI_API_KEY` | OpenAI GPT API key |
| `GOOGLE_API_KEY` | Google Gemini API key |
| `OLLAMA_HOST` | Ollama server URL (default: `http://localhost:11434`) |
| `RAPTOR_MAX_UPLOAD_MB` | Max upload size for web interface (default: 100) |

---

## Architecture

```
                    ┌──────────────────────┐
                    │    web_server.py      │
                    │   Flask Web Interface │
                    └──────────┬───────────┘
                               │
                    ┌──────────▼───────────┐
                    │      raptor.py        │
                    │    CLI Dispatcher     │
                    ├──────────┬───────────┤
                    │ webapp   │  binary    │
                    └────┬─────┴─────┬─────┘
                         │           │
           ┌─────────────▼─┐   ┌────▼──────────────┐
           │raptor_webapp.py│   │ raptor_binary.py   │
           └───────┬───────┘   └───────┬────────────┘
                   │                   │
        ┌──────────▼──────────────────▼──────────┐
        │        PHASE 1: DISCOVERY               │
        │   packages/discovery/                    │
        │   ┌──────┐ ┌───────┐ ┌──────┐ ┌──────┐ │
        │   │Semgrep│ │CodeQL │ │Truffle│ │LLM   │ │
        │   │      │ │       │ │Hog   │ │Scan  │ │
        │   └──┬───┘ └──┬────┘ └──┬───┘ └──┬───┘ │
        │      └────┬────┴────┬───┘--──-───┘     │
        └───────────┼─────────┼────────────-─────┘
                    │         │
        ┌───────────▼─────────▼──────────────────┐
        │  (binary only) PHASE 2: FUZZING         │
        │  AFL++ instrument → fuzz → crash parse  │
        │  gdb + rr + valgrind                    │
        └───────────┬────────────────────────────┘
                    │
        ┌───────────▼────────────────────────────┐
        │        PHASE N: VALIDATION              │
        │   packages/validation/                   │
        │   Dedup → Extract code → LLM exploit    │
        │   + patch → (webapp) live test          │
        └───────────┬────────────────────────────┘
                    │
                    ▼
            merged_report.json
```

For detailed architecture documentation, see [`docs/ARCHITECTURE_GUIDE.md`](docs/ARCHITECTURE_GUIDE.md).


### Adding a New Discovery Tool

1. Write a `_run_<toolname>()` method in `packages/discovery/__init__.py`
2. Add it to the tool registry list in `DiscoveryOrchestrator.run()`
3. Add a toggle parameter to `run()` and the CLI argparse in `raptor_webapp.py` / `raptor_binary.py`
4. Add a toggle switch in `web_server.py` `INDEX_HTML`

### Adding a New Validation Step

1. Write a method or module-level function in `packages/validation/__init__.py`
2. Call it from `_enrich_finding()` at the appropriate point

---

## Credits

This tool was heavily inspired from the amazing RAPTOR tool on [Github](https://github.com/gadievron/raptor), build by Gadi Evron, Daniel Cuthbert, Thomas Dullien (Halvar Flake), Michael Bargury, John Cartwright.

---

## License

See [LICENSE](LICENSE) for details.
