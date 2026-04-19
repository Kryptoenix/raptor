# RAPTOR v2 — Implementation Plan

## Architecture Summary

```
RAPTOR v2
├── 2 Modes: Web App | Binary
├── 2 Phases: Discovery | Validation
├── Discovery Tools: TruffleHog + Semgrep + CodeQL + LLMScan (toggle each)
├── Strategy: Web-specific or Binary-specific LLM scanning
├── Validation: Dedup → Validate → Exploit PoC → Patch → Remediation
└── Web UI: Pipeline animation, toggleable tools, APP/PROXY/BUG URL inputs
```

## What Exists vs What's Needed

### Can Reuse (exists, needs adaptation)
- [x] web_server.py — Flask app, job system, ZIP extraction, results display
- [x] packages/llm_scan/ — LLM scanner (chunker, scanner, merger)
- [x] packages/llm_analysis/ — LLM client, providers, config
- [x] packages/codeql/ — CodeQL agent, build detector, database manager
- [x] packages/fuzzing/ — AFL++ runner, corpus, crash collector
- [x] packages/exploit_feasibility/ — mitigation analysis
- [x] packages/binary_analysis/ — crash analyser
- [x] core/ — logging, config, JSON, SARIF, reporting
- [x] engine/semgrep/ — rules, SARIF merge

### Needs New Implementation
- [ ] TruffleHog integration (new tool wrapper)
- [ ] README parser (read README before analysis for context)
- [ ] Internet documentation search (optional feature)
- [ ] Web validation tools: nmap, gobuster, sqlmap integration
- [ ] Proxy support for all HTTP requests
- [ ] Binary: valgrind integration
- [ ] Binary: gdb/rr crash parsing
- [ ] Binary: QEMU firmware emulation
- [ ] Binary: reverse engineering mode (binary-only, no source)
- [ ] Reflexive agent loop (retry on errors)
- [ ] Pipeline animation UI (GitHub Actions style)
- [ ] TruffleHog credential impact analysis
- [ ] New unified finding schema (vuln_code, surrounding_context fields)
- [ ] PDF report generation with new schema

### Needs Restructuring
- [ ] raptor.py — 2 modes instead of 5
- [ ] web_server.py INDEX_HTML — 2 mode cards with toggle sub-options
- [ ] Discovery phase — unified runner for both strategies
- [ ] Validation phase — unified dedup + validate + exploit + patch
- [ ] LLMScan prompts — web strategy vs binary strategy

## Implementation Order

### Phase 1: Core Restructure (this session)
1. New entry points: `raptor_webapp.py`, `raptor_binary.py`
2. Updated `raptor.py` dispatcher (2 modes)
3. New web UI with 2 modes + toggles + pipeline animation
4. Updated `web_server.py` job runner
5. Unified finding schema

### Phase 2: Discovery Pipeline
6. TruffleHog wrapper
7. README parser
8. Discovery orchestrator (runs selected tools in parallel)
9. Web strategy LLM prompt
10. Binary strategy LLM prompt
11. Reflexive agent loop (retry on error)

### Phase 3: Validation Pipeline
12. Unified deduplication (all tool outputs)
13. Per-finding validation loop
14. Exploit PoC generation
15. Patch generation
16. TruffleHog credential impact
17. New finding schema fields (vuln_code, surrounding_context)

### Phase 4: Web Validation
18. nmap integration
19. gobuster integration
20. sqlmap integration
21. Proxy support
22. APP URL testing

### Phase 5: Binary Validation
23. valgrind integration
24. gdb/rr crash parsing
25. QEMU firmware emulation
26. Reverse engineering mode
27. BUG TRACK URL parsing

### Phase 6: Polish
28. Pipeline animation UI
29. PDF report with new schema
30. Testing & integration
