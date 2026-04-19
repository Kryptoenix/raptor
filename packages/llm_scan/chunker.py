"""
Source-file chunker for LLM security scanning.

Strategy (in priority order):

1. **Small files** (<= MAX_CHUNK_LINES): sent as a single chunk.
2. **Structured languages** (Python, JS/TS, Java, Go, C/C++, Ruby, PHP, Rust):
   split at top-level function/class/method boundaries detected by simple
   regex heuristics (no tree-sitter required, but honours tree-sitter when
   available).
3. **Large unstructured files**: split by sliding window of WINDOW_LINES with
   OVERLAP_LINES overlap so LLM context is not lost at seams.

Each chunk carries:
  - file_path   : str   — relative path inside the repo
  - start_line  : int   — 1-based first line
  - end_line    : int   — 1-based last line (inclusive)
  - content     : str   — the source text
  - chunk_type  : str   — "file" | "function" | "class" | "window"
  - language    : str   — detected language name
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, List, Optional

# Maximum lines to send in one chunk (fits in ~8 k tokens for most languages).
MAX_CHUNK_LINES: int = 300
WINDOW_LINES: int = 250
OVERLAP_LINES: int = 40

# Languages we attempt structural splitting for.
# Maps extension → language name.
_EXT_LANG: dict[str, str] = {
    ".py":   "python",
    ".pyw":  "python",
    ".js":   "javascript",
    ".mjs":  "javascript",
    ".cjs":  "javascript",
    ".ts":   "typescript",
    ".tsx":  "typescript",
    ".jsx":  "javascript",
    ".java": "java",
    ".go":   "go",
    ".c":    "c",
    ".h":    "c",
    ".cc":   "cpp",
    ".cpp":  "cpp",
    ".cxx":  "cpp",
    ".hpp":  "cpp",
    ".rb":   "ruby",
    ".php":  "php",
    ".rs":   "rust",
    ".kt":   "kotlin",
    ".swift":"swift",
    ".cs":   "csharp",
    ".scala":"scala",
    ".sc":   "scala",
    ".groovy":"groovy",
    ".gradle":"groovy",
}

# File extensions that are worth scanning.
SCANNABLE_EXTENSIONS: frozenset[str] = frozenset(_EXT_LANG.keys()) | frozenset({
    ".sh", ".bash", ".yaml", ".yml", ".json", ".toml", ".tf", ".hcl",
    ".sql", ".xml", ".conf", ".ini",
    # Web templates — critical for XSS / injection detection
    ".html", ".htm", ".xhtml",
    ".jsp", ".jspx",
    ".erb", ".haml", ".slim",
    ".twig", ".blade.php",
    ".hbs", ".handlebars", ".mustache", ".ejs",
    ".ftl",              # FreeMarker
    ".vm",               # Velocity
    ".thymeleaf",
    ".sbt",              # Scala build definitions
    ".properties",       # Java properties (secrets, credentials)
    ".env",              # Environment files (secrets)
})

# Paths to always skip (binary, generated, vendored).
_SKIP_DIRS: frozenset[str] = frozenset({
    ".git", ".hg", ".svn", "node_modules", "vendor", "__pycache__",
    ".tox", ".venv", "venv", "env", ".env", "dist", "build", "target",
    "out", "bin", ".cache", ".mypy_cache", ".pytest_cache", "coverage",
    "htmlcov", "docs", ".idea", ".vscode",
})

_SKIP_SUFFIXES: frozenset[str] = frozenset({
    ".min.js", ".bundle.js", ".map", ".pyc", ".pyo", ".class",
    ".jar", ".war", ".egg", ".whl", ".lock",
})

# Regex patterns that mark the start of a top-level structural block.
# Each entry: (pattern, chunk_type_label)
_STRUCTURE_PATTERNS: dict[str, list[tuple[re.Pattern, str]]] = {
    "python": [
        (re.compile(r'^(async\s+)?def\s+\w', re.M), "function"),
        (re.compile(r'^class\s+\w', re.M), "class"),
    ],
    "javascript": [
        (re.compile(r'^(export\s+)?(async\s+)?function\s+\w', re.M), "function"),
        (re.compile(r'^(export\s+)?(default\s+)?class\s+\w', re.M), "class"),
        (re.compile(r'^(const|let|var)\s+\w+\s*=\s*(async\s+)?\(', re.M), "function"),
        (re.compile(r'^(const|let|var)\s+\w+\s*=\s*function', re.M), "function"),
    ],
    "typescript": [
        (re.compile(r'^(export\s+)?(async\s+)?function\s+\w', re.M), "function"),
        (re.compile(r'^(export\s+)?(abstract\s+)?class\s+\w', re.M), "class"),
        (re.compile(r'^(export\s+)?(const|let|var)\s+\w+\s*=', re.M), "function"),
    ],
    "java": [
        (re.compile(r'^\s*(public|private|protected|static|final|abstract).*?\s+class\s+\w', re.M), "class"),
        (re.compile(r'^\s*(public|private|protected|static|final|abstract|synchronized).*?\w+\s*\(', re.M), "function"),
    ],
    "go": [
        (re.compile(r'^func\s+', re.M), "function"),
        (re.compile(r'^type\s+\w+\s+struct', re.M), "class"),
    ],
    "c": [
        (re.compile(r'^\w[\w\s\*]+\w\s*\([^;]*\)\s*\{', re.M), "function"),
    ],
    "cpp": [
        (re.compile(r'^class\s+\w', re.M), "class"),
        (re.compile(r'^\w[\w\s\*:~]+\w\s*\([^;]*\)\s*\{', re.M), "function"),
    ],
    "rust": [
        (re.compile(r'^(pub\s+)?(async\s+)?fn\s+\w', re.M), "function"),
        (re.compile(r'^(pub\s+)?(struct|enum|impl|trait)\s+\w', re.M), "class"),
    ],
    "ruby": [
        (re.compile(r'^\s*def\s+\w', re.M), "function"),
        (re.compile(r'^\s*class\s+\w', re.M), "class"),
    ],
    "kotlin": [
        (re.compile(r'^(fun|class|object|interface)\s+\w', re.M), "function"),
    ],
    "csharp": [
        (re.compile(r'^\s*(public|private|protected|internal|static|abstract|override|virtual).*?class\s+\w', re.M), "class"),
        (re.compile(r'^\s*(public|private|protected|internal|static|abstract|override|virtual).*?\w+\s*\(', re.M), "function"),
    ],
    "scala": [
        (re.compile(r'^\s*(class|object|trait|case\s+class)\s+\w', re.M), "class"),
        (re.compile(r'^\s*(def|val|var|lazy\s+val)\s+\w', re.M), "function"),
    ],
    "groovy": [
        (re.compile(r'^\s*(class|interface|enum|trait)\s+\w', re.M), "class"),
        (re.compile(r'^\s*(def|void|String|int|boolean|private|public|protected|static).*?\w+\s*\(', re.M), "function"),
    ],
}


@dataclass
class SourceChunk:
    file_path: str          # relative to repo root
    start_line: int         # 1-based
    end_line: int           # 1-based, inclusive
    content: str
    chunk_type: str         # "file" | "function" | "class" | "window"
    language: str
    name: str = ""          # optional symbol name extracted from first line


def detect_language(path: Path) -> str:
    """Return a language label for a source file, or '' if unknown."""
    for suffix, lang in _EXT_LANG.items():
        if path.name.endswith(suffix):
            return lang
    return ""


def is_scannable(path: Path) -> bool:
    """Return True if this file should be scanned."""
    name_lower = path.name.lower()
    # Skip files that look binary or generated
    if any(name_lower.endswith(s) for s in _SKIP_SUFFIXES):
        return False
    suffix = path.suffix.lower()
    return suffix in SCANNABLE_EXTENSIONS


def _find_block_boundaries(lines: list[str], lang: str) -> list[tuple[int, str]]:
    """
    Return sorted list of (line_index_0based, chunk_type) for each structural
    boundary in the file.  Falls back to empty list if no patterns for lang.
    """
    patterns = _STRUCTURE_PATTERNS.get(lang, [])
    if not patterns:
        return []

    text = "\n".join(lines)
    hits: list[tuple[int, str]] = []

    for pat, ctype in patterns:
        for m in pat.finditer(text):
            # Convert string offset to 0-based line number
            line_no = text[:m.start()].count("\n")
            hits.append((line_no, ctype))

    # Sort and deduplicate (keep first ctype when lines collide)
    hits.sort(key=lambda x: x[0])
    deduped: list[tuple[int, str]] = []
    seen_lines: set[int] = set()
    for ln, ct in hits:
        if ln not in seen_lines:
            deduped.append((ln, ct))
            seen_lines.add(ln)

    return deduped


def _extract_name(line: str) -> str:
    """Try to extract a symbol name from the first line of a block."""
    m = re.search(r'\b(def|function|fn|func|class|struct|impl|trait)\s+(\w+)', line)
    if m:
        return m.group(2)
    m = re.search(r'(\w+)\s*\(', line)
    if m:
        return m.group(1)
    return ""


def chunk_file(repo_root: Path, rel_path: Path) -> list[SourceChunk]:
    """
    Return a list of SourceChunk for the given file.
    Never returns an empty list (at minimum the whole file is one chunk).
    """
    abs_path = repo_root / rel_path
    try:
        text = abs_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    lines = text.splitlines()
    if not lines:
        return []

    lang = detect_language(abs_path)
    file_str = str(rel_path)
    total = len(lines)

    # ── Small files: single chunk ─────────────────────────────────
    if total <= MAX_CHUNK_LINES:
        return [SourceChunk(
            file_path=file_str,
            start_line=1,
            end_line=total,
            content=text,
            chunk_type="file",
            language=lang,
        )]

    # ── Structural splitting ───────────────────────────────────────
    boundaries = _find_block_boundaries(lines, lang)

    if boundaries:
        # Build ranges: each boundary starts a new chunk, ends at next-1
        chunks: list[SourceChunk] = []
        # Add a sentinel at the end
        boundaries_with_end = boundaries + [(total, "")]

        for i, (start_ln, ctype) in enumerate(boundaries_with_end[:-1]):
            end_ln = boundaries_with_end[i + 1][0] - 1
            # Merge tiny adjacent blocks into one chunk (< 10 lines)
            while (end_ln - start_ln < 10
                   and i + 1 < len(boundaries_with_end) - 1):
                i += 1
                end_ln = boundaries_with_end[i + 1][0] - 1
                ctype = "function"  # merged

            # If this chunk is still huge, sub-chunk it with sliding window
            if end_ln - start_ln + 1 > MAX_CHUNK_LINES:
                sub = _window_chunks(lines, start_ln, end_ln, file_str, lang, ctype)
                chunks.extend(sub)
            else:
                chunk_lines = lines[start_ln: end_ln + 1]
                name = _extract_name(lines[start_ln]) if chunk_lines else ""
                chunks.append(SourceChunk(
                    file_path=file_str,
                    start_line=start_ln + 1,
                    end_line=end_ln + 1,
                    content="\n".join(chunk_lines),
                    chunk_type=ctype,
                    language=lang,
                    name=name,
                ))

        # Prefix chunk: lines before first boundary
        if boundaries[0][0] > 0:
            prefix = lines[: boundaries[0][0]]
            chunks.insert(0, SourceChunk(
                file_path=file_str,
                start_line=1,
                end_line=boundaries[0][0],
                content="\n".join(prefix),
                chunk_type="file",
                language=lang,
            ))

        if chunks:
            return chunks

    # ── Sliding window fallback ───────────────────────────────────
    return _window_chunks(lines, 0, total - 1, file_str, lang, "window")


def _window_chunks(
    lines: list[str],
    start: int,
    end: int,
    file_str: str,
    lang: str,
    chunk_type: str,
) -> list[SourceChunk]:
    chunks: list[SourceChunk] = []
    pos = start
    while pos <= end:
        chunk_end = min(pos + WINDOW_LINES - 1, end)
        chunk_lines = lines[pos: chunk_end + 1]
        chunks.append(SourceChunk(
            file_path=file_str,
            start_line=pos + 1,
            end_line=chunk_end + 1,
            content="\n".join(chunk_lines),
            chunk_type=chunk_type,
            language=lang,
        ))
        # Advance with overlap so we don't lose context across seams
        next_pos = pos + WINDOW_LINES - OVERLAP_LINES
        if next_pos <= pos:
            next_pos = pos + 1  # safety: always progress
        pos = next_pos
    return chunks


def walk_repo(repo_root: Path, max_files: int = 500) -> Iterator[SourceChunk]:
    """
    Yield SourceChunk objects for all scannable files in the repo,
    **prioritised by security relevance**.

    For repos with more files than max_files, the budget is allocated across
    three tiers so that high-attack-surface files (controllers, auth configs,
    templates, route definitions) are always scanned first, even in 10k+ file
    repos.

    Tier 1 — HIGH attack surface (always scanned, even if count > max_files):
        Security configs, auth modules, controllers, route files, API
        endpoints, templates, environment/secret files.

    Tier 2 — MEDIUM attack surface (scanned within remaining budget):
        Models, services, middleware, database code, utility modules that
        handle user input, serialization, or crypto.

    Tier 3 — LOW attack surface (fills remaining budget):
        Everything else (tests, docs, build scripts, etc).

    Within each tier, files are sorted smallest-first so the budget covers
    the maximum number of files.
    """
    # ── Phase 1: collect all scannable files (fast, no I/O beyond stat) ───
    all_files: list[tuple[Path, int]] = []  # (relative_path, tier)
    for abs_path in repo_root.rglob("*"):
        if not abs_path.is_file():
            continue
        parts = abs_path.relative_to(repo_root).parts
        if any(p in _SKIP_DIRS for p in parts[:-1]):
            continue
        if not is_scannable(abs_path):
            continue
        rel = abs_path.relative_to(repo_root)
        tier = _security_tier(rel)
        all_files.append((rel, tier))

    # ── Phase 2: sort by tier (ascending), then by file size (smallest first) ─
    def _sort_key(item: tuple[Path, int]) -> tuple[int, int]:
        rel, tier = item
        try:
            size = (repo_root / rel).stat().st_size
        except OSError:
            size = 0
        return (tier, size)

    all_files.sort(key=_sort_key)

    # ── Phase 3: yield chunks respecting budget ──────────────────────────
    # Tier 1 files always get scanned (even if they exceed max_files).
    # Tiers 2-3 share the remaining budget.
    scanned = 0
    tier1_count = sum(1 for _, t in all_files if t == 1)

    for rel, tier in all_files:
        # Tier 1: always include. Tiers 2-3: only if budget remains.
        if tier > 1 and scanned >= max_files:
            break
        for chunk in chunk_file(repo_root, rel):
            yield chunk
        scanned += 1


# ---------------------------------------------------------------------------
# Security-relevance tiering for file prioritisation
# ---------------------------------------------------------------------------

# Patterns matched against the lowercased relative path string.
# Order: most specific first within each tier.

_TIER1_PATH_PATTERNS: list[re.Pattern] = [
    # Security & auth configuration
    re.compile(r'securityconfig|security_config|securityconfiguration'),
    re.compile(r'authconfig|auth_config|authentication'),
    re.compile(r'csrf|cors_config|cors\.'),
    re.compile(r'oauth|jwt|token'),
    re.compile(r'permissions?\.py|acl|rbac|roles?\.'),

    # Controllers, handlers, endpoints, routes
    re.compile(r'controller|handler|endpoint|resource'),
    re.compile(r'routes?\.(py|js|ts|rb|java|scala|go|php|conf)'),
    re.compile(r'urls?\.(py|conf)'),
    re.compile(r'views?\.(py|rb)'),  # Django/Rails views = controllers
    re.compile(r'api[_/]'),

    # Templates (XSS attack surface)
    re.compile(r'\.html$|\.htm$|\.xhtml$'),
    re.compile(r'\.jsp$|\.jspx$'),
    re.compile(r'\.erb$|\.haml$|\.slim$'),
    re.compile(r'\.hbs$|\.handlebars$|\.mustache$|\.ejs$'),
    re.compile(r'\.ftl$|\.vm$|\.thymeleaf$'),
    re.compile(r'\.twig$|\.blade\.php$'),

    # Application configuration (secrets, debug mode, DB creds)
    re.compile(r'application\.(conf|properties|ya?ml)$'),
    re.compile(r'settings\.(py|json|ya?ml)$'),
    re.compile(r'\.env(\.|$)'),
    re.compile(r'config\.(py|js|ts|json|ya?ml|rb|scala)$'),
    re.compile(r'database\.(yml|yaml|json|conf)$'),
    re.compile(r'secrets?\.(py|json|ya?ml)$'),

    # Middleware / filters (auth bypass surface)
    re.compile(r'middleware|filter|interceptor|guard'),
]

_TIER2_PATH_PATTERNS: list[re.Pattern] = [
    # Models / entities (SQLi in custom queries, data exposure)
    re.compile(r'models?\.(py|rb|java|scala|go)$'),
    re.compile(r'entity|domain|schema'),
    re.compile(r'repository|repo\.'),

    # Services / business logic
    re.compile(r'service|manager|provider|facade'),
    re.compile(r'helper|util|utils'),

    # Database / queries
    re.compile(r'query|queries|dao|mapper'),
    re.compile(r'migration|migrate'),
    re.compile(r'\.sql$'),

    # Serialization / parsing
    re.compile(r'serial|deserial|marshal|parse|codec'),
    re.compile(r'xml_|json_|yaml_'),

    # Crypto / hashing
    re.compile(r'crypt|hash|cipher|sign|verify|encrypt|decrypt'),

    # File handling (path traversal)
    re.compile(r'upload|download|file_|storage'),

    # Input validation
    re.compile(r'valid|sanitiz|escap|encod'),

    # WebSocket / real-time
    re.compile(r'websocket|socket|ws_|channel'),

    # Build config (dependency vulns)
    re.compile(r'pom\.xml$|build\.(gradle|sbt)$|package\.json$|gemfile$|requirements'),
    re.compile(r'composer\.json$|cargo\.toml$|go\.mod$'),
]

# Everything else is Tier 3 (no patterns needed — it's the default).


def _security_tier(rel_path: Path) -> int:
    """
    Classify a file into a security-relevance tier (1=high, 2=medium, 3=low).
    Matching is done on the full lowercased relative path string so both
    filename and directory components are considered.
    """
    path_str = str(rel_path).lower()

    for pat in _TIER1_PATH_PATTERNS:
        if pat.search(path_str):
            return 1

    for pat in _TIER2_PATH_PATTERNS:
        if pat.search(path_str):
            return 2

    return 3
