"""Mermaid label sanitizer — shared across all diagram renderers."""

# Default max length for a single line within a node label.
# Individual renderers can pass a different value or None to disable.
DEFAULT_MAX_LEN = 80


def sanitize(text: str, max_len: int = None) -> str:
    """Escape characters that break Mermaid node labels.

    Args:
        text: Raw label text.
        max_len: Truncate to this length with '...' suffix.
                 Pass None to disable truncation (default).
    """
    result = (
        str(text)
        .replace('"', "'")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("{", "(")
        .replace("}", ")")
        .replace("\n", " ")
    )
    if max_len and len(result) > max_len:
        result = result[:max_len - 3] + "..."
    return result
