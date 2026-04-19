"""
RAPTOR LLM Direct-Code Scanner (llmscan)

Walks a repository, chunks source files intelligently, sends each chunk
to an LLM with a security-focused system prompt, collects structured
findings, then merges and deduplicates them with Semgrep/CodeQL output.

Public API:
    from packages.llm_scan import LLMScanner, merge_findings
"""

from .scanner import LLMScanner
from .merger import merge_findings

__all__ = ["LLMScanner", "merge_findings"]
