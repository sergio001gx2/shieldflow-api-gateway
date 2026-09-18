"""
ShieldFlow — XSS Detection Patterns
======================================
Compiled regex patterns for detecting Cross-Site Scripting (XSS) attempts.
Covers reflected, stored, DOM-based, and polyglot XSS vectors.

References:
  - OWASP XSS Prevention Cheat Sheet
  - PortSwigger XSS cheat sheet
"""

from __future__ import annotations

import re
from typing import List, Pattern

# ── Individual pattern strings ─────────────────────────────────────────────────
_XSS_RAW_PATTERNS: List[str] = [
    # Classic <script> tags (with variations)
    r"<\s*script[\s>]",
    r"<\s*/\s*script\s*>",
    # Event handlers (onerror, onload, onclick, etc.)
    r"(?i)\bon\w+\s*=\s*['\"]?[^'\"]{0,200}['\"]?",
    # JavaScript protocol in href/src
    r"(?i)javascript\s*:",
    # Data URI with script content
    r"(?i)data\s*:\s*text/html",
    r"(?i)data\s*:\s*application/javascript",
    # VBScript protocol
    r"(?i)vbscript\s*:",
    # document.cookie / document.write access
    r"(?i)document\s*\.\s*(cookie|write|location|domain|referrer)",
    # window.location manipulation
    r"(?i)window\s*\.\s*(location|open|eval)",
    # eval() and Function() calls with dynamic content
    r"(?i)\beval\s*\(",
    r"(?i)\bFunction\s*\(",
    # innerHTML / outerHTML assignment
    r"(?i)(innerHTML|outerHTML)\s*=",
    # src attribute with javascript:
    r"(?i)(src|href|action)\s*=\s*['\"]?\s*javascript",
    # HTML entity encoding bypass: &#x...;
    r"&#x[0-9a-fA-F]+;",
    # Expression() in CSS (IE-specific)
    r"(?i)expression\s*\(",
    # SVG-based XSS
    r"<\s*svg[\s>].*?(onload|onerror)",
    # Template injection markers ({{ }}, ${})
    r"\$\{.*?\}|\{\{.*?\}\}",
    # alert / prompt / confirm commonly used in PoC
    r"(?i)\b(alert|prompt|confirm)\s*\(",
    # Base tag hijacking
    r"<\s*base\s+href",
    # Meta refresh redirect
    r"<\s*meta[^>]+http-equiv\s*=\s*['\"]?refresh",
]

# ── Combined compiled pattern ─────────────────────────────────────────────────
XSS_PATTERN: Pattern[str] = re.compile(
    "|".join(f"({p})" for p in _XSS_RAW_PATTERNS),
    flags=re.IGNORECASE | re.DOTALL,
)

# ── Individual compiled patterns ──────────────────────────────────────────────
XSS_COMPILED_PATTERNS: List[Pattern[str]] = [
    re.compile(p, flags=re.IGNORECASE | re.DOTALL) for p in _XSS_RAW_PATTERNS
]

# Human-readable labels for each pattern
XSS_PATTERN_LABELS: List[str] = [
    "Script tag open",
    "Script tag close",
    "Inline event handler",
    "JavaScript protocol",
    "Data URI (text/html)",
    "Data URI (application/js)",
    "VBScript protocol",
    "document.* access",
    "window.* manipulation",
    "eval() call",
    "Function() constructor",
    "innerHTML/outerHTML assignment",
    "javascript: in attribute",
    "HTML entity encoding bypass",
    "CSS expression()",
    "SVG onload/onerror",
    "Template injection ({{ }} / ${})",
    "alert/prompt/confirm PoC",
    "Base tag hijacking",
    "Meta refresh redirect",
]


def detect_xss(text: str) -> tuple[bool, str]:
    """
    Check if the given text contains XSS patterns.

    Returns:
        (detected: bool, label: str) — label is the matched pattern name.
    """
    for pattern, label in zip(XSS_COMPILED_PATTERNS, XSS_PATTERN_LABELS):
        if pattern.search(text):
            return True, label
    return False, ""
