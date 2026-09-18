"""
ShieldFlow — SQL Injection Detection Patterns
===============================================
Compiled regex patterns for detecting SQL Injection attempts.
Patterns cover UNION-based, blind, time-based, and error-based SQLi.

References:
  - OWASP SQL Injection Prevention Cheat Sheet
  - ModSecurity CRS SQL injection rules
"""

from __future__ import annotations

import re
from typing import List, Pattern

# ── Individual pattern strings ─────────────────────────────────────────────────
_SQLI_RAW_PATTERNS: List[str] = [
    # Classic UNION-based injection
    r"(?i)\bUNION\b.{0,30}\bSELECT\b",
    # OR/AND tautologies
    r"(?i)\b(OR|AND)\b\s+[\w'\"]+\s*=\s*[\w'\"]+",
    # Comment sequences used to truncate queries
    r"(--|#|\/\*|\*\/|;--)",
    # SQL keywords chained in suspicious context
    r"(?i)\b(DROP|DELETE|INSERT|UPDATE|ALTER|CREATE|TRUNCATE)\b.{0,20}\b(TABLE|DATABASE|FROM|INTO)\b",
    # Stacked queries
    r";\s*(SELECT|INSERT|UPDATE|DELETE|DROP|EXEC)",
    # Time-based blind injection functions
    r"(?i)\b(SLEEP|BENCHMARK|WAITFOR\s+DELAY|pg_sleep)\s*\(",
    # Error-based functions
    r"(?i)\b(EXTRACTVALUE|UPDATEXML|EXP|FLOOR)\s*\(",
    # Information schema probing
    r"(?i)(information_schema|sys\.tables|sysobjects|pg_catalog)",
    # Hex encoding bypass
    r"0x[0-9a-fA-F]{4,}",
    # String concatenation attacks
    r"(?i)(CHAR\s*\(|CONCAT\s*\(|GROUP_CONCAT\s*\()",
    # Boolean-based blind injection patterns
    r"(?i)\b(TRUE|FALSE)\b\s*(AND|OR)\s+[\d'\"]\s*=\s*[\d'\"]",
    # LOAD_FILE / INTO OUTFILE
    r"(?i)\b(LOAD_FILE|INTO\s+OUTFILE|INTO\s+DUMPFILE)\b",
    # EXEC / EXECUTE stored procedures
    r"(?i)\b(EXEC|EXECUTE|sp_|xp_)\w*\s*\(",
    # Subquery injection
    r"(?i)\bSELECT\b.+\bFROM\b.+\bWHERE\b",
    # HAVING clause injection
    r"(?i)\bHAVING\b\s+[\d'\"=]",
    # ORDER BY injection
    r"(?i)\bORDER\s+BY\s+\d+",
    # Null byte injection
    r"%00|\\x00",
    # SQLite-specific
    r"(?i)\bsqlite_master\b",
    # PostgreSQL-specific: pg_sleep / COPY
    r"(?i)\bCOPY\b.+\bFROM\b",
]

# ── Compile all patterns into a single combined regex ─────────────────────────
SQLI_PATTERN: Pattern[str] = re.compile(
    "|".join(f"({p})" for p in _SQLI_RAW_PATTERNS),
    flags=re.IGNORECASE | re.DOTALL,
)

# ── Individual compiled patterns (for granular reporting) ─────────────────────
SQLI_COMPILED_PATTERNS: List[Pattern[str]] = [
    re.compile(p, flags=re.IGNORECASE | re.DOTALL) for p in _SQLI_RAW_PATTERNS
]

# Human-readable labels aligned with the pattern list (for logging)
SQLI_PATTERN_LABELS: List[str] = [
    "UNION-based SQLi",
    "OR/AND tautology",
    "SQL comment sequence",
    "DDL statement injection",
    "Stacked query",
    "Time-based blind (SLEEP/BENCHMARK)",
    "Error-based function",
    "Information schema probe",
    "Hex-encoded payload",
    "String concatenation function",
    "Boolean-based blind",
    "File read/write (LOAD_FILE/OUTFILE)",
    "Stored procedure execution",
    "Subquery injection",
    "HAVING clause injection",
    "ORDER BY injection",
    "Null byte injection",
    "SQLite master table probe",
    "PostgreSQL COPY injection",
]


def detect_sqli(text: str) -> tuple[bool, str]:
    """
    Check if the given text contains SQL Injection patterns.

    Returns:
        (detected: bool, label: str) — label is the matched pattern name.
    """
    for pattern, label in zip(SQLI_COMPILED_PATTERNS, SQLI_PATTERN_LABELS):
        if pattern.search(text):
            return True, label
    return False, ""
