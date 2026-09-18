"""
ShieldFlow — Request Inspector
================================
Inspects all parts of an incoming HTTP request (query params, headers, body)
against SQLi and XSS rule sets. Returns a structured inspection result.
"""

from __future__ import annotations

import json
import urllib.parse
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from starlette.requests import Request

from app.rules.sqli_patterns import detect_sqli
from app.rules.xss_patterns import detect_xss


@dataclass
class ThreatMatch:
    """Represents a single detected threat within the request."""
    attack_type: str          # "sqli" or "xss"
    location: str             # Where the payload was found (header/query/body)
    field_name: str           # Specific field name (e.g., "q", "User-Agent")
    matched_pattern: str      # The pattern label that triggered the match
    payload_snippet: str      # Truncated snippet of the suspicious value


@dataclass
class InspectionResult:
    """Result of a full request inspection pass."""
    is_threat: bool = False
    threats: List[ThreatMatch] = field(default_factory=list)
    client_ip: str = "unknown"
    request_path: str = "/"
    request_method: str = "GET"

    @property
    def primary_attack_type(self) -> Optional[str]:
        """Return the first detected attack type, if any."""
        return self.threats[0].attack_type if self.threats else None

    @property
    def summary(self) -> str:
        if not self.threats:
            return "clean"
        labels = list({t.matched_pattern for t in self.threats})
        return ", ".join(labels[:3])


def _get_client_ip(request: Request) -> str:
    """Extract the real client IP, honoring X-Forwarded-For from reverse proxies."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "unknown"


def _check_value(
    value: str,
    location: str,
    field_name: str,
) -> List[ThreatMatch]:
    """
    Run both SQLi and XSS checks on a single string value.
    Returns a list of ThreatMatch objects (may be empty).
    """
    threats: List[ThreatMatch] = []
    snippet = value[:256]  # Limit snippet size for storage safety

    detected, label = detect_sqli(value)
    if detected:
        threats.append(
            ThreatMatch(
                attack_type="sqli",
                location=location,
                field_name=field_name,
                matched_pattern=label,
                payload_snippet=snippet,
            )
        )

    detected, label = detect_xss(value)
    if detected:
        threats.append(
            ThreatMatch(
                attack_type="xss",
                location=location,
                field_name=field_name,
                matched_pattern=label,
                payload_snippet=snippet,
            )
        )

    return threats


# ── Headers that should NOT be inspected (safe/structural headers) ────────────
_SKIP_HEADERS = frozenset(
    {
        "content-length",
        "content-type",
        "accept-encoding",
        "accept-language",
        "connection",
        "host",
        "pragma",
        "cache-control",
        "transfer-encoding",
    }
)


async def inspect_request(
    request: Request,
    body_bytes: Optional[bytes] = None,
) -> InspectionResult:
    """
    Full-spectrum request inspector.

    Inspects:
    1. URL query parameters
    2. Suspicious HTTP headers (User-Agent, Referer, custom headers)
    3. Request body (JSON, form-data, raw text)

    Args:
        request:    The incoming Starlette/FastAPI request object.
        body_bytes: Pre-read body bytes (pass to avoid double-reading the stream).

    Returns:
        InspectionResult with all detected threats.
    """
    all_threats: List[ThreatMatch] = []
    client_ip = _get_client_ip(request)

    # ── 1. Inspect query parameters ──────────────────────────────────────────
    for key, value in request.query_params.multi_items():
        # URL-decode before inspection to catch encoded payloads
        decoded_key = urllib.parse.unquote_plus(key)
        decoded_value = urllib.parse.unquote_plus(value)

        all_threats.extend(_check_value(decoded_key, "query_param", f"key:{decoded_key}"))
        all_threats.extend(_check_value(decoded_value, "query_param", key))

    # ── 2. Inspect headers ───────────────────────────────────────────────────
    for header_name, header_value in request.headers.items():
        if header_name.lower() in _SKIP_HEADERS:
            continue
        all_threats.extend(_check_value(header_value, "header", header_name))

    # ── 3. Inspect request body ──────────────────────────────────────────────
    if body_bytes:
        raw_body = body_bytes.decode("utf-8", errors="replace")

        # Try JSON parsing for field-level inspection
        content_type = request.headers.get("content-type", "")
        if "application/json" in content_type:
            try:
                body_data = json.loads(raw_body)
                _inspect_dict(body_data, all_threats, "body_json")
            except (json.JSONDecodeError, ValueError):
                # Fall back to raw body inspection
                all_threats.extend(_check_value(raw_body, "body_raw", "raw"))
        elif "application/x-www-form-urlencoded" in content_type:
            # Parse form-encoded body
            form_data = urllib.parse.parse_qs(raw_body, keep_blank_values=True)
            for key, values in form_data.items():
                for val in values:
                    all_threats.extend(_check_value(val, "body_form", key))
        else:
            # Raw body scan (multipart text parts, plain text, etc.)
            all_threats.extend(_check_value(raw_body, "body_raw", "raw"))

    return InspectionResult(
        is_threat=len(all_threats) > 0,
        threats=all_threats,
        client_ip=client_ip,
        request_path=request.url.path,
        request_method=request.method,
    )


def _inspect_dict(
    data: object,
    threats: List[ThreatMatch],
    location: str,
    parent_key: str = "",
) -> None:
    """
    Recursively traverse a parsed JSON object and inspect all string values.
    """
    if isinstance(data, dict):
        for k, v in data.items():
            full_key = f"{parent_key}.{k}" if parent_key else k
            _inspect_dict(v, threats, location, full_key)
    elif isinstance(data, list):
        for idx, item in enumerate(data):
            _inspect_dict(item, threats, location, f"{parent_key}[{idx}]")
    elif isinstance(data, str):
        threats.extend(_check_value(data, location, parent_key))
