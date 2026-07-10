"""Sanitize scanner evidence for safe browser display (Phase 22).

Scanner output can contain control characters, terminal escapes, and very large
blobs. The frontend escapes HTML, but we additionally strip control/escape
characters and bound size/shape here so evidence is safe and readable in the UI
without the user having to inspect raw output. This never changes stored data —
it only shapes the display copy.
"""

from __future__ import annotations

import re
from typing import Any

# Strip C0/C1 control characters except tab (\t) and newline (\n); this removes
# ANSI/terminal escapes (the ESC \x1b) and other non-printables.
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")

MAX_STR = 4000
MAX_ITEMS = 50
MAX_KEY = 120


def _clean(text: str) -> str:
    return _CONTROL.sub("", text)[:MAX_STR]


def _value(value: Any) -> Any:
    if isinstance(value, str):
        return _clean(value)
    if isinstance(value, bool) or value is None or isinstance(value, int | float):
        return value
    if isinstance(value, list):
        return [_value(v) for v in value[:MAX_ITEMS]]
    if isinstance(value, dict):
        return {
            _clean(str(k))[:MAX_KEY]: _value(v)
            for k, v in list(value.items())[:MAX_ITEMS]
        }
    return _clean(str(value))


def sanitize_evidence(evidence: dict[str, Any] | None) -> dict[str, Any]:
    """Return a display-safe, size-bounded copy of an evidence mapping."""
    if not isinstance(evidence, dict):
        return {}
    out: dict[str, Any] = {}
    for i, (key, val) in enumerate(evidence.items()):
        if i >= MAX_ITEMS:
            break
        out[_clean(str(key))[:MAX_KEY]] = _value(val)
    return out
