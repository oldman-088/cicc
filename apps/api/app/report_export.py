"""Bounded ASCII text export of an already authorized investigation report.

The serialized report is JSON-shaped text, not HTML or an evidentiary document.
JSON escaping prevents raw control and bidi characters in the exported bytes.
The caller owns authorization, transaction, audit, and report collection bounds.
"""
import json

MAX_EXPORT_BYTES = 4 * 1024 * 1024


class ReportTooLarge(ValueError):
    pass


def render_text(report: dict) -> str:
    encoder = json.JSONEncoder(ensure_ascii=True, indent=2, allow_nan=False)
    parts = []
    size = 0
    for part in encoder.iterencode(report):
        # ensure_ascii means characters and UTF-8 bytes have identical lengths.
        size += len(part)
        if size > MAX_EXPORT_BYTES:
            raise ReportTooLarge('Report export exceeds size limit')
        parts.append(part)
    return ''.join(parts)
