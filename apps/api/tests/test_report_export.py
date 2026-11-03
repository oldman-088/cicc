import json
import pytest
from app import report_export


def test_control_and_unicode_are_escaped_and_roundtrip():
    text = report_export.render_text({'synthetic':'line\n\x1b[31m\u202eمؤشر', 'truncated':True})
    assert text.isascii() and '\x1b' not in text and '\u202e' not in text
    assert json.loads(text)['synthetic'] == 'line\n\x1b[31m\u202eمؤشر'


def test_export_size_limit_fails_closed(monkeypatch):
    monkeypatch.setattr(report_export, 'MAX_EXPORT_BYTES', 10)
    with pytest.raises(report_export.ReportTooLarge): report_export.render_text({'a':'x'*20})
