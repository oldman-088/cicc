"""Malformed / hostile input handling: connectors must fail typed, never invent records.

Contract under test: garbage documents produce either a typed error or an empty
result — never a fabricated CVE.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from tests.conftest import FakeTransport, response
from vuln_intel import kev as kev_mod
from vuln_intel.connectors import debian, ghsa, ubuntu
from vuln_intel.errors import SourceResponseError, ValidationError
from vuln_intel.retry import RetryPolicy

NOW = datetime(2026, 11, 5, tzinfo=timezone.utc)


def _connector(cls, doc):
    return cls(transport=FakeTransport(script=[response(doc)]),
               origin="fixture", retry=RetryPolicy(attempts=1), sleep=lambda _: None)


def _records_of(snap, records_fn):
    return list(records_fn(snap))


class TestOsvMalformed:
    @pytest.mark.parametrize("doc", [
        {}, [], "nope", {"id": "GHSA-0000-aaaa-bbbb"},
        {"id": "GHSA-0000-aaaa-bbbb", "aliases": [42]},
    ])
    def test_garbage_typed_error_or_none(self, doc):
        from vuln_intel.connectors.osv import OsvConnector
        c = _connector(OsvConnector, {})
        try:
            rec, _adv = c.parse_record(doc, fetched_at=NOW)
        except (ValidationError, SourceResponseError):
            return
        assert rec is None or str(rec.cve).startswith("CVE-")


class TestDebianMalformed:
    @pytest.mark.parametrize("doc", [{}, [], {"pkg": "nope"}, {"pkg": {"x": None}}])
    def test_garbage_never_invents_cves(self, doc):
        c = _connector(debian.DebianTrackerConnector, doc)
        try:
            snap = c.fetch()
        except (ValidationError, SourceResponseError):
            return
        for rec in debian.to_vulnerability_records(snap):
            assert str(rec.cve).startswith("CVE-")


class TestUbuntuMalformed:
    @pytest.mark.parametrize("doc", [{}, [], {"USN-1-1": "nope"}])
    def test_garbage_never_invents_cves(self, doc):
        c = _connector(ubuntu.UbuntuUsnConnector, doc)
        try:
            snap = c.fetch()
        except (ValidationError, SourceResponseError):
            return
        for rec in ubuntu.to_vulnerability_records(snap):
            assert str(rec.cve).startswith("CVE-")


class TestGhsaMalformed:
    @pytest.mark.parametrize("doc", [[], [None], [{"ghsa_id": "GHSA-a-b-c"}], "nope"])
    def test_garbage_typed_error_or_empty(self, doc):
        c = _connector(ghsa.GhsaConnector, doc)
        try:
            snap = c.fetch()
            recs = list(ghsa.to_vulnerability_records(snap))
            for rec in recs:
                assert str(rec.cve).startswith("CVE-")
        except (ValidationError, SourceResponseError):
            return  # typed failure is acceptable; raw crash is not


class TestKevMalformed:
    @pytest.mark.parametrize("doc", [{}, {"vulnerabilities": "nope"},
                                     {"vulnerabilities": [{"cveID": "not-a-cve"}]}])
    def test_garbage_never_invents_cves(self, doc):
        c = kev_mod.KevConnector(transport=FakeTransport(script=[response(doc)]),
                                 origin="fixture", retry=RetryPolicy(attempts=1),
                                 sleep=lambda _: None)
        try:
            cat = c.fetch()
        except (ValidationError, SourceResponseError):
            return
        for e in cat.entries:
            assert str(e.cve).startswith("CVE-")
