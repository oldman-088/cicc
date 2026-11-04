"""Adversarial and resource-exhaustion behaviour of the parsing surfaces.

Every value that reaches this subsystem is attacker-influenced: anyone can publish a
CVE record, an OSV advisory or an EPSS row, and anyone can put arbitrary bytes in a
vector string. The requirement is not that malformed input is rejected — it is that
it is rejected *as a domain error*, quickly, without a traceback escaping and
without unbounded work.

These tests are the executable form of two claims made in the docs:

1. external data can never raise anything other than a ``VulnIntelError``;
2. no input causes super-linear time or unbounded memory.
"""

from __future__ import annotations

import contextlib
import random
import time

import pytest

from vuln_intel.cvss import score_vector
from vuln_intel.cvss40 import score_vector_v4
from vuln_intel.errors import VulnIntelError
from vuln_intel.schema import CveId

#: Deliberately hostile alphabet: control characters, non-ASCII, quotes,
#: separators, a NUL byte. If any of these produce a non-domain exception, a
#: connector would propagate it into a batch and abort a collection run.
HOSTILE = "CVSS:/AVNLIAPUXH{}[]\x00é😀0123456789,.-_ \t\n'\"\\"


class TestParsersNeverLeakForeignExceptions:
    @pytest.mark.parametrize("fn", [score_vector_v4, score_vector], ids=["v4", "v3"])
    def test_random_vectors_raise_only_domain_errors(self, fn):
        # A seeded PRNG is required, not incidental: fuzzing that cannot be
        # replayed is not a regression test. No security property depends on it.
        rng = random.Random(1234)  # noqa: S311
        for _ in range(1500):
            candidate = "".join(
                rng.choice(HOSTILE) for _ in range(rng.randint(0, 90))
            )
            try:
                fn(candidate)
            except VulnIntelError:
                continue  # the contract
            except Exception as exc:  # pragma: no cover - this is the failure
                raise AssertionError(
                    f"{fn.__name__} leaked {type(exc).__name__} for {candidate!r}"
                ) from exc

    def test_cve_identifiers_reject_anything_without_leaking(self):
        rng = random.Random(99)  # noqa: S311 - deterministic fuzzing
        alphabet = "CVE-0123456789abc/\\..\x00 "
        for _ in range(800):
            candidate = "".join(
                rng.choice(alphabet) for _ in range(rng.randint(0, 40))
            )
            try:
                CveId.parse(candidate)
            except VulnIntelError:
                continue
            except Exception as exc:  # pragma: no cover
                raise AssertionError(
                    f"CveId.parse leaked {type(exc).__name__} for {candidate!r}"
                ) from exc


class TestNoResourceExhaustion:
    """A pathological input must not buy an attacker unbounded CPU or memory."""

    def _bounded(self, fn, budget_seconds: float = 1.0):
        started = time.perf_counter()
        # Rejection is the expected outcome; what is being measured is the cost.
        with contextlib.suppress(VulnIntelError):
            fn()
        elapsed = time.perf_counter() - started
        assert elapsed < budget_seconds, f"took {elapsed:.2f}s"

    def test_huge_v4_vector_is_bounded(self):
        self._bounded(lambda: score_vector_v4("CVSS:4.0/" + "A" * 500_000))

    def test_huge_v3_vector_is_bounded(self):
        self._bounded(lambda: score_vector("CVSS:3.1/" + "A" * 500_000))

    def test_repeated_metrics_do_not_go_quadratic(self):
        """Parsing must be linear in the number of metrics, not quadratic."""
        self._bounded(lambda: score_vector_v4("CVSS:4.0/" + "AV:N/" * 20_000))

    def test_megabyte_cve_identifier_is_bounded(self):
        self._bounded(lambda: CveId.parse("CVE-" + "1" * 500_000))

    def test_epss_many_rows_is_linear_enough(self):
        from vuln_intel.connectors.epss import parse_epss_response

        payload = {
            "status": "OK",
            "data": [
                {"cve": f"CVE-2026-{index:05d}", "epss": "0.5", "percentile": "0.5"}
                for index in range(5_000)
            ],
        }
        self._bounded(lambda: parse_epss_response(payload), budget_seconds=2.0)


class TestNonFiniteNumbersAreRejected:
    """``nan`` and ``inf`` slip past naive range checks in surprising ways."""

    @pytest.mark.parametrize("value", ["nan", "inf", "-inf", "NaN", "Infinity", "1e400"])
    def test_epss_rejects_non_finite_scores(self, value):
        from vuln_intel.connectors.epss import parse_epss_response

        payload = {
            "status": "OK",
            "data": [{"cve": "CVE-2026-0001", "epss": value, "percentile": "0.5"}],
        }
        with pytest.raises(VulnIntelError):
            parse_epss_response(payload)

    def test_booleans_are_not_numbers(self):
        """``True`` is an ``int`` in Python; accepting it as a probability is a bug."""
        from vuln_intel.connectors.epss import parse_epss_response

        payload = {
            "status": "OK",
            "data": [{"cve": "CVE-2026-0001", "epss": True, "percentile": "0.5"}],
        }
        with pytest.raises(VulnIntelError):
            parse_epss_response(payload)


class TestStructuralHostility:
    """Wrong shape at every level, not just wrong values."""

    @pytest.mark.parametrize(
        "payload",
        [
            None,
            [],
            "a string",
            0,
            {"data": None},
            {"data": [None]},
            {"data": [{}]},
            {"data": [{"cve": None, "epss": "0.5", "percentile": "0.5"}]},
            {"data": [{"cve": "CVE-2026-0001", "epss": "0.5"}]},
            {"status": "ERROR", "data": []},
        ],
    )
    def test_epss_payloads_fail_as_domain_errors(self, payload):
        from vuln_intel.connectors.epss import parse_epss_response

        with pytest.raises(VulnIntelError):
            parse_epss_response(payload)  # type: ignore[arg-type]

    def test_vector_with_embedded_nul_is_rejected(self):
        with pytest.raises(VulnIntelError):
            score_vector_v4("CVSS:4.0/AV:N\x00/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H")

    def test_vector_with_newline_injection_is_rejected(self):
        """Log injection: a newline in a stored vector forges a log line."""
        with pytest.raises(VulnIntelError):
            score_vector_v4("CVSS:4.0/AV:N\nFAKE LOG LINE/AC:L/AT:N/PR:N/UI:N")


class TestErrorMessagesAreSafeToLog:
    """Error text reaches operator logs, so it must not carry control characters."""

    def test_rejection_message_has_no_newlines(self):
        hostile = "CVSS:4.0/AV:N\n\r\t\x00"
        with pytest.raises(VulnIntelError) as caught:
            score_vector_v4(hostile)
        message = str(caught.value)
        for forbidden in ("\n", "\r", "\x00"):
            assert forbidden not in message, f"{forbidden!r} leaked into an error message"
