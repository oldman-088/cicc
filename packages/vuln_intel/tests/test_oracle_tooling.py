"""Tests for the oracle tooling itself.

The differential checks are only credible if the machinery around them is honest. This
file tests that machinery: that a missing oracle is reported as missing rather than
silently skipped, that version extraction works on real banner formats, and that the
status banner names every oracle either way.

Why this matters: the failure mode being guarded against is a *green build* in which a
cross-check never ran. A green build is not evidence; the banner is.
"""

from __future__ import annotations

import subprocess
import sys

import pytest

from tests import oracle_tools


class TestVersionExtraction:
    @pytest.mark.parametrize(
        ("banner", "expected"),
        [
            ("RPM version 4.19.1.1", "4.19.1.1"),
            ("Debian 'dpkg' package management program version 1.21.23 (amd64).", "1.21.23"),
            ("Python 3.12.1", "3.12.1"),
            ("dpkg 1.19", "1.19"),
        ],
    )
    def test_extracts_a_dotted_version(self, banner, expected):
        assert oracle_tools._extract_version(banner) == expected

    def test_falls_back_to_the_whole_line(self):
        # Worse than a number, better than nothing: the banner still records what the
        # tool said, so a reader can tell the probe ran.
        assert oracle_tools._extract_version("no version here") == "no version here"


class TestProbes:
    def test_every_known_oracle_is_probed(self):
        names = {probe.name for probe in oracle_tools.probes()}
        assert names == {
            "packaging",
            "semantic_version",
            "rpm-vercmp",
            "dpkg",
            "rpm",
        }

    def test_an_unavailable_oracle_explains_itself_and_says_how_to_fix_it(self):
        for probe in oracle_tools.probes():
            if probe.available:
                assert probe.reason is None
                continue
            assert probe.reason, f"{probe.name} is unavailable but gives no reason"
            assert probe.install, f"{probe.name} is unavailable but says not how to install"

    def test_require_skips_with_an_actionable_message(self):
        """A missing oracle must produce a skip that names it and says it did not run."""
        missing = [probe for probe in oracle_tools.probes() if not probe.available]
        if not missing:
            pytest.skip("every oracle is available in this environment")
        with pytest.raises(pytest.skip.Exception) as caught:
            oracle_tools.require(missing[0].name)
        message = str(caught.value)
        assert missing[0].name in message
        assert "did NOT run" in message


class TestReportIsHonest:
    def test_banner_names_every_oracle_and_states_the_caveat(self):
        text = oracle_tools.report()
        for probe in oracle_tools.probes():
            assert probe.name in text, f"{probe.name} is missing from the banner"
        assert "NOT evidence of correctness" in text

    def test_banner_distinguishes_ran_from_skipped(self):
        text = oracle_tools.report()
        ran = sum(1 for probe in oracle_tools.probes() if probe.available)
        skipped = len(oracle_tools.probes()) - ran
        assert f"{ran} oracle(s) available, {skipped} unavailable" in text
        # Each line is explicitly tagged, never left to the reader to infer.
        assert text.count("[RUNS ]") == ran
        assert text.count("[SKIP ]") == skipped

    def test_cli_exit_code_reflects_missing_oracles(self):
        """``python -m tests.oracle_tools`` must not exit 0 when a check cannot run."""
        completed = subprocess.run(
            [sys.executable, "-m", "tests.oracle_tools"],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        expected = 0 if all(p.available for p in oracle_tools.probes()) else 1
        assert completed.returncode == expected
        assert "ORACLE STATUS" in completed.stdout


class TestExpectedVersionsAreDocumented:
    def test_every_oracle_has_a_documented_expectation(self):
        for probe in oracle_tools.probes():
            assert probe.name in oracle_tools.EXPECTED_VERSIONS, (
                f"{probe.name} has no entry in EXPECTED_VERSIONS; the documented "
                "cross-check results must name the version they were produced with"
            )

    def test_present_oracles_match_the_documented_version(self):
        """Version drift is a signal to re-run the audit and update the numbers.

        Not a hard failure for tools that are distribution-provided (``rpm``), whose
        version legitimately varies; ``None`` in EXPECTED_VERSIONS means "recorded but
        not pinned".
        """
        drift = []
        for probe in oracle_tools.probes():
            expected = oracle_tools.EXPECTED_VERSIONS.get(probe.name)
            if not probe.available or expected is None or probe.version is None:
                continue
            if probe.version != expected:
                drift.append((probe.name, expected, probe.version))
        assert not drift, (
            "oracle version drift — re-run the audit and update "
            f"ORACLE_VALIDATION.md: {drift}"
        )
