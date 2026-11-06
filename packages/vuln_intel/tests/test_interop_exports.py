

class TestRetractedAdvisoriesAreNotPresentedAsActionable:
    """A withdrawn CVE still has a version range, so it still matches.

    The match is not wrong: the range really does cover the installed version. What
    was wrong is that the standing never left `NormalizedVulnerability` — it reached
    the CTIS adapter (which calls a rejected record `false_positive`) and nothing else.
    The VEX, OpenVEX and SARIF adapters described the same record as
    `affected`/`exploitable`/`error`, so two exports of one record disagreed about
    whether the vulnerability was real.

    These pin the resolution: the standing travels with the match, every adapter states
    it, and the disagreement with CTIS is now explained rather than silent.
    """

    @staticmethod
    def _report(*, status=None, kev=None):
        from datetime import datetime, timezone

        from vuln_intel.assessment import workflow_for
        from vuln_intel.schema import (
            AffectedPackage,
            CveId,
            CvssScore,
            NormalizedVulnerability,
            Origin,
            Severity,
        )
        from vuln_intel.watchlist import Dependency, Inventory

        record = NormalizedVulnerability(
            cve=CveId.parse("CVE-2026-3001"),
            origin=Origin.FIXTURE,
            affected=(
                AffectedPackage(
                    ecosystem="npm", name="acme-router", introduced="0", fixed="2.4.1"
                ),
            ),
            cvss=(
                CvssScore(
                    version="3.1", base_score=9.8, severity=Severity.CRITICAL, vector="", source="nvd"
                ),
            ),
            kev=kev,
            record_status=status,
        )
        inventory = Inventory(dependencies=(Dependency(ecosystem="npm", name="acme-router", version="2.3.0"),))
        return workflow_for(
            records=[record],
            inventory=inventory,
            now=lambda: datetime(2026, 1, 1, tzinfo=timezone.utc),
        )

    def test_the_match_carries_the_standing(self):
        from vuln_intel.schema import RecordStatus

        report = self._report(status=RecordStatus.REJECTED)
        match = report.exposure.matches[0]
        assert match.record_status is RecordStatus.REJECTED
        assert match.retracted is True
        # The verdict is still AFFECTED: the range matches. Standing is not a verdict.
        assert match.assessment.verdict.value == "affected"

    def test_absent_standing_is_not_published(self):
        """"No source said anything" must not become "published"."""
        report = self._report(status=None)
        match = report.exposure.matches[0]
        assert match.record_status is None
        assert match.retracted is False
        assert match.as_dict()["record_status"] is None

    def test_vex_states_the_standing_and_lists_the_cve_as_retracted(self):
        from vuln_intel.interop.vex import to_vex
        from vuln_intel.schema import RecordStatus

        report = self._report(status=RecordStatus.REJECTED, kev=True)
        export = to_vex(report, generated_at=report.run_at)
        entry = export.document["vulnerabilities"][0]
        assert entry["analysis"]["detail"].find("advisory standing: rejected") != -1
        assert "CVE-2026-3001" in export.retracted
        # Still reported, never silently dropped: someone may be tracking it.
        assert entry["analysis"]["state"] in {"affected", "exploitable"}

    def test_openvex_states_the_standing_in_the_status_note(self):
        from vuln_intel.interop.openvex import to_openvex
        from vuln_intel.schema import RecordStatus

        report = self._report(status=RecordStatus.REJECTED)
        export = to_openvex(report, generated_at=report.run_at)
        note = export.document["statements"][0]["status_notes"]
        assert "advisory standing: rejected" in note

    def test_sarif_demotes_a_retracted_finding_and_labels_it(self):
        """`error` is what makes a scanner fail a build on a withdrawn claim."""
        from vuln_intel.interop.sarif import to_sarif
        from vuln_intel.schema import RecordStatus

        report = self._report(status=RecordStatus.REJECTED)
        result = to_sarif(report)["runs"][0]["results"][0]
        assert result["level"] == "warning", "a retracted claim must not gate a build"
        assert "advisory withdrawn" in result["message"]["text"]

    def test_a_published_finding_is_still_an_error(self):
        from vuln_intel.interop.sarif import to_sarif
        from vuln_intel.schema import RecordStatus

        report = self._report(status=RecordStatus.PUBLISHED)
        result = to_sarif(report)["runs"][0]["results"][0]
        assert result["level"] == "error"
        assert "advisory withdrawn" not in result["message"]["text"]

    def test_the_adapters_and_ctis_no_longer_say_opposite_things(self):
        """The whole point: one record, four exports, no unexplained contradiction.

        CTIS maps a rejected record to `false_positive` because that is its strongest
        "this is not a live finding" state. The other three keep the range verdict —
        which is still true — and now say *why* it must not be acted on. Before this,
        the VEX said `exploitable` and CTIS said `false_positive` with nothing in
        either document explaining the difference.
        """
        from vuln_intel.interop.ctis import to_ctis_finding, to_ctis_report
        from vuln_intel.interop.vex import to_vex
        from vuln_intel.schema import RecordStatus

        report = self._report(status=RecordStatus.REJECTED)
        vex_detail = to_vex(report, generated_at=report.run_at).document["vulnerabilities"][0][
            "analysis"
        ]["detail"]
        finding = to_ctis_finding(report.clusters[0].merged)
        payload = to_ctis_report([finding], generated_at=report.run_at)
        assert "rejected" in vex_detail
        assert "false_positive" in str(payload), "CTIS should still call it a false positive"


class TestCrossFormatConsistency:
    """One record, four exports. They must not contradict each other silently.

    The VEX/CTIS contradiction fixed earlier was found by reading the adapters, not by
    a test — the four adapters had four separate test suites and nothing compared them.
    These do not require the formats to *agree* (they cannot: CTIS has no VEX state,
    VEX has no false_positive), they require every disagreement to be one a consumer
    can see and explain.
    """

    @staticmethod
    def _record(*, status=None, kev=None, score=9.8):
        from vuln_intel.schema import (
            AffectedPackage,
            CveId,
            CvssScore,
            NormalizedVulnerability,
            Origin,
            Severity,
        )

        return NormalizedVulnerability(
            cve=CveId.parse("CVE-2026-4001"),
            origin=Origin.FIXTURE,
            summary="cross-format check",
            affected=(
                AffectedPackage(ecosystem="npm", name="acme-core", introduced="0", fixed="2.0.0"),
            ),
            cvss=(
                CvssScore(
                    version="3.1", base_score=score, severity=Severity.CRITICAL,
                    vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", source="nvd",
                ),
            ),
            kev=kev,
            record_status=status,
            references=tuple(
                __import__("vuln_intel.schema", fromlist=["Reference"]).Reference(
                    url=f"https://example.test/adv/{i}", kind="advisory"
                )
                for i in range(3)
            ),
        )

    @staticmethod
    def _report(record):
        from datetime import datetime, timezone

        from vuln_intel.assessment import workflow_for
        from vuln_intel.watchlist import Dependency, Inventory

        inventory = Inventory(
            dependencies=(Dependency(ecosystem="npm", name="acme-core", version="1.0.0"),)
        )
        return workflow_for(
            records=[record], inventory=inventory,
            now=lambda: datetime(2026, 1, 1, tzinfo=timezone.utc),
        )

    def _all_exports(self, record):
        from vuln_intel.interop.ctis import to_ctis_finding
        from vuln_intel.interop.openvex import to_openvex
        from vuln_intel.interop.sarif import to_sarif
        from vuln_intel.interop.vex import to_vex

        report = self._report(record)
        return report, {
            "vex": to_vex(report, generated_at=report.run_at),
            "openvex": to_openvex(report, generated_at=report.run_at),
            "sarif": to_sarif(report),
            "ctis": to_ctis_finding(record),
        }

    def test_every_export_names_the_same_cve(self):
        _report, exports = self._all_exports(self._record())
        vex_cves = {v["id"] for v in exports["vex"].document["vulnerabilities"]}
        openvex_cves = {s["vulnerability"]["name"] for s in exports["openvex"].document["statements"]}
        sarif_cves = {r["ruleId"] for r in exports["sarif"]["runs"][0]["results"]}
        ctis = exports["ctis"].finding
        assert vex_cves == openvex_cves == sarif_cves == {"CVE-2026-4001"}
        assert ctis["title"].startswith("CVE-2026-4001")

    def test_a_retracted_record_is_flagged_by_every_export_that_can_flag_it(self):
        from vuln_intel.schema import RecordStatus

        _, exports = self._all_exports(self._record(status=RecordStatus.REJECTED))
        detail = exports["vex"].document["vulnerabilities"][0]["analysis"]["detail"]
        assert "advisory standing: rejected" in detail
        assert "CVE-2026-4001" in exports["vex"].retracted
        assert "advisory standing: rejected" in (
            exports["openvex"].document["statements"][0]["status_notes"]
        )
        assert exports["sarif"]["runs"][0]["results"][0]["level"] == "warning"
        assert exports["ctis"].finding["status"] == "false_positive"

    def test_no_export_claims_not_affected_for_an_affected_record(self):
        """The one conversion that must never happen anywhere, in any format."""
        _, exports = self._all_exports(self._record())
        for vulnerability in exports["vex"].document["vulnerabilities"]:
            assert vulnerability.get("analysis", {}).get("state") != "not_affected"
        for statement in exports["openvex"].document["statements"]:
            assert statement["status"] != "not_affected"
        for result in exports["sarif"]["runs"][0]["results"]:
            assert result["level"] != "none"

    def test_standing_is_carried_across_the_whole_status_matrix(self):
        """Checked as a matrix so a new adapter cannot quietly opt out.

        Added after the fact: the four adapters had four test suites and no test
        compared them, which is how one record came to be `exploitable` in VEX and
        `false_positive` in CTIS with every suite green.
        """
        from vuln_intel.schema import RecordStatus

        for status in (None, RecordStatus.PUBLISHED, RecordStatus.DISPUTED, RecordStatus.REJECTED):
            report, exports = self._all_exports(self._record(status=status, kev=True))
            assert report.exposure.matches, f"no match for status={status}"
            match = report.exposure.matches[0]
            assert match.record_status is status
            # The verdict is never rewritten by standing.
            assert match.assessment.verdict.value == "affected"
            # ...and every format that can carry the standing, does.
            vex_detail = exports["vex"].document["vulnerabilities"][0]["analysis"]["detail"]
            if status is None:
                assert "advisory standing" not in vex_detail
            else:
                assert f"advisory standing: {status.value}" in vex_detail
