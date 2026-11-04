"""The offline demo is the reviewable artifact; it must stay synthetic-only."""

from __future__ import annotations

from vuln_intel import demo


def test_demo_runs_offline_and_reports_zero_network_requests() -> None:
    payload = demo.build()
    assert payload["network_requests"] == {"nvd": 1, "osv": 1}  # canned transports only
    assert "SYNTHETIC" in str(payload["notice"]).upper()


def test_demo_records_are_all_fixture_origin() -> None:
    payload = demo.build()
    assert payload["records"]
    assert {record["origin"] for record in payload["records"]} == {"fixture"}


def test_demo_ranking_is_explained_and_bounded() -> None:
    ranking = demo.build()["ranking"]
    assert ranking
    top = ranking[0]
    assert 0.0 <= top["score"] <= 100.0
    assert top["reasons"]
    assert any("not production intelligence" in w for w in top["warnings"])
