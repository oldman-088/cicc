"""
Tests for apps.threat_intelligence.live_source_readiness.

Every test here uses an INJECTED FAKE TRANSPORT. No test in this file - or anywhere in the normal
suite - can reach the network, because the package holds no network client of its own.
"""

import json
import pytest
from datetime import datetime, timedelta, timezone

from apps.threat_intelligence.live_source_readiness import (
    DEFAULT_MAX_RESPONSE_BYTES,
    DEFAULT_TIMEOUT_SECONDS,
    LIVE_OPT_IN_ENV,
    FetchedPayload,
    FetchPlan,
    LiveAccessRefusedError,
    LiveSourceError,
    LiveSourceGate,
    LiveSourcePolicy,
    LiveSourceReadinessService,
    PayloadStatus,
    ProvenanceStampedRecord,
    SourceSchema,
)

TENANT = "t-live"
T0 = datetime(2026, 11, 5, 12, 0, 0, tzinfo=timezone.utc)

KEV_BODY = json.dumps(
    {
        "title": "CISA KEV (fixture)",
        "vulnerabilities": [
            {
                "cveID": "CVE-2024-0001",
                "vendorProject": "Example Vendor",
                "product": "Example Product",
                "requiredAction": "Apply updates per vendor instructions.",
            }
        ],
    }
).encode("utf-8")


def _kev_transport(body: bytes = KEV_BODY, status: int = 200, content_type: str = "application/json"):
    def transport(method, url, timeout, max_bytes):
        return (status, content_type, body)

    return transport


def _policy(**kw) -> LiveSourcePolicy:
    base = dict(
        source_id="cisa-kev",
        url="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        payload_schema=SourceSchema(
            required_top_level_keys=["vulnerabilities"],
            records_path="vulnerabilities",
            required_record_keys=["cveID", "vendorProject", "product"],
            min_records=1,
        ),
        rate_limit_documented=True,
        rate_limit_note="no published limit; 60s floor self-imposed",
        license_terms="US Government work, public domain",
    )
    base.update(kw)
    return LiveSourcePolicy(**base)


def _service(**kw) -> LiveSourceReadinessService:
    svc = LiveSourceReadinessService(tenant_id=TENANT, **kw)
    svc.register_policy(_policy())
    return svc


# ------------------------------------------------------------------- policy


def test_tenant_id_is_required():
    with pytest.raises(LiveSourceError):
        LiveSourceReadinessService(tenant_id="  ")


def test_policy_requires_https_with_no_whitespace():
    for bad in ("http://example.invalid/x", "ftp://example.invalid/x", "not a url",
                "https://example.invalid/a b"):
        with pytest.raises(Exception):
            _policy(url=bad)
    assert _policy(url="https://example.invalid/ok").url == "https://example.invalid/ok"


def test_policy_bounds_timeout_size_and_retries():
    with pytest.raises(Exception):
        _policy(timeout_seconds=0)
    with pytest.raises(Exception):
        _policy(timeout_seconds=10_000)
    with pytest.raises(Exception):
        _policy(max_response_bytes=0)
    with pytest.raises(Exception):
        _policy(max_retries=99)
    assert _policy().timeout_seconds == DEFAULT_TIMEOUT_SECONDS
    assert _policy().max_response_bytes == DEFAULT_MAX_RESPONSE_BYTES


def test_credential_ref_must_be_a_name_not_a_value():
    assert _policy(credential_ref="CISA_KEV_TOKEN").credential_ref == "CISA_KEV_TOKEN"
    with pytest.raises(Exception):
        _policy(credential_ref="api_key=sk-abc123def456")
    with pytest.raises(Exception):
        _policy(credential_ref="Bearer abc def")
    with pytest.raises(Exception):
        _policy(credential_ref="x" * 200)


def test_duplicate_policy_registration_is_rejected():
    svc = LiveSourceReadinessService(tenant_id=TENANT)
    svc.register_policy(_policy())
    with pytest.raises(LiveSourceError):
        svc.register_policy(_policy())


def test_retrying_policy_must_declare_a_rate_floor():
    """A retry loop with no interval floor would hammer a rate-limited source."""
    svc = LiveSourceReadinessService(tenant_id=TENANT)
    with pytest.raises(LiveSourceError):
        svc.register_policy(_policy(min_interval_seconds=0, max_retries=2))
    assert svc.register_policy(_policy(min_interval_seconds=0, max_retries=0)) is not None


def test_method_is_normalised_to_upper_case():
    assert _policy(method=" post ").method == "POST"


# ---------------------------------------------------------- the opt-in gate


def test_gate_is_closed_by_default():
    gate = LiveSourceGate(env={})
    assert gate.opt_in_present is False
    assert gate.check(allow_live=True) == (False, f"environment opt-in {LIVE_OPT_IN_ENV} is not set")


def test_gate_requires_the_caller_flag_even_with_opt_in():
    gate = LiveSourceGate(env={LIVE_OPT_IN_ENV: "1"})
    assert gate.opt_in_present is True
    permitted, reason = gate.check(allow_live=False)
    assert permitted is False
    assert "allow_live" in reason


def test_gate_opens_only_when_both_conditions_hold():
    gate = LiveSourceGate(env={LIVE_OPT_IN_ENV: "true"})
    assert gate.check(allow_live=True) == (True, None)


def test_gate_recognises_only_explicit_truthy_values():
    for value in ("0", "false", "no", "", "  ", "maybe"):
        assert LiveSourceGate(env={LIVE_OPT_IN_ENV: value}).opt_in_present is False
    for value in ("1", "true", "TRUE", "yes"):
        assert LiveSourceGate(env={LIVE_OPT_IN_ENV: value}).opt_in_present is True


def test_fetch_without_a_transport_is_refused_not_silently_skipped():
    svc = _service()
    with pytest.raises(LiveAccessRefusedError):
        svc.fetch("cisa-kev", allow_live=True, now=T0)


def test_fetch_without_the_env_opt_in_is_refused():
    svc = _service(transport=_kev_transport(), gate=LiveSourceGate(env={}))
    with pytest.raises(LiveAccessRefusedError) as exc:
        svc.fetch("cisa-kev", allow_live=True, now=T0)
    assert LIVE_OPT_IN_ENV in str(exc.value)


def test_fetch_without_allow_live_is_refused():
    svc = _service(transport=_kev_transport(), gate=LiveSourceGate(env={LIVE_OPT_IN_ENV: "1"}))
    with pytest.raises(LiveAccessRefusedError):
        svc.fetch("cisa-kev", allow_live=False, now=T0)


def test_fetch_on_an_unknown_source_is_rejected():
    svc = _service(transport=_kev_transport(), gate=LiveSourceGate(env={LIVE_OPT_IN_ENV: "1"}))
    with pytest.raises(LiveSourceError):
        svc.fetch("no-such-source", allow_live=True, now=T0)


# ------------------------------------------------------------------- plans


def test_plan_performs_no_io_and_reports_permission():
    svc = _service()
    plan = svc.plan("cisa-kev")
    assert isinstance(plan, FetchPlan)
    assert plan.live_permitted is False
    assert plan.reason_if_not_permitted is not None
    assert plan.url.startswith("https://")
    assert plan.max_retries == 2
    assert plan.rate_limit_documented is True
    assert plan.has_credential_ref is False


def test_plan_reflects_the_gate_state():
    svc = _service(gate=LiveSourceGate(env={LIVE_OPT_IN_ENV: "1"}))
    assert svc.plan("cisa-kev", allow_live=True).live_permitted is True
    assert svc.plan("cisa-kev", allow_live=False).live_permitted is False


def test_readiness_report_names_actual_blockers():
    svc = _service()
    report = svc.readiness_report()
    assert report["source_count"] == 1
    assert report["ready_for_live_count"] == 0
    blockers = report["sources"][0]["blockers"]
    assert any("allow_live" in b for b in blockers)
    assert report["transport_available"] is False
    assert "no live request has been made" in report["note"]


def test_readiness_report_is_positive_only_when_evidence_exists():
    svc = _service(
        transport=_kev_transport(), gate=LiveSourceGate(env={LIVE_OPT_IN_ENV: "1"})
    )
    report = svc.readiness_report(allow_live=True)
    assert report["ready_for_live_count"] == 1
    assert report["sources"][0]["blockers"] == []


def test_undocumented_rate_limit_is_a_blocker():
    svc = LiveSourceReadinessService(tenant_id=TENANT)
    svc.register_policy(_policy(rate_limit_documented=False))
    report = svc.readiness_report()
    assert any("rate limit not documented" in b for b in report["sources"][0]["blockers"])


def test_missing_licence_terms_is_a_blocker():
    svc = LiveSourceReadinessService(tenant_id=TENANT)
    svc.register_policy(_policy(license_terms=None))
    report = svc.readiness_report()
    assert any("licence terms not recorded" in b for b in report["sources"][0]["blockers"])


# --------------------------------------------------------------- validation


def test_valid_payload_is_accepted_with_a_content_hash():
    svc = _service()
    payload = svc.validate_payload(_policy(), "application/json", KEV_BODY, now=T0)
    assert payload.status is PayloadStatus.ACCEPTED
    assert payload.record_count == 1
    assert payload.records[0]["cveID"] == "CVE-2024-0001"
    assert payload.content_hash is not None and len(payload.content_hash) == 64
    assert payload.body_bytes == len(KEV_BODY)


def test_missing_top_level_key_is_rejected():
    svc = _service()
    payload = svc.validate_payload(_policy(), "application/json", b'{"other": 1}', now=T0)
    assert payload.status is PayloadStatus.REJECTED_SCHEMA
    assert "vulnerabilities" in payload.detail


def test_missing_record_key_is_rejected():
    svc = _service()
    body = json.dumps({"vulnerabilities": [{"cveID": "CVE-2024-0002"}]}).encode()
    payload = svc.validate_payload(_policy(), "application/json", body, now=T0)
    assert payload.status is PayloadStatus.REJECTED_SCHEMA
    assert "missing keys" in payload.detail


def test_absent_records_path_is_rejected():
    svc = _service()
    # No required top-level keys here, so the failure is attributable to records_path itself.
    policy = _policy(payload_schema=SourceSchema(records_path="a.b"))
    payload = svc.validate_payload(policy, "application/json", b'{"a": {"c": []}}', now=T0)
    assert payload.status is PayloadStatus.REJECTED_SCHEMA
    assert "records_path" in payload.detail


def test_nested_records_path_is_followed():
    svc = _service()
    policy = _policy(payload_schema=SourceSchema(records_path="feed.items"))
    body = json.dumps({"feed": {"items": [{"x": 1}, {"x": 2}]}}).encode()
    payload = svc.validate_payload(policy, "application/json", body, now=T0)
    assert payload.status is PayloadStatus.ACCEPTED
    assert payload.record_count == 2


def test_records_must_be_a_list():
    svc = _service()
    body = json.dumps({"vulnerabilities": "not-a-list"}).encode()
    payload = svc.validate_payload(_policy(), "application/json", body, now=T0)
    assert payload.status is PayloadStatus.REJECTED_SCHEMA


def test_min_records_is_enforced():
    svc = _service()
    body = json.dumps({"vulnerabilities": []}).encode()
    payload = svc.validate_payload(_policy(), "application/json", body, now=T0)
    assert payload.status is PayloadStatus.REJECTED_SCHEMA
    assert payload.record_count == 0
    assert "min_records" in payload.detail


def test_max_records_is_enforced():
    svc = _service()
    policy = _policy(payload_schema=SourceSchema(records_path="vulnerabilities", max_records=2))
    body = json.dumps({"vulnerabilities": [{"v": i} for i in range(5)]}).encode()
    payload = svc.validate_payload(policy, "application/json", body, now=T0)
    assert payload.status is PayloadStatus.REJECTED_SIZE
    assert payload.record_count == 5


def test_wrong_content_type_is_rejected():
    svc = _service()
    payload = svc.validate_payload(_policy(), "text/html", KEV_BODY, now=T0)
    assert payload.status is PayloadStatus.REJECTED_CONTENT_TYPE
    assert "application/json" in payload.detail


def test_content_type_parameters_are_ignored_when_matching():
    svc = _service()
    payload = svc.validate_payload(
        _policy(), "application/json; charset=utf-8", KEV_BODY, now=T0
    )
    assert payload.status is PayloadStatus.ACCEPTED


def test_empty_body_is_rejected():
    svc = _service()
    payload = svc.validate_payload(_policy(), "application/json", b"", now=T0)
    assert payload.status is PayloadStatus.REJECTED_EMPTY


def test_oversized_body_is_rejected_before_parsing():
    svc = _service()
    policy = _policy(max_response_bytes=64)
    payload = svc.validate_payload(policy, "application/json", KEV_BODY, now=T0)
    assert payload.status is PayloadStatus.REJECTED_SIZE
    assert "max_response_bytes" in payload.detail


def test_invalid_json_is_rejected_without_raising():
    svc = _service()
    payload = svc.validate_payload(_policy(), "application/json", b"{not json", now=T0)
    assert payload.status is PayloadStatus.REJECTED_SCHEMA
    assert "not valid UTF-8 JSON" in payload.detail


def test_invalid_utf8_is_rejected_without_raising():
    svc = _service()
    payload = svc.validate_payload(_policy(), "application/json", b"\xff\xfe\x00\x01", now=T0)
    assert payload.status is PayloadStatus.REJECTED_SCHEMA


def test_rejection_never_corrupts_previously_accepted_data():
    svc = _service(transport=_kev_transport(), gate=LiveSourceGate(env={LIVE_OPT_IN_ENV: "1"}))
    good = svc.fetch("cisa-kev", allow_live=True, now=T0)
    assert good.status is PayloadStatus.ACCEPTED
    # A later bad response must not replace the good one.
    bad = svc.validate_payload(_policy(), "application/json", b"{}", now=T0 + timedelta(minutes=5))
    assert bad.status is PayloadStatus.REJECTED_SCHEMA
    assert svc.history("cisa-kev")[-1].status is PayloadStatus.ACCEPTED
    assert bad.records == []


# ---------------------------------------------------------------- provenance


def test_records_are_stamped_with_retrieval_provenance():
    svc = _service()
    policy = _policy()
    payload = svc.validate_payload(policy, "application/json", KEV_BODY, now=T0)
    stamped = svc.stamp_records(policy, payload)
    assert len(stamped) == 1
    record = stamped[0]
    assert isinstance(record, ProvenanceStampedRecord)
    assert record.source_id == "cisa-kev"
    assert record.source_url == policy.url
    assert record.retrieved_at == T0
    assert record.content_hash == payload.content_hash
    assert record.experimental_label == "EXPERIMENTAL_DEMO_DATA_ONLY"


def test_stamped_records_default_to_fixture_not_live_verification():
    svc = _service()
    policy = _policy()
    payload = svc.validate_payload(policy, "application/json", KEV_BODY, now=T0)
    assert svc.stamp_records(policy, payload)[0].verification_mode.value == "fixture_tested"


def test_stamping_a_rejected_payload_is_refused():
    svc = _service()
    policy = _policy()
    payload = svc.validate_payload(policy, "application/json", b"{}", now=T0)
    with pytest.raises(LiveSourceError):
        svc.stamp_records(policy, payload)


# -------------------------------------------------------------------- fetch


def test_fetch_accepts_a_well_formed_response():
    svc = _service(transport=_kev_transport(), gate=LiveSourceGate(env={LIVE_OPT_IN_ENV: "1"}))
    payload = svc.fetch("cisa-kev", allow_live=True, now=T0)
    assert payload.status is PayloadStatus.ACCEPTED
    assert payload.record_count == 1
    assert payload.attempts == 1
    assert svc.history("cisa-kev")[-1] is payload


def test_rate_limit_floor_is_enforced_between_fetches():
    svc = _service(transport=_kev_transport(), gate=LiveSourceGate(env={LIVE_OPT_IN_ENV: "1"}))
    assert svc.fetch("cisa-kev", allow_live=True, now=T0).status is PayloadStatus.ACCEPTED
    with pytest.raises(LiveSourceError) as exc:
        svc.fetch("cisa-kev", allow_live=True, now=T0 + timedelta(seconds=30))
    assert "rate limit floor" in str(exc.value)
    later = svc.fetch("cisa-kev", allow_live=True, now=T0 + timedelta(minutes=2))
    assert later.status is PayloadStatus.ACCEPTED


def test_zero_interval_policy_allows_back_to_back_fetches():
    svc = LiveSourceReadinessService(
        tenant_id=TENANT, transport=_kev_transport(), gate=LiveSourceGate(env={LIVE_OPT_IN_ENV: "1"})
    )
    svc.register_policy(_policy(min_interval_seconds=0, max_retries=0))
    assert svc.fetch("cisa-kev", allow_live=True, now=T0).status is PayloadStatus.ACCEPTED
    assert svc.fetch("cisa-kev", allow_live=True, now=T0).status is PayloadStatus.ACCEPTED


def test_5xx_is_retried_then_reported_as_transport_failure():
    calls = []

    def transport(method, url, timeout, max_bytes):
        calls.append(url)
        return (503, "text/plain", b"upstream down")

    svc = LiveSourceReadinessService(
        tenant_id=TENANT, transport=transport, gate=LiveSourceGate(env={LIVE_OPT_IN_ENV: "1"})
    )
    svc.register_policy(_policy(max_retries=2))
    payload = svc.fetch("cisa-kev", allow_live=True, now=T0)
    assert payload.status is PayloadStatus.TRANSPORT_FAILED
    assert payload.attempts == 3  # 1 initial + 2 retries
    assert len(calls) == 3


def test_5xx_then_success_is_accepted():
    state = {"n": 0}

    def transport(method, url, timeout, max_bytes):
        state["n"] += 1
        if state["n"] == 1:
            return (500, "text/plain", b"flaky")
        return (200, "application/json", KEV_BODY)

    svc = LiveSourceReadinessService(
        tenant_id=TENANT, transport=transport, gate=LiveSourceGate(env={LIVE_OPT_IN_ENV: "1"})
    )
    svc.register_policy(_policy(max_retries=2))
    payload = svc.fetch("cisa-kev", allow_live=True, now=T0)
    assert payload.status is PayloadStatus.ACCEPTED
    assert payload.attempts == 2


def test_4xx_is_not_retried():
    calls = []

    def transport(method, url, timeout, max_bytes):
        calls.append(url)
        return (404, "application/json", b'{"error": "gone"}')

    svc = LiveSourceReadinessService(
        tenant_id=TENANT, transport=transport, gate=LiveSourceGate(env={LIVE_OPT_IN_ENV: "1"})
    )
    svc.register_policy(_policy(max_retries=3))
    payload = svc.fetch("cisa-kev", allow_live=True, now=T0)
    assert payload.status is PayloadStatus.TRANSPORT_FAILED
    assert payload.attempts == 1
    assert len(calls) == 1
    assert "404" in payload.detail


def test_timeout_is_reported_as_timed_out():
    def transport(method, url, timeout, max_bytes):
        raise TimeoutError("read timeout")

    svc = LiveSourceReadinessService(
        tenant_id=TENANT, transport=transport, gate=LiveSourceGate(env={LIVE_OPT_IN_ENV: "1"})
    )
    svc.register_policy(_policy())
    payload = svc.fetch("cisa-kev", allow_live=True, now=T0)
    assert payload.status is PayloadStatus.TIMED_OUT
    assert "read timeout" in payload.detail


def test_transport_exception_is_retried_then_reported():
    attempts = []

    def transport(method, url, timeout, max_bytes):
        attempts.append(1)
        raise ConnectionError("dns failure")

    svc = LiveSourceReadinessService(
        tenant_id=TENANT, transport=transport, gate=LiveSourceGate(env={LIVE_OPT_IN_ENV: "1"})
    )
    svc.register_policy(_policy(max_retries=1))
    payload = svc.fetch("cisa-kev", allow_live=True, now=T0)
    assert payload.status is PayloadStatus.TRANSPORT_FAILED
    assert len(attempts) == 2
    assert "ConnectionError" in payload.detail


def test_schema_rejection_is_recorded_in_history():
    svc = LiveSourceReadinessService(
        tenant_id=TENANT,
        transport=_kev_transport(body=b'{"unexpected": true}'),
        gate=LiveSourceGate(env={LIVE_OPT_IN_ENV: "1"}),
    )
    svc.register_policy(_policy())
    payload = svc.fetch("cisa-kev", allow_live=True, now=T0)
    assert payload.status is PayloadStatus.REJECTED_SCHEMA
    assert svc.history("cisa-kev")[-1].status is PayloadStatus.REJECTED_SCHEMA


def test_fetch_history_can_be_filtered_and_bounded():
    svc = LiveSourceReadinessService(
        tenant_id=TENANT, transport=_kev_transport(), gate=LiveSourceGate(env={LIVE_OPT_IN_ENV: "1"})
    )
    svc.register_policy(_policy(min_interval_seconds=0, max_retries=0))
    for i in range(5):
        svc.fetch("cisa-kev", allow_live=True, now=T0 + timedelta(seconds=i))
    assert len(svc.history()) == 5
    assert len(svc.history(limit=2)) == 2
    assert svc.history(source_id="other") == []


# ------------------------------------------------------------- audit trail


def test_gate_records_an_audit_trail_of_attempts():
    gate = LiveSourceGate(env={LIVE_OPT_IN_ENV: "1"})
    svc = _service(transport=_kev_transport(), gate=gate)
    svc.fetch("cisa-kev", allow_live=True, now=T0)
    trail = gate.audit_trail()
    assert len(trail) == 1
    assert trail[0]["source_id"] == "cisa-kev"
    assert trail[0]["at"] == T0.isoformat()


def test_service_defaults_are_conservative():
    svc = LiveSourceReadinessService(tenant_id=TENANT)
    report = svc.readiness_report()
    assert report["opt_in_present"] is False
    assert report["transport_available"] is False
    assert report["ready_for_live_count"] == 0
    assert svc.policies() == []
