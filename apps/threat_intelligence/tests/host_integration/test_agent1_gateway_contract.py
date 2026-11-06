"""Opt-in Agent 1 host E2E acceptance suite, currently blocked on an approved harness.

The harness is test infrastructure, NOT a proposed host wire contract. It must
call the actual approved gateway, host router, principal binding and isolated
PostgreSQL, not simulate them. See HOST_INTEGRATION_HANDOFF.md. No environment
URLs or credentials are emitted by this suite.
"""
import importlib
import os
from uuid import uuid4

import pytest


@pytest.fixture
def host():
    module = os.getenv('CICC_TI_HOST_TEST_HARNESS')
    if os.getenv('CICC_TI_HOST_ISOLATED') != '1' or not module:
        pytest.skip('actual host harness and isolated environment are not configured')
    # Harness is owner-supplied, executable test code; never load from a request.
    harness = importlib.import_module(module).build_harness()
    harness.assert_isolated_actual_host()
    yield harness
    harness.close()


def sample():
    suffix = uuid4().hex
    return {'source_entity': {'entity_id': 'host-fixture-a-' + suffix, 'entity_type': 'Actor'},
            'target_entity': {'entity_id': 'host-fixture-b-' + suffix, 'entity_type': 'Malware'},
            'relationship_type': 'USES', 'confidence': 'HIGH', 'confirmed': False,
            'provenance': 'EXPERIMENTAL_DEMO_DATA_ONLY fixture',
            'experimental_label': 'EXPERIMENTAL_DEMO_DATA_ONLY',
            'evidence': [{'source': 'fixture', 'timestamp': '2026-01-01T00:00:00Z',
                'description': 'fixture evidence', 'confidence': 'HIGH', 'provenance': 'fixture'}]}


def test_actual_gateway_create_postgres_and_audit(host):
    data, key = sample(), uuid4().hex
    result = host.create(host.tenant_a, data, key)
    assert result.status == 201 and result.gateway_task_id and result.correlation_id
    assert result.body['experimental_label'] == 'EXPERIMENTAL_DEMO_DATA_ONLY'
    assert result.body['provenance'] == data['provenance']
    event = host.read_audit(host.tenant_a, result.correlation_id)
    assert event['resource_id'] == result.body['relationship_id']
    assert event['tenant_id'] == host.tenant_a_id and event['outcome'] == 'created'
    assert host.get(host.tenant_a, result.body['relationship_id']).status == 200


def test_actual_gateway_denies_unauthenticated_and_cross_tenant(host):
    assert host.create(host.unauthenticated, sample(), uuid4().hex).status == 401
    data = sample()
    result = host.create(host.tenant_a, data, uuid4().hex)
    assert result.status == 201
    assert host.get(host.tenant_b, result.body['relationship_id']).status == 404
    assert host.traverse(host.tenant_b, data['source_entity']['entity_type'], data['source_entity']['entity_id']).status == 404
    assert host.read_audit(host.tenant_b, result.correlation_id) is None


def test_actual_gateway_rejects_invalid_and_forged_tenant(host):
    data = sample(); data['confidence'] = 'not-a-valid-level'
    assert host.create(host.tenant_a, data, uuid4().hex).status == 422
    data = sample(); data['tenant_id'] = host.tenant_b_id
    assert host.create(host.tenant_a, data, uuid4().hex).status == 422


def test_actual_gateway_duplicate_and_conflict(host):
    data, key = sample(), uuid4().hex
    first, second = host.create(host.tenant_a, data, key), host.create(host.tenant_a, data, key)
    assert (first.status, second.status) == (201, 200)
    assert first.body['relationship_id'] == second.body['relationship_id']
    assert host.create(host.tenant_a, sample(), key).status == 409


def test_actual_gateway_audit_failure_rolls_back(host):
    data, key = sample(), uuid4().hex
    with host.fail_next_relationship_audit():
        assert host.create(host.tenant_a, data, key).status >= 500
    assert host.find_by_idempotency_key(host.tenant_a, key) is None
    assert host.create(host.tenant_a, data, key).status == 201


def test_actual_host_pool_reuse_keeps_tenant_isolation(host):
    """Harness must exercise real pool reuse, not fabricate connection evidence."""
    result = host.verify_pool_reuse_isolation()
    assert result.reused_backend_observed is True
    assert result.same_tenant_access_preserved is True
    assert result.cross_tenant_access_denied is True
    assert result.transaction_rollback_isolated is True
