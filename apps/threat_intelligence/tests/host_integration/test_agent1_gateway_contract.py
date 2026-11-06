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


class HostConfigurationError(Exception):
    pass


def host_harness_module(environ):
    """Skip only when no harness was requested; partial configuration is an error."""
    isolation = environ.get('CICC_TI_HOST_ISOLATED')
    module = environ.get('CICC_TI_HOST_TEST_HARNESS')
    if not module and isolation in (None, '', '0'):
        return None
    if isolation != '1':
        raise HostConfigurationError('actual-host testing requires explicit isolated-host opt-in')
    if not module or not module.strip():
        raise HostConfigurationError('actual-host testing requires an approved harness module')
    return module


@pytest.fixture
def host(request):
    try:
        module = host_harness_module(os.environ)
    except HostConfigurationError as exc:
        pytest.fail(str(exc), pytrace=False)
    if module is None:
        needs = {
            'test_actual_gateway_create_postgres_and_audit': 'approved gateway mount, verified principal, actor-scoped PostgreSQL and trusted audit/trace',
            'test_actual_gateway_denies_unauthenticated_and_cross_tenant': 'actual gateway authentication and two verified tenant identities',
            'test_actual_gateway_rejects_invalid_and_forged_tenant': 'actual gateway principal binding and mounted validation',
            'test_actual_gateway_duplicate_and_conflict': 'actual gateway mount and isolated PostgreSQL idempotency',
            'test_actual_gateway_audit_failure_rolls_back': 'actual host audit-failure injection and transactional PostgreSQL',
            'test_actual_host_pool_reuse_keeps_tenant_isolation': 'actual actor-scoped pool reuse and rollback observation',
            'test_actual_gateway_list_is_tenant_scoped_and_audited': 'actual mounted list, two verified tenants and trusted audit',
            'test_actual_host_rejects_unauthorized_direct_sql': 'actual runtime database role, direct SQL probe and trusted audit',
        }
        pytest.skip('requires isolated actual-host harness: ' + needs.get(request.node.name, 'approved host integration'))
    # Harness is owner-supplied, executable test code; never load from a request.
    harness = importlib.import_module(module).build_harness()
    try:
        if harness.assert_isolated_actual_host() is not True:
            pytest.fail('harness must positively verify the isolated actual host', pytrace=False)
        yield harness
    finally:
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
    assert host.gateway_trace_contains(host.tenant_a, result.gateway_task_id, result.correlation_id)
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


def test_actual_gateway_list_is_tenant_scoped_and_audited(host):
    data, key = sample(), uuid4().hex
    created = host.create(host.tenant_a, data, key)
    assert created.status == 201
    entity = data['source_entity']
    own = host.list(host.tenant_a, entity['entity_type'], entity['entity_id'], limit=1, offset=0)
    assert own.status == 200 and own.correlation_id and own.gateway_task_id
    assert own.body['total'] == 1 and own.body['items'][0]['relationship_id'] == created.body['relationship_id']
    assert host.gateway_trace_contains(host.tenant_a, own.gateway_task_id, own.correlation_id)
    event = host.read_audit(host.tenant_a, own.correlation_id)
    assert event['tenant_id'] == host.tenant_a_id and event['operation'] == 'relationship.list'
    other = host.list(host.tenant_b, entity['entity_type'], entity['entity_id'], limit=1, offset=0)
    assert other.status == 200 and other.body['total'] == 0 and not other.body['items']


def test_actual_host_rejects_unauthorized_direct_sql(host):
    """Harness uses the actual restricted runtime DB login on an isolated host."""
    result = host.verify_direct_sql_denied()
    assert result.used_actual_runtime_login is True
    assert result.relationship_select_denied is True
    assert result.relationship_insert_update_delete_denied is True
    assert result.audit_select_insert_update_delete_denied is True
    assert result.tenant_mapping_mutation_denied is True
    assert result.other_tenant_role_denied is True
