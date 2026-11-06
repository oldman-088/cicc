"""Synthetic, in-memory planning over disposable PostgreSQL evidence; not host audit."""
import json
from datetime import datetime,timezone
from uuid import UUID
import pytest
from apps.threat_intelligence.cisa_kev_persistence import persist_catalog
from apps.threat_intelligence.cisa_kev_snapshot import inspect_conflict, load_snapshot
from apps.threat_intelligence.cisa_github_collector import verify_source_bytes
from apps.threat_intelligence.kev_resolution_draft import prepare_resolution, ResolutionDraftError, ResolutionDraftDenied
from test_cisa_kev_persistence import db,collected
from test_cisa_github_collector import sample

@pytest.fixture
def inspection(db):
    first=collected(sample());persist_catalog(db,first)
    data=sample();data['vulnerabilities'][0]['product']='EXPERIMENTAL_DEMO_DATA_ONLY conflicting fixture'
    candidate=collected(data); result=persist_catalog(db,candidate)
    return inspect_conflict(db,origin=first.origin,conflict_id=result.conflict_id)

def args(inspection):
    return dict(expected_previous_sha256=inspection['previous_sha256'],expected_candidate_sha256=inspection['candidate_sha256'],
                resolver='EXPERIMENTAL_DEMO_DATA_ONLY operator',authorize=lambda resolver,action: True,
                disposition='acknowledge_unresolved',rationale='EXPERIMENTAL_DEMO_DATA_ONLY rationale',
                evidence_refs=['fixture:evidence:2','fixture:evidence:1'],decided_at=datetime(2026,1,1,tzinfo=timezone.utc),idempotency_key=UUID(int=1))

def test_draft_history_reproducibility_idempotency_and_preserved_bytes(db,inspection):
    old=verify_source_bytes(inspection['previous']);new=verify_source_bytes(inspection['candidate'])
    one=prepare_resolution(inspection,**args(inspection)); assert one==prepare_resolution(inspection,**args(inspection))
    head=json.loads(one.event_json)['event_sha256']
    retry=prepare_resolution(inspection,**args(inspection),history=one.history,expected_history_head=head)
    assert retry.replayed and retry.history==one.history
    later=args(inspection);later['idempotency_key']=UUID(int=2);later['disposition']='request_source_recheck'
    two=prepare_resolution(inspection,**later,history=one.history,expected_history_head=head)
    assert len(two.history)==2 and json.loads(two.event_json)['previous_event_sha256']==json.loads(one.event_json)['event_sha256']
    assert verify_source_bytes(inspection['previous'])==old and verify_source_bytes(inspection['candidate'])==new
    assert load_snapshot(db,origin=inspection['origin']).content_sha256==inspection['previous_sha256']

def test_denied_stale_tampered_and_unsupported_fail_closed(inspection):
    kw=args(inspection);kw['authorize']=lambda *_:False
    with pytest.raises(ResolutionDraftDenied): prepare_resolution(inspection,**kw)
    kw=args(inspection);kw['expected_candidate_sha256']='0'*64
    with pytest.raises(ResolutionDraftError): prepare_resolution(inspection,**kw)
    kw=args(inspection);kw['disposition']='select_candidate'
    with pytest.raises(ResolutionDraftError): prepare_resolution(inspection,**kw)
    first=prepare_resolution(inspection,**args(inspection));bad=first.event_json.replace('fixture:evidence:1','fixture:evidence:0')
    with pytest.raises(ResolutionDraftError): prepare_resolution(inspection,**args(inspection),history=[bad])
    kw=args(inspection);kw['rationale']='different fixture'
    with pytest.raises(ResolutionDraftError,match='idempotency'): prepare_resolution(inspection,**kw,history=first.history,expected_history_head=json.loads(first.event_json)['event_sha256'])
    inspection['candidate']._source_bytes=b'broken fixture'
    with pytest.raises(ResolutionDraftError): prepare_resolution(inspection,**args(inspection))

def test_rationale_evidence_and_aware_time_required(inspection):
    for change in ({'rationale':' '},{'evidence_refs':[]},{'decided_at':datetime(2026,1,1)}):
        kw=args(inspection);kw.update(change)
        with pytest.raises(ResolutionDraftError): prepare_resolution(inspection,**kw)


def test_optimistic_history_head_rejects_conflicting_concurrent_drafts(db,inspection):
    """Simulate an external serializing store; planner alone has no CAS or persistence."""
    from concurrent.futures import ThreadPoolExecutor
    first=args(inspection);second=args(inspection);second['idempotency_key']=UUID(int=2);second['rationale']='EXPERIMENTAL_DEMO_DATA_ONLY other rationale'
    with ThreadPoolExecutor(max_workers=2) as pool:
        proposals=list(pool.map(lambda kw:prepare_resolution(inspection,**kw),[first,second]))
    assert proposals[0].history!=proposals[1].history  # two independent drafts, not commits
    current=proposals[0].history
    with pytest.raises(ResolutionDraftError,match='stale draft history head'):
        prepare_resolution(inspection,**second,history=current,expected_history_head=None)
    assert load_snapshot(db,origin=inspection['origin']).content_sha256==inspection['previous_sha256']
