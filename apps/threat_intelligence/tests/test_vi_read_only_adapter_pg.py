"""Synthetic operator callback and disposable PostgreSQL; not Agent 1 host."""
import pytest
from sqlalchemy import text
from apps.threat_intelligence.vi_read_only_adapter import VIReadOnlyAdapter
from apps.threat_intelligence.cisa_kev_persistence import persist_catalog
from test_cisa_kev_persistence import db,collected
from test_cisa_github_collector import sample


def test_candidate_operator_conflict_read_is_read_only_and_denial_is_host_owned(db):
    original=collected(sample());persist_catalog(db,original)
    data=sample();data['vulnerabilities'][0]['product']='EXPERIMENTAL_DEMO_DATA_ONLY changed fixture'
    conflict=persist_catalog(db,collected(data))
    def operator(context):
        if context!='EXPERIMENTAL_DEMO_DATA_ONLY operator': raise PermissionError('synthetic denied')
        return db
    adapter=VIReadOnlyAdapter(load_scoped_quality=lambda _:None,operator_engine=operator)
    params=dict(schema_version='cicc.kev-conflict-summary/1',origin=original.origin,conflict_id=conflict.conflict_id)
    with pytest.raises(PermissionError): adapter.kev_conflict('not authorized',**params)
    with db.connect() as c: before=c.execute(text('SELECT count(*) FROM ti_kev.source_conflict')).scalar_one()
    result=adapter.kev_conflict('EXPERIMENTAL_DEMO_DATA_ONLY operator',**params)
    with db.connect() as c: after=c.execute(text('SELECT count(*) FROM ti_kev.source_conflict')).scalar_one()
    assert before==after==1 and result['previous_sha256']==original.content_sha256
