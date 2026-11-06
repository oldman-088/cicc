"""Synthetic candidate hooks; not actual host auth or tenant acceptance."""
from datetime import timedelta
import pytest
from apps.threat_intelligence.vi_read_only_adapter import VIReadOnlyAdapter, QualitySnapshot
from test_vulnerability_quality import inventory,obs,CVE,NOW


def test_version_preflight_before_host_callbacks_and_scoped_loader():
    calls=[]
    def loader(context):
        calls.append(context)
        if context!='EXPERIMENTAL_DEMO_DATA_ONLY allowed': raise PermissionError('synthetic denied')
        return QualitySnapshot(inventory(),[obs(1,'NVD',CVE)],[])
    adapter=VIReadOnlyAdapter(load_scoped_quality=loader,operator_engine=lambda _:None)
    kw=dict(as_of=NOW,max_observation_age=timedelta(days=1))
    with pytest.raises(ValueError): adapter.quality('wrong',schema_version='cicc.vulnerability-quality/2',**kw)
    assert calls==[]
    with pytest.raises(PermissionError): adapter.quality('not allowed',schema_version='cicc.vulnerability-quality/1',**kw)
    result=adapter.quality('EXPERIMENTAL_DEMO_DATA_ONLY allowed',schema_version='cicc.vulnerability-quality/1',**kw)
    assert result['schema_version']=='cicc.vulnerability-quality/1'
    assert len(calls)==2


def test_hooks_are_mandatory_and_no_silent_conflict_downgrade():
    with pytest.raises(TypeError): VIReadOnlyAdapter(load_scoped_quality=None,operator_engine=lambda _:None)
    calls=[];a=VIReadOnlyAdapter(load_scoped_quality=lambda _:None,operator_engine=lambda ctx:calls.append(ctx))
    with pytest.raises(ValueError): a.kev_conflict('fixture',schema_version='cicc.kev-conflict-summary/2',origin='EXPERIMENTAL_DEMO_DATA_ONLY',conflict_id=1)
    assert calls==[]
