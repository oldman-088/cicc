"""Synthetic caller-scoped asset links, never authoritative findings."""
from datetime import timedelta
import pytest
from apps.threat_intelligence.vi_asset_correlation import AssetBinding,correlate_declared_asset_evidence
from test_vulnerability_quality import inventory,NOW,LABEL

def binding(asset='EXPERIMENTAL_DEMO_DATA_ONLY asset',document='EXPERIMENTAL_DEMO_DATA_ONLY sbom',when=NOW):
    return AssetBinding(asset_id=asset,document_id=document,provenance='EXPERIMENTAL_DEMO_DATA_ONLY binding',collected_at=when,origin=LABEL)

def test_only_explicit_links_are_joined_and_unknown_remains_unknown():
    inv=inventory(); b=binding(when=NOW-timedelta(days=2))
    out=correlate_declared_asset_evidence([inv],[b],as_of=NOW,max_age=timedelta(days=1))
    row=out['results'][0]
    assert row['binding_age']['age_status']=='outside_window' and row['inventory_origin']==LABEL
    assert row['links'][0]['link']['basis']=='source_declared'
    assert row['applicability']==row['exposure']=='unknown'
    assert correlate_declared_asset_evidence([inv],[],as_of=NOW,max_age=timedelta(days=1))['results']==[]

def test_dangling_duplicate_and_mutated_inventory_fail_closed():
    inv=inventory(); kwargs=dict(as_of=NOW,max_age=timedelta(days=1))
    with pytest.raises(ValueError): correlate_declared_asset_evidence([inv],[binding(document='missing')],**kwargs)
    with pytest.raises(ValueError): correlate_declared_asset_evidence([inv],[binding(),binding()],**kwargs)
    inv.components.clear()
    with pytest.raises(ValueError): correlate_declared_asset_evidence([inv],[binding()],**kwargs)
