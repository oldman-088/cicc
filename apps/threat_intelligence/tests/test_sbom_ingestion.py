"""SBOM fixtures are synthetic EXPERIMENTAL_DEMO_DATA_ONLY."""
import hashlib
import json
from datetime import datetime,timedelta,timezone
import pytest
from apps.threat_intelligence.sbom_ingestion import import_sbom, SBOMError
from apps.threat_intelligence.vulnerability_quality import quality_document

NOW=datetime(2026,1,2,tzinfo=timezone.utc)
def raw(doc): return json.dumps(doc,sort_keys=True).encode()
def load(doc): return import_sbom(raw(doc),document_id='fixture SBOM',provenance='EXPERIMENTAL_DEMO_DATA_ONLY fixture',collected_at=NOW,origin='EXPERIMENTAL_DEMO_DATA_ONLY')

def cyclone():
    return {'bomFormat':'CycloneDX','specVersion':'1.5','components':[
        {'type':'library','bom-ref':'a','name':'fixture-a','version':'1','purl':'pkg:generic/a@1','licenses':[{'license':{'id':'MIT'}}]},
        {'type':'library','bom-ref':'b','name':'fixture-b'}], 'dependencies':[{'ref':'a','dependsOn':['b']},{'ref':'b','dependsOn':[]}]}

def spdx():
    return {'spdxVersion':'SPDX-2.3','SPDXID':'SPDXRef-DOCUMENT','name':'fixture','packages':[
        {'SPDXID':'SPDXRef-A','name':'fixture-a','versionInfo':'1','licenseDeclared':'NOASSERTION',
         'licenseConcluded':'MIT','externalRefs':[{'referenceCategory':'PACKAGE-MANAGER','referenceType':'purl','referenceLocator':'pkg:generic/a@1'}]},
        {'SPDXID':'SPDXRef-B','name':'fixture-b'}],
        'relationships':[{'spdxElementId':'SPDXRef-A','relationshipType':'DEPENDS_ON','relatedSpdxElement':'SPDXRef-B'}]}

@pytest.mark.parametrize('factory,fmt,version',[(cyclone,'CycloneDX','1.5'),(spdx,'SPDX','2.3')])
def test_supported_subset_provenance_dependencies_and_quality(factory,fmt,version):
    doc=factory(); a=load(doc); b=load(doc)
    assert a==b and a.source_sha256==hashlib.sha256(raw(doc)).hexdigest()
    assert (a.format,a.version)==(fmt,version) and len(a.inventory.components)==2 and len(a.inventory.dependencies)==1
    assert a.inventory.component_completeness==a.inventory.dependency_completeness=='unknown'
    assert a.inventory.vulnerability_links==[] and a.source_sha256 in a.inventory.provenance
    report=quality_document(a.inventory,[],[],as_of=NOW+timedelta(days=2),max_observation_age=timedelta(days=1))
    assert any(f['code']=='inventory_collection_outside_window' for f in report['findings'])
    assert not any(f['classification'] in ('safe','not_vulnerable','vulnerable') for f in report['findings'])

def test_spdx_noassertion_stays_unknown_and_licenses_remain_distinct():
    a=load(spdx()); licenses=a.inventory.components[0].licenses
    assert licenses[0].expression is None and licenses[1].expression=='MIT'
    assert licenses[0].provenance.endswith('#licenseDeclared')
    assert ('SPDXRef-A','licenseDeclared','NOASSERTION') in a.license_statements

@pytest.mark.parametrize('change',[
    lambda d:d.update(specVersion='1.6'),
    lambda d:d.update(vulnerabilities=[{'id':'CVE-2099-0001'}]),
    lambda d:d['components'][0].update(components=[]),
    lambda d:d['dependencies'][0].update(dependsOn=['missing']),
    lambda d:d['components'][0].update(licenses=[{'expression':'MIT','license':{'id':'MIT'}}]),
])
def test_unsupported_or_incomplete_structures_fail_closed(change):
    d=cyclone();change(d)
    with pytest.raises(SBOMError): load(d)

def test_invalid_data_never_silently_accepted():
    for bad in [b'{"bomFormat":"CycloneDX","bomFormat":"CycloneDX"}',b'\xff',b'x'*1_000_001,b'[]', b'{"bomFormat":"CycloneDX","metadata":1e999}']:
        with pytest.raises(SBOMError): import_sbom(bad,document_id='fixture',provenance='fixture',collected_at=NOW,origin='EXPERIMENTAL_DEMO_DATA_ONLY')
    d=spdx();d['relationships'][0]['relationshipType']='CONTAINS'
    with pytest.raises(SBOMError): load(d)
    with pytest.raises(SBOMError): import_sbom(raw(cyclone()),document_id='fixture',provenance='fixture',collected_at=NOW.replace(tzinfo=None),origin='EXPERIMENTAL_DEMO_DATA_ONLY')


def test_import_does_not_infer_vulnerability_from_component_identity():
    from uuid import UUID
    from apps.threat_intelligence.vulnerability_quality import Observation, VulnerabilityLink, Inventory
    inv=load(cyclone()).inventory
    evidence=Observation(observation_id=UUID(int=1),source='NVD',source_record_id='CVE-2099-0001',cve_ids=['CVE-2099-0001'],claims=[],
        source_modified_at=None,collected_at=NOW,provenance='EXPERIMENTAL_DEMO_DATA_ONLY NVD fixture',origin='EXPERIMENTAL_DEMO_DATA_ONLY')
    report=quality_document(inv,[evidence],[],as_of=NOW,max_observation_age=timedelta(days=1))
    assert report['evidence']['assessments'][0]['linked_components']==[]
    data=inv.model_dump();data['vulnerability_links']=[VulnerabilityLink(link_id=UUID(int=2),bom_ref='a',cve_id='CVE-2099-0001',basis='analyst_declared',
        provenance='EXPERIMENTAL_DEMO_DATA_ONLY explicit link',collected_at=NOW,origin='EXPERIMENTAL_DEMO_DATA_ONLY').model_dump()]
    linked=quality_document(Inventory.model_validate(data),[evidence],[],as_of=NOW,max_observation_age=timedelta(days=1))
    assert linked['evidence']['assessments'][0]['linked_components'][0]['basis']=='analyst_declared'
