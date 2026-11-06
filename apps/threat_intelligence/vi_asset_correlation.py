"""Declared asset/SBOM evidence links; not an applicability or exposure decision."""
from datetime import datetime,timedelta,timezone
from typing import Annotated, Literal
from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator
from .vulnerability_quality import Inventory

Text=Annotated[str,StringConstraints(strip_whitespace=True,min_length=1,max_length=1024)]

class AssetBinding(BaseModel):
    model_config=ConfigDict(extra='forbid',frozen=True)
    asset_id: Text
    document_id: Text
    provenance: Text
    collected_at: datetime
    origin: Literal['EXPERIMENTAL_DEMO_DATA_ONLY','CALLER_SUPPLIED_UNVERIFIED']

    @field_validator('collected_at',mode='before')
    @classmethod
    def no_numeric(cls,value):
        if isinstance(value,(int,float,bool)): raise ValueError('explicit timestamp required')
        return value

    @field_validator('collected_at')
    @classmethod
    def aware(cls,value):
        if value.tzinfo is None or value.utcoffset() is None: raise ValueError('aware timestamp required')
        return value.astimezone(timezone.utc)


def correlate_declared_asset_evidence(inventories: list[Inventory], bindings: list[AssetBinding], *,
                                      as_of: datetime, max_age: timedelta) -> dict:
    """Join explicit bindings to explicit component/CVE links without applicability inference."""
    if not isinstance(inventories,list) or not isinstance(bindings,list) or len(inventories)>1000 or len(bindings)>5000:
        raise ValueError('invalid correlation input')
    if any(not isinstance(i,Inventory) for i in inventories) or any(not isinstance(b,AssetBinding) for b in bindings):
        raise ValueError('validated inventory and binding inputs required')
    if not isinstance(as_of,datetime) or as_of.tzinfo is None or as_of.utcoffset() is None: raise ValueError('aware as_of required')
    if not isinstance(max_age,timedelta) or max_age.total_seconds()<=0: raise ValueError('positive age horizon required')
    inventories=[Inventory.model_validate(i.model_dump()) for i in inventories]
    bindings=[AssetBinding.model_validate(b.model_dump()) for b in bindings]
    docs={i.document_id:i for i in inventories}
    if len(docs)!=len(inventories): raise ValueError('duplicate inventory identifier')
    if len({(b.asset_id,b.document_id) for b in bindings})!=len(bindings): raise ValueError('duplicate asset binding')
    if any(b.document_id not in docs for b in bindings): raise ValueError('unresolved inventory binding')
    if sum(len(docs[b.document_id].vulnerability_links) for b in bindings)>10000: raise ValueError('expanded link limit exceeded')
    budget=0
    for b in bindings:
        budget+=len(b.model_dump_json().encode('utf-8'))
        budget+=sum(len(link.model_dump_json().encode('utf-8')) for link in docs[b.document_id].vulnerability_links)
        if budget>4_194_304: raise ValueError('expanded evidence payload limit exceeded')
    as_of=as_of.astimezone(timezone.utc);horizon=max_age.total_seconds(); results=[]
    def timed(value):
        age=(as_of-value).total_seconds()
        return {'age_seconds':age,'age_status':'future_collection_time' if age<0 else ('within_window' if age<=horizon else 'outside_window')}
    for binding in sorted(bindings,key=lambda b:(b.asset_id,b.document_id)):
        inv=docs[binding.document_id]
        links=[]
        for link in sorted(inv.vulnerability_links,key=lambda x:str(x.link_id)):
            links.append({'link':link.model_dump(mode='json'),**timed(link.collected_at)})
        results.append({'binding':binding.model_dump(mode='json'),'binding_age':timed(binding.collected_at),
                        'inventory_provenance':inv.provenance,'inventory_origin':inv.origin,
                        'inventory_collected_at':inv.collected_at.isoformat(),'inventory_age':timed(inv.collected_at),
                        'inventory_completeness':inv.component_completeness,'dependency_completeness':inv.dependency_completeness,
                        'links':links,'applicability':'unknown','exposure':'unknown'})
    return {'schema_version':'cicc.vi.asset-evidence/1','as_of':as_of.isoformat(),'max_age_seconds':horizon,'results':results,
            'interpretation':'Explicit declarations only; no applicability, exposure or safety decision.'}
