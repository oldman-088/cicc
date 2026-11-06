"""Bounded, offline normalization of caller-supplied provider record subsets.

No fetching, publisher authentication, authoritative applicability, scoring,
source freshness guarantee, or tenant authorization is provided here.
"""
from datetime import date, datetime, timezone
from decimal import Decimal, InvalidOperation
import hashlib
import json
import re
from typing import Literal
from uuid import NAMESPACE_URL, uuid5
from pydantic import BaseModel, ConfigDict, Field, field_validator
from .vulnerability_quality import Observation, Claim

MAX_BYTES=1_000_000
CVE=re.compile(r'^CVE-[0-9]{4}-[0-9]{4,}$')

class EvidenceError(ValueError): pass

class SourceEvidence(BaseModel):
    model_config=ConfigDict(extra='forbid',frozen=True)
    source: Literal['NVD','OSV','GHSA','EPSS']
    source_record_id: str = Field(min_length=1,max_length=1024)
    cve_ids: list[str] = Field(max_length=100)
    other_identifiers: list[str] = Field(max_length=100)
    source_modified_at: datetime | None
    collected_at: datetime
    provenance: str = Field(min_length=1,max_length=900)
    source_sha256: str = Field(pattern=r'^[0-9a-f]{64}$')
    origin: Literal['EXPERIMENTAL_DEMO_DATA_ONLY','CALLER_SUPPLIED_UNVERIFIED']
    cvss_observations: list[dict[str,str]] = Field(max_length=50)
    epss_score: str | None
    epss_score_date: date | None

    @field_validator('source_record_id','provenance',mode='before')
    @classmethod
    def valid_text(cls,value):
        if not isinstance(value,str) or not value.strip(): raise ValueError('nonempty source text required')
        return value.strip()

    @field_validator('collected_at','source_modified_at',mode='before')
    @classmethod
    def explicit_time(cls,value):
        if isinstance(value,(int,float,bool)): raise ValueError('explicit timestamp required')
        return value

    @field_validator('cve_ids')
    @classmethod
    def valid_cves(cls, values):
        if len(values)!=len(set(values)) or any(not CVE.fullmatch(x) for x in values): raise ValueError('invalid CVE identifiers')
        return values

    @field_validator('collected_at','source_modified_at')
    @classmethod
    def aware(cls, value):
        if value is not None and (value.tzinfo is None or value.utcoffset() is None): raise ValueError('aware timestamp required')
        return value.astimezone(timezone.utc) if value else None


def _json(raw):
    if not isinstance(raw,bytes) or not raw or len(raw)>MAX_BYTES: raise EvidenceError('invalid evidence input size')
    def pairs(items):
        out={}
        for key,value in items:
            if key in out: raise EvidenceError('duplicate JSON key')
            out[key]=value
        return out
    try:
        result=json.loads(raw.decode('utf-8'),object_pairs_hook=pairs,parse_float=Decimal,
            parse_constant=lambda _: (_ for _ in ()).throw(EvidenceError('invalid JSON constant')))
    except (ValueError,UnicodeError,RecursionError,InvalidOperation): raise EvidenceError('invalid evidence JSON') from None
    if not isinstance(result,dict): raise EvidenceError('evidence root must be an object')
    return result


def _text(value):
    if not isinstance(value,str) or not value.strip() or len(value)>1024: raise EvidenceError('invalid identifier')
    return value.strip()


def _timestamp(value):
    if value is None: return None
    if not isinstance(value,str): raise EvidenceError('timestamp must be explicit')
    try: result=datetime.fromisoformat(value.replace('Z','+00:00'))
    except ValueError: raise EvidenceError('invalid timestamp') from None
    if result.tzinfo is None or result.utcoffset() is None: raise EvidenceError('aware timestamp required')
    return result.astimezone(timezone.utc)


def parse_source_evidence(raw: bytes, *, source: str, collected_at: datetime, provenance: str, origin: str) -> SourceEvidence:
    """Read a single record subset; original raw bytes must be retained by caller."""
    if not isinstance(collected_at,datetime): raise EvidenceError('explicit collection timestamp required')
    doc=_json(raw); digest=hashlib.sha256(raw).hexdigest(); others=[]; scores=[]; epss=None; score_date=None
    try:
        if source=='NVD':
            cve=doc.get('cve',doc)
            if not isinstance(cve,dict): raise EvidenceError('invalid NVD record')
            identifier=_text(cve.get('id')); cves=[identifier]
            if not CVE.fullmatch(identifier): raise EvidenceError('invalid CVE identifier')
            modified=_timestamp(cve.get('lastModified'))
            metrics=cve.get('metrics',{})
            if not isinstance(metrics,dict): raise EvidenceError('invalid CVSS metrics')
            for kind in ('cvssMetricV2','cvssMetricV30','cvssMetricV31','cvssMetricV40'):
                rows=metrics.get(kind,[])
                if not isinstance(rows,list) or len(rows)>50: raise EvidenceError('invalid CVSS metrics')
                for row in rows:
                    if not isinstance(row,dict) or not isinstance(row.get('cvssData'),dict): raise EvidenceError('invalid CVSS data')
                    cv=row['cvssData']; vector=cv.get('vectorString'); score=cv.get('baseScore'); entry={'kind':kind}
                    if vector is not None: entry['vector']=_text(vector)
                    if score is not None:
                        if isinstance(score,bool) or not isinstance(score,(int,Decimal)): raise EvidenceError('invalid CVSS score')
                        number=Decimal(score)
                        if not number.is_finite() or not 0<=number<=10: raise EvidenceError('invalid CVSS score')
                        entry['base_score']=str(number)
                    if len(entry)==1: raise EvidenceError('empty CVSS data')
                    if 'source' in row: entry['source']=_text(row['source'])
                    scores.append(entry)
            if len(scores)>50: raise EvidenceError('too many CVSS metrics')
        elif source=='OSV':
            identifier=_text(doc.get('id')); modified=_timestamp(doc.get('modified')); aliases=doc.get('aliases',[])
            if not isinstance(aliases,list) or len(aliases)>100: raise EvidenceError('invalid OSV aliases')
            values=[_text(x) for x in aliases]
            if any(x.startswith('CVE-') and not CVE.fullmatch(x) for x in values): raise EvidenceError('invalid CVE alias')
            cves=[x for x in values if CVE.fullmatch(x)];others=[x for x in values if not CVE.fullmatch(x)]
        elif source=='GHSA':
            identifier=_text(doc.get('ghsa_id')); modified=_timestamp(doc.get('updated_at')); values=[]
            if doc.get('cve_id') is not None:
                cve_id=_text(doc['cve_id'])
                if not CVE.fullmatch(cve_id): raise EvidenceError('invalid CVE identifier')
                values.append(cve_id)
            identifiers=doc.get('identifiers',[])
            if not isinstance(identifiers,list) or len(identifiers)>100: raise EvidenceError('invalid GHSA identifiers')
            for entry in identifiers:
                if not isinstance(entry,dict) or 'value' not in entry: raise EvidenceError('invalid GHSA identifier')
                value=_text(entry['value'])
                if (entry.get('type')=='CVE' or value.startswith('CVE-')) and not CVE.fullmatch(value): raise EvidenceError('invalid CVE identifier')
                values.append(value)
            cves=[x for x in values if CVE.fullmatch(x)];others=[x for x in values if not CVE.fullmatch(x)]
        elif source=='EPSS':
            identifier=_text(doc.get('cve')); cves=[identifier]; modified=None
            if not CVE.fullmatch(identifier): raise EvidenceError('invalid CVE identifier')
            epss=_text(doc.get('epss'))
            if len(epss)>32 or not re.fullmatch(r'(?:0(?:\.[0-9]+)?|1(?:\.0+)?)',epss): raise EvidenceError('invalid EPSS score')
            score_date=date.fromisoformat(_text(doc.get('date')))
        else: raise EvidenceError('unsupported source')
        if len(set(cves))!=len(cves): cves=list(set(cves))
        if len(set(others))!=len(others): others=list(set(others))
        return SourceEvidence(source=source,source_record_id=identifier,cve_ids=sorted(cves),other_identifiers=sorted(others),
            source_modified_at=modified,collected_at=collected_at,provenance=provenance,source_sha256=digest,origin=origin,
            cvss_observations=scores,epss_score=epss,epss_score_date=score_date)
    except EvidenceError: raise
    except (ValueError,TypeError,KeyError,InvalidOperation): raise EvidenceError('invalid source evidence') from None


def quality_observation(evidence: SourceEvidence) -> Observation:
    """Bridge explicit CVE identifiers to existing quality analysis; EPSS is separate."""
    if not isinstance(evidence,SourceEvidence): raise EvidenceError('source evidence required')
    evidence=SourceEvidence.model_validate(evidence.model_dump())
    if evidence.source=='EPSS': raise EvidenceError('EPSS scores are not a quality observation')
    # No CVSS value is selected from conflicting metrics; retain them in SourceEvidence.
    return Observation(observation_id=uuid5(NAMESPACE_URL,':'.join([evidence.source,evidence.source_sha256,evidence.collected_at.isoformat()])),
        source=evidence.source,source_record_id=evidence.source_record_id,cve_ids=evidence.cve_ids,claims=[],
        source_modified_at=evidence.source_modified_at,collected_at=evidence.collected_at,
        provenance=evidence.provenance+'#sha256:'+evidence.source_sha256,origin=evidence.origin)
