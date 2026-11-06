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
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
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

    @model_validator(mode='after')
    def consistent_fields(self):
        if any(not x or len(x)>1024 for x in self.other_identifiers) or len(set(self.other_identifiers))!=len(self.other_identifiers):
            raise ValueError('invalid other identifiers')
        if self.source in ('NVD','EPSS') and (not CVE.fullmatch(self.source_record_id) or self.cve_ids != [self.source_record_id]):
            raise ValueError('CVE record identifier mismatch')
        if self.source!='NVD' and self.cvss_observations: raise ValueError('unexpected CVSS observations')
        for metric in self.cvss_observations:
            if (set(metric)-{'kind','source','vector','base_score'} or metric.get('kind') not in ('cvssMetricV2','cvssMetricV30','cvssMetricV31','cvssMetricV40')
                or not ('base_score' in metric or 'vector' in metric)
                or any(not val.strip() or len(val)>1024 for val in metric.values())):
                raise ValueError('invalid CVSS observation')
            if 'base_score' in metric:
                try: score=Decimal(metric['base_score'])
                except InvalidOperation: raise ValueError('invalid CVSS score') from None
                if not score.is_finite() or not 0<=score<=10: raise ValueError('invalid CVSS score')
        if self.source=='EPSS':
            if self.epss_score is None or len(self.epss_score)>32 or not re.fullmatch(r'(?:0(?:\.[0-9]+)?|1(?:\.0+)?)',self.epss_score) or self.epss_score_date is None:
                raise ValueError('invalid EPSS evidence')
        elif self.epss_score is not None or self.epss_score_date is not None:
            raise ValueError('unexpected EPSS evidence')
        return self


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


def verify_evidence_bytes(evidence: SourceEvidence, raw: bytes) -> None:
    """Check supplied raw bytes and normalized fields agree; not publisher authentication."""
    if not isinstance(evidence,SourceEvidence): raise EvidenceError('source evidence required')
    try:
        checked=SourceEvidence.model_validate(evidence.model_dump())
        reparsed=parse_source_evidence(raw,source=checked.source,collected_at=checked.collected_at,
                                       provenance=checked.provenance,origin=checked.origin)
        if checked!=reparsed: raise EvidenceError('source evidence does not match supplied bytes')
    except EvidenceError: raise
    except (ValueError,TypeError): raise EvidenceError('invalid source evidence') from None


def evidence_batch_report(evidence: list[SourceEvidence], *, as_of: datetime, max_collection_age) -> dict:
    """Summarize caller-scoped evidence, never choose a winner or make decisions.

    Duplicate content is grouped by provider/record/digest; observations remain
    intact. Same-revision disagreement is reported only for comparable explicitly
    supplied CVSS fields or EPSS scores, not inferred from a digest mismatch.
    """
    from datetime import timedelta
    if not isinstance(evidence,list) or len(evidence)>5000 or any(not isinstance(x,SourceEvidence) for x in evidence):
        raise EvidenceError('invalid evidence batch')
    if not isinstance(as_of,datetime) or as_of.tzinfo is None or as_of.utcoffset() is None:
        raise EvidenceError('aware as_of required')
    if not isinstance(max_collection_age,timedelta) or max_collection_age.total_seconds()<=0:
        raise EvidenceError('positive age horizon required')
    try: items=[SourceEvidence.model_validate(x.model_dump()) for x in evidence]
    except ValueError: raise EvidenceError('invalid source evidence') from None
    if sum(len(x.model_dump_json().encode('utf-8')) for x in items)>4_194_304:
        raise EvidenceError('evidence batch size exceeded')
    as_of=as_of.astimezone(timezone.utc); horizon=max_collection_age.total_seconds(); observations=[]; groups={}; comparisons={}
    for item in items:
        age=(as_of-item.collected_at).total_seconds()
        data=item.model_dump(mode='json')
        score_age=(as_of.date()-item.epss_score_date).days if item.epss_score_date is not None else None
        observations.append({'evidence':data,'collection_age_seconds':age,
            'collection_age_status':'future' if age<0 else ('stale' if age>horizon else 'within_window'),
            'source_modified_status':'unknown' if item.source_modified_at is None else ('future' if item.source_modified_at>as_of else 'supplied'),
            'score_date_age_days':score_age,'score_date_status':'unknown' if score_age is None else ('future' if score_age<0 else 'supplied')})
        groups.setdefault((item.origin,item.source,item.source_record_id,item.source_sha256),[]).append(item)
        # Comparing values requires the same source, record and explicit revision.
        if item.source=='NVD' and item.source_modified_at is not None:
            for metric in item.cvss_observations:
                if 'source' not in metric: continue # do not assume same metric issuer
                key=(item.origin,item.source,item.source_record_id,item.source_modified_at.isoformat(),metric.get('kind'),metric['source'])
                fields=comparisons.setdefault(key,{})
                for field in ('vector','base_score'):
                    if field in metric:
                        value=str(Decimal(metric[field]).normalize()) if field=='base_score' else metric[field]
                        fields.setdefault(field,set()).add(value)
        if item.source=='EPSS' and item.epss_score is not None and item.epss_score_date is not None:
            key=(item.origin,item.source,item.source_record_id,item.epss_score_date.isoformat(),'epss','provider-declared')
            comparisons.setdefault(key,{}).setdefault('score',set()).add(str(Decimal(item.epss_score).normalize()))
    observations.sort(key=lambda x:json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=False))
    duplicates=[{'origin':key[0],'source':key[1],'source_record_id':key[2],'source_sha256':key[3],'observation_count':len(group)}
                for key,group in sorted(groups.items()) if len(group)>1]
    conflicts=[]
    for key,fields in sorted(comparisons.items()):
        differing={k:sorted(v) for k,v in sorted(fields.items()) if len(v)>1}
        if differing: conflicts.append({'origin':key[0],'source':key[1],'source_record_id':key[2],'revision':key[3],
                                         'metric':key[4],'issuer':key[5],'differing_fields':differing})
    return {'schema_version':'cicc.vi.source-evidence-batch/1','as_of':as_of.isoformat(),
            'max_collection_age_seconds':horizon,'observations':observations,'duplicate_content':duplicates,
            'same_revision_conflicts':conflicts,'interpretation':'Evidence comparison only; no source winner, applicability, exposure, confidence or priority.'}
