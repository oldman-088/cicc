"""Experimental pure resolution-history planning; NO persistence or authorization boundary.

A host-supplied authorizer is simulated here; it is not a verified identity.
Never deploy as a resolution service without approved DB-derived authorization,
transactional audit, externally protected retention and concurrency controls.
"""
import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from uuid import UUID
from .cisa_github_collector import verify_source_bytes, CollectionError

class ResolutionDraftError(ValueError): pass
class ResolutionDraftDenied(PermissionError): pass

@dataclass(frozen=True)
class DraftResult:
    event_json: str
    history: tuple[str, ...]
    replayed: bool


def _encode(x): return json.dumps(x,sort_keys=True,ensure_ascii=False,separators=(',',':'),allow_nan=False)
def _digest(x): return hashlib.sha256(_encode(x).encode('utf-8')).hexdigest()


def _history(history, identity):
    if not isinstance(history,(tuple,list)) or len(history)>1000: raise ResolutionDraftError('invalid draft history')
    parsed=[]; previous=None; keys=set()
    for index,raw in enumerate(history,1):
        if not isinstance(raw,str) or len(raw.encode('utf-8'))>16384: raise ResolutionDraftError('invalid draft event')
        try: data=json.loads(raw)
        except (ValueError,RecursionError): raise ResolutionDraftError('invalid draft event') from None
        if not isinstance(data,dict) or _encode(data)!=raw: raise ResolutionDraftError('noncanonical draft event')
        digest=data.pop('event_sha256',None)
        if (set(data)!={'schema_version','sequence','previous_event_sha256','conflict','resolver','disposition','rationale','evidence_refs','decided_at','idempotency_key'}
            or data['schema_version']!='cicc.kev-resolution-draft/1' or data['sequence']!=index
            or data['previous_event_sha256']!=previous or data['conflict']!=identity or digest!=_digest(data)
            or not isinstance(data['idempotency_key'],str) or data['idempotency_key'] in keys):
            raise ResolutionDraftError('draft history integrity check failed')
        keys.add(data['idempotency_key']);data['event_sha256']=digest;parsed.append(data);previous=digest
    return parsed


def prepare_resolution(inspection, *, expected_previous_sha256, expected_candidate_sha256, resolver,
                       authorize, disposition, rationale, evidence_refs, decided_at, idempotency_key, history=()):
    """Build/replay a draft event; identity and authorization are injected, not trusted.

    Does not save history, mutate conflict/streams, alter active snapshots, or
    execute a resolution. Caller-provided history/hashes can be forged without
    an independently protected anchor and are not an immutable audit log.
    """
    if not isinstance(resolver,str) or not resolver.strip() or len(resolver)>256 or not callable(authorize):
        raise ResolutionDraftError('invalid resolver or authorizer')
    if authorize(resolver,disposition) is not True: raise ResolutionDraftDenied('resolver not authorized')
    if disposition not in ('acknowledge_unresolved','request_source_recheck'):
        raise ResolutionDraftError('unsupported disposition')
    if not isinstance(rationale,str) or not rationale.strip() or len(rationale)>2000: raise ResolutionDraftError('rationale required')
    if (not isinstance(evidence_refs,(list,tuple)) or not 1<=len(evidence_refs)<=20
        or any(not isinstance(x,str) or not x.strip() or len(x)>512 for x in evidence_refs)):
        raise ResolutionDraftError('evidence references required')
    refs=sorted(set(evidence_refs))
    if len(refs)!=len(evidence_refs): raise ResolutionDraftError('duplicate evidence reference')
    if not isinstance(decided_at,datetime) or decided_at.tzinfo is None or decided_at.utcoffset() is None:
        raise ResolutionDraftError('timezone-aware decision time required')
    try: key=str(UUID(str(idempotency_key)))
    except (ValueError,TypeError,AttributeError): raise ResolutionDraftError('invalid idempotency key') from None
    if not isinstance(inspection,dict) or inspection.get('schema_version')!='cicc.kev-conflict-inspection/1': raise ResolutionDraftError('unsupported conflict inspection')
    for side,expected in (('previous',expected_previous_sha256),('candidate',expected_candidate_sha256)):
        if not isinstance(expected,str) or not re.fullmatch(r'[a-f0-9]{64}',expected): raise ResolutionDraftError('invalid expected digest')
        try:
            catalog=inspection[side]; verify_source_bytes(catalog)
            valid=inspection[side+'_sha256']==expected==catalog.content_sha256 and inspection['origin']==catalog.origin
        except (KeyError,TypeError,ValueError,AttributeError,CollectionError): raise ResolutionDraftError('conflict evidence unavailable') from None
        if not valid: raise ResolutionDraftError('stale or inconsistent conflict evidence')
    if inspection['previous'].catalog.dateReleased != inspection['candidate'].catalog.dateReleased:
        raise ResolutionDraftError('conflict release mismatch')
    conflict={'origin':inspection['origin'],'conflict_id':inspection['conflict_id'],'previous_snapshot_id':inspection['previous_snapshot_id'],
              'previous_sha256':expected_previous_sha256,'candidate_sha256':expected_candidate_sha256}
    parsed=_history(history,conflict)
    request={'schema_version':'cicc.kev-resolution-draft/1','conflict':conflict,'resolver':resolver,
             'disposition':disposition,'rationale':rationale,'evidence_refs':refs,
             'decided_at':decided_at.astimezone(timezone.utc).isoformat(),'idempotency_key':key}
    for existing,raw in zip(parsed,history):
        if existing['idempotency_key']==key:
            if any(existing[k]!=v for k,v in request.items()): raise ResolutionDraftError('idempotency conflict')
            return DraftResult(raw,tuple(history),True)
    event=dict(request,sequence=len(parsed)+1,previous_event_sha256=parsed[-1]['event_sha256'] if parsed else None)
    event['event_sha256']=_digest(event); raw=_encode(event)
    return DraftResult(raw,tuple(history)+(raw,),False)
