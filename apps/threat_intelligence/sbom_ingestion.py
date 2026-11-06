"""Offline, bounded SPDX 2.3 and CycloneDX 1.5 JSON subset translation.

Not full schema validation, vulnerability matching, a tenant boundary, or a host
API. Unsupported structures fail closed rather than asserting completeness.
"""
import hashlib
import json
import math
from dataclasses import dataclass
from datetime import datetime
from uuid import NAMESPACE_URL, uuid5
from .vulnerability_quality import Component, Dependency, Inventory, LicenseEvidence

MAX_BYTES=1_000_000

class SBOMError(ValueError):
    """Invalid, oversized, ambiguous, or unsupported SBOM."""

@dataclass(frozen=True)
class ImportedSBOM:
    format: str
    version: str
    source_sha256: str
    inventory: Inventory
    ignored_fields: tuple[str, ...]
    license_statements: tuple[tuple[str, str, str], ...]


def _parse(raw):
    if not isinstance(raw,bytes) or not raw or len(raw)>MAX_BYTES: raise SBOMError('invalid SBOM bytes or size')
    def pairs(values):
        out={}
        for k,v in values:
            if k in out: raise SBOMError('duplicate JSON key')
            out[k]=v
        return out
    def finite_float(value):
        result=float(value)
        if not math.isfinite(result): raise SBOMError('non-finite JSON number')
        return result
    try:
        doc=json.loads(raw.decode('utf-8'),object_pairs_hook=pairs,parse_float=finite_float,
                       parse_constant=lambda _: (_ for _ in ()).throw(SBOMError('invalid JSON constant')))
    except (ValueError,UnicodeError,RecursionError): raise SBOMError('invalid SBOM JSON') from None
    if not isinstance(doc,dict): raise SBOMError('SBOM root must be an object')
    return doc


def _obj(value, allowed, where):
    if not isinstance(value,dict) or set(value)-set(allowed): raise SBOMError('unsupported '+where+' fields')
    return value


def _list(value, limit, where):
    if not isinstance(value,list) or len(value)>limit: raise SBOMError('invalid '+where)
    return value


def import_sbom(raw: bytes, *, document_id: str, provenance: str, collected_at: datetime, origin: str) -> ImportedSBOM:
    """Translate explicitly supported subsets, retaining hash and unknown coverage.

    The caller owns source authentication, authorization and retaining raw bytes.
    Does not infer package identity, dependencies, CVEs, completeness or licenses.
    """
    doc=_parse(raw); digest=hashlib.sha256(raw).hexdigest()
    if not isinstance(provenance,str) or not provenance.strip() or len(provenance)>900: raise SBOMError('invalid provenance')
    prov=provenance.strip()+'#sha256:'+digest
    components=[]; edges=[]; ignored=[]; statements=[]
    try:
        if doc.get('bomFormat')=='CycloneDX' and doc.get('specVersion')=='1.5':
            _obj(doc,('bomFormat','specVersion','serialNumber','version','metadata','components','dependencies'),'CycloneDX document')
            for key in ('serialNumber','version','metadata'):
                if key in doc: ignored.append(key)
            for component in _list(doc.get('components',[]),5000,'components'):
                _obj(component,('type','bom-ref','name','version','purl','licenses'),'CycloneDX component')
                ref=component['bom-ref']; licenses=[]
                if 'type' in component: ignored.append('components.type')
                for i,entry in enumerate(_list(component.get('licenses',[]),100,'licenses')):
                    _obj(entry,('license','expression'),'CycloneDX license')
                    if ('license' in entry)==('expression' in entry): raise SBOMError('ambiguous license')
                    if 'license' in entry:
                        lic=_obj(entry['license'],('id',),'CycloneDX license identity'); expression=lic.get('id')
                    else: expression=entry['expression']
                    if not isinstance(expression,str) or not expression.strip(): raise SBOMError('invalid license expression')
                    statements.append((ref,'license' if 'license' in entry else 'expression',expression))
                    licenses.append(LicenseEvidence(evidence_id=uuid5(NAMESPACE_URL,f'{digest}:{ref}:license:{i}'),expression=expression,
                        collected_at=collected_at,provenance=prov,origin=origin))
                components.append(Component(bom_ref=ref,name=component['name'],version=component.get('version'),purl=component.get('purl'),licenses=licenses))
            known_refs={c.bom_ref for c in components}
            for dependency in _list(doc.get('dependencies',[]),10000,'dependencies'):
                _obj(dependency,('ref','dependsOn'),'CycloneDX dependency')
                for target in _list(dependency.get('dependsOn',[]),10000,'dependency targets'):
                    if len(edges)>=10000: raise SBOMError('too many dependencies')
                    edges.append(Dependency(from_ref=dependency['ref'],to_ref=target))
                # Validate even an empty dependency record; no claim of completeness.
                if dependency.get('ref') not in known_refs: raise SBOMError('unresolved dependency reference')
            fmt,version='CycloneDX','1.5'
        elif doc.get('spdxVersion')=='SPDX-2.3':
            _obj(doc,('spdxVersion','SPDXID','name','dataLicense','documentNamespace','creationInfo','packages','relationships'),'SPDX document')
            for key in ('SPDXID','name','dataLicense','documentNamespace','creationInfo'):
                if key in doc: ignored.append(key)
            for package in _list(doc.get('packages',[]),5000,'packages'):
                _obj(package,('SPDXID','name','versionInfo','externalRefs','licenseDeclared','licenseConcluded'),'SPDX package')
                ref=package['SPDXID']; purls=[]; licenses=[]
                for ext in _list(package.get('externalRefs',[]),100,'external references'):
                    _obj(ext,('referenceCategory','referenceType','referenceLocator'),'SPDX external reference')
                    if 'referenceCategory' in ext: ignored.append('packages.externalRefs.referenceCategory')
                    if ext.get('referenceType')=='purl': purls.append(ext.get('referenceLocator'))
                    else: raise SBOMError('unsupported SPDX external reference')
                if len(purls)>1: raise SBOMError('ambiguous package URLs')
                for field in ('licenseDeclared','licenseConcluded'):
                    if field in package:
                        value=package[field]
                        if not isinstance(value,str) or not value.strip(): raise SBOMError('invalid license declaration')
                        statements.append((ref,field,value))
                        licenses.append(LicenseEvidence(evidence_id=uuid5(NAMESPACE_URL,f'{digest}:{ref}:{field}'),
                            expression=None if value in ('NOASSERTION','NONE') else value,collected_at=collected_at,
                            provenance=prov+'#'+field,origin=origin))
                components.append(Component(bom_ref=ref,name=package['name'],version=package.get('versionInfo'),purl=purls[0] if purls else None,licenses=licenses))
            for relation in _list(doc.get('relationships',[]),10000,'relationships'):
                _obj(relation,('spdxElementId','relationshipType','relatedSpdxElement'),'SPDX relationship')
                if relation.get('relationshipType')!='DEPENDS_ON': raise SBOMError('unsupported SPDX relationship')
                edges.append(Dependency(from_ref=relation['spdxElementId'],to_ref=relation['relatedSpdxElement']))
            fmt,version='SPDX','2.3'
        else: raise SBOMError('unsupported SBOM format or version')
        inv=Inventory(document_id=document_id,component_completeness='unknown',dependency_completeness='unknown',
            provenance=prov,collected_at=collected_at,origin=origin,components=components,dependencies=edges,vulnerability_links=[])
        return ImportedSBOM(fmt,version,digest,inv,tuple(sorted(set(ignored))),tuple(sorted(statements)))
    except SBOMError: raise
    except (KeyError,ValueError,TypeError,RecursionError): raise SBOMError('invalid SBOM data') from None
