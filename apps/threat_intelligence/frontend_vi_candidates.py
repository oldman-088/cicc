"""Read-only, versioned local presentation candidates; NOT mounted host APIs."""
from typing import Any, Literal
from pydantic import BaseModel, ConfigDict, Field
from .sbom_ingestion import ImportedSBOM

class Candidate(BaseModel):
    model_config=ConfigDict(extra='forbid',frozen=True)

class QualityFinding(Candidate):
    classification: Literal['unknown','missing_evidence','stale_evidence','conflict']
    code: str
    subject: dict[str,str]
    evidence_ids: list[str]

class QualityCandidate(Candidate):
    schema_version: Literal['cicc.vulnerability-quality/1']
    purpose: Literal['evidence_quality_only']
    findings: list[QualityFinding]
    evidence: dict[str,Any] # The v1 evidence body is described by QualityReport plus derived fields.

class SbomCandidate(Candidate):
    schema_version: Literal['cicc.vi.sbom-summary/1']
    format: Literal['SPDX','CycloneDX']
    version: str
    source_sha256: str = Field(pattern=r'^[a-f0-9]{64}$')
    inventory: dict[str,Any] # Document remains caller-scoped; detailed model is Inventory.
    ignored_fields: list[str]
    license_statements: list[tuple[str,str,str]]

class ConflictCandidate(Candidate):
    schema_version: Literal['cicc.kev-conflict-summary/1']
    conflict_id: int = Field(gt=0)
    previous_snapshot_id: int = Field(gt=0)
    origin: Literal['EXPERIMENTAL_DEMO_DATA_ONLY','FETCHED_FROM_GITHUB_CISA_REPO']
    observed_at: str
    release_at: str
    previous_collected_at: str
    candidate_collected_at: str
    previous_sha256: str = Field(pattern=r'^[a-f0-9]{64}$')
    candidate_sha256: str = Field(pattern=r'^[a-f0-9]{64}$')
    previous_blob_sha: str = Field(pattern=r'^[a-f0-9]{40}$')
    candidate_blob_sha: str = Field(pattern=r'^[a-f0-9]{40}$')
    metadata_fields_changed: list[str]
    added_cves: list[str]
    removed_cves: list[str]
    changed_cves: list[str]

class ResolutionAvailabilityCandidate(Candidate):
    schema_version: Literal['cicc.vi.resolution-availability/1']
    status: Literal['not_implemented']
    persistent_history_available: Literal[False]
    note: str


def sbom_summary(imported: ImportedSBOM, *, schema_version: str) -> dict:
    if schema_version!='cicc.vi.sbom-summary/1': raise ValueError('unsupported SBOM summary version')
    if not isinstance(imported,ImportedSBOM): raise ValueError('imported SBOM required')
    inv=imported.inventory.model_validate(imported.inventory.model_dump())
    return SbomCandidate(schema_version=schema_version,format=imported.format,version=imported.version,
        source_sha256=imported.source_sha256,inventory=inv.model_dump(mode='json'),
        ignored_fields=list(imported.ignored_fields),license_statements=list(imported.license_statements)).model_dump(mode='json')


def resolution_availability(*, schema_version: str) -> dict:
    if schema_version!='cicc.vi.resolution-availability/1': raise ValueError('unsupported resolution availability version')
    return ResolutionAvailabilityCandidate(schema_version=schema_version,status='not_implemented',persistent_history_available=False,
        note='No persistent resolution status or trusted audit is implemented.').model_dump(mode='json')

# Candidate-only frontend representation of supplied source evidence; no new route.
from .vi_evidence_ingestion import SourceEvidence

class EvidenceObservationCandidate(Candidate):
    evidence: SourceEvidence
    collection_age_seconds: float
    collection_age_status: Literal['future','stale','within_window']
    source_modified_status: Literal['unknown','future','supplied']
    score_date_age_days: int | None
    score_date_status: Literal['unknown','future','supplied']

class DuplicateContentCandidate(Candidate):
    origin: Literal['EXPERIMENTAL_DEMO_DATA_ONLY','CALLER_SUPPLIED_UNVERIFIED']
    source: Literal['NVD','OSV','GHSA','EPSS']
    source_record_id: str
    source_sha256: str
    observation_count: int

class SourceConflictCandidate(Candidate):
    origin: Literal['EXPERIMENTAL_DEMO_DATA_ONLY','CALLER_SUPPLIED_UNVERIFIED']
    source: Literal['NVD','EPSS']
    source_record_id: str
    revision: str
    metric: str
    issuer: str
    differing_fields: dict[str,list[str]]

class SourceEvidenceBatchCandidate(Candidate):
    schema_version: Literal['cicc.vi.source-evidence-batch/1']
    as_of: str
    max_collection_age_seconds: float
    observations: list[EvidenceObservationCandidate]
    duplicate_content: list[DuplicateContentCandidate]
    same_revision_conflicts: list[SourceConflictCandidate]
    interpretation: str

# M54 local source-to-asset trace; no HTTP contract or authorization implied.
from .vi_asset_correlation import AssetBinding
from .vulnerability_quality import Component, VulnerabilityLink

class TraceAgeCandidate(Candidate):
    age_seconds: float
    age_status: Literal['within_window','outside_window','future_collection_time']

class TraceObservationCandidate(EvidenceObservationCandidate):
    byte_consistency: Literal['consistent_with_supplied_bytes','not_checked']

class TraceLinkCandidate(Candidate):
    declared_link: VulnerabilityLink
    link_age_seconds: float
    link_age_status: Literal['within_window','outside_window','future_collection_time']
    component: Component
    source_observations: list[TraceObservationCandidate]
    source_observation_state: Literal['observed','unknown']

class TraceResultCandidate(Candidate):
    binding: AssetBinding
    binding_age: TraceAgeCandidate
    inventory_provenance: str
    inventory_origin: Literal['EXPERIMENTAL_DEMO_DATA_ONLY','CALLER_SUPPLIED_UNVERIFIED']
    inventory_collected_at: str
    inventory_age: TraceAgeCandidate
    inventory_completeness: Literal['declared_complete','declared_incomplete','unknown']
    dependency_completeness: Literal['declared_complete','declared_incomplete','unknown']
    links: list[TraceLinkCandidate]
    applicability: Literal['unknown']
    exposure: Literal['unknown']

class AssetSourceTraceCandidate(Candidate):
    schema_version: Literal['cicc.vi.asset-source-trace/1']
    as_of: str
    max_collection_age_seconds: float
    results: list[TraceResultCandidate]
    interpretation: str
