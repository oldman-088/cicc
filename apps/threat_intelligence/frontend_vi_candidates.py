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
