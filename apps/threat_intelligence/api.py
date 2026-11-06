"""
Threat Intelligence API Implementation & Mounting (P1-05 + P2-01)

API schemas, mounting interface, handlers for:
- actors, malware, campaigns, ttps, mitre
- relationships, enrichment, collection
- mitre-ingestion, cisa-kev, vendor-advisories, osint-sources
- source-adapters, relationship-analysis (P2-01)

Integration:
- Agent 1 Coordination Gateway contract (Agent1CoordinationContract)
- Agent 4 Frontend contract (Agent4FrontendContract)

Author: Arena.ai Agent Mode (Threat Intelligence Domain)
Date: 2026-11-06
Version: 1.0
Experimental Label: EXPERIMENTAL_DEMO_DATA_ONLY
"""

from datetime import datetime
from typing import List, Optional, Dict, Any
from uuid import UUID, uuid4
from pydantic import BaseModel, ConfigDict, Field, field_validator
from fastapi import FastAPI, APIRouter, HTTPException, Request
import logging

# Experimental data labeling constant
EXPERIMENTAL_DEMO_DATA_ONLY = "EXPERIMENTAL_DEMO_DATA_ONLY"

# Configure logging
logger = logging.getLogger(__name__)

# Fail explicitly if the relationship engine is unavailable; never substitute mocks.
from apps.threat_intelligence.relationship_analysis import (
    RelationshipAnalysisEngine, RelationshipType, RelationshipConfidence,
    RelationshipEvidence, EntityReference, RelationshipRecord,
)


# --- API SCHEMAS (P1-05 + P2-01) ---

class ThreatIntelligenceRequest(BaseModel):
    """Base request schema for Threat Intelligence API endpoints"""
    model_config = ConfigDict(extra="forbid")

    tenant_id: Optional[str] = Field(None, description="Tenant isolation identifier")
    query: Optional[str] = Field(None, description="Search query or filter criteria")
    limit: int = Field(100, ge=1, le=1000, description="Pagination limit")
    offset: int = Field(0, ge=0, description="Pagination offset")
    experimental_label: Optional[str] = Field(None, description="Experimental data label")

    @field_validator('experimental_label')
    @classmethod
    def validate_experimental_label(cls, v):
        if v is not None and v != EXPERIMENTAL_DEMO_DATA_ONLY:
            raise ValueError("Experimental label must be EXPERIMENTAL_DEMO_DATA_ONLY or None")
        return v

class ThreatIntelligenceResponse(BaseModel):
    """Base response schema for Threat Intelligence API endpoints"""
    model_config = ConfigDict(extra="forbid")

    status: str = Field(..., description="Response status (success, error)")
    data: Optional[List[Dict[str, Any]]] = Field(None, description="Payload data")
    total_count: int = Field(0, ge=0, description="Total records available")
    has_more: bool = Field(False, description="Pagination indicator")
    provenance: str = Field(..., description="Provenance chain")
    confidence: float = Field(1.0, ge=0.0, le=1.0, description="Confidence score")
    experimental_label: Optional[str] = Field(None, description="Experimental data label")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Response timestamp")

    @field_validator('experimental_label')
    @classmethod
    def validate_experimental_label(cls, v):
        if v is not None and v != EXPERIMENTAL_DEMO_DATA_ONLY:
            raise ValueError("Experimental label must be EXPERIMENTAL_DEMO_DATA_ONLY or None")
        return v

# Relationship Analysis Schemas (P2-01)

class EntityReferenceSchema(BaseModel):
    """Schema for entity reference in API requests"""
    model_config = ConfigDict(extra="forbid")

    entity_id: str = Field(..., description="Unique entity identifier")
    entity_type: str = Field(..., description="Entity type")
    name: Optional[str] = Field(None, description="Entity name")
    experimental_label: str = Field(default=EXPERIMENTAL_DEMO_DATA_ONLY, description="Experimental data labeling")

class RelationshipEvidenceSchema(BaseModel):
    """Schema for relationship evidence in API requests"""
    model_config = ConfigDict(extra="forbid")

    source: str = Field(..., description="Source attribution")
    description: str = Field(..., description="Evidence description")
    confidence: str = Field(..., description="Confidence level (LOW, MEDIUM, HIGH, CONFIRMED, INFERRED)")
    provenance: str = Field(..., description="Provenance tracking")
    experimental_label: str = Field(default=EXPERIMENTAL_DEMO_DATA_ONLY, description="Experimental data labeling")

class RelationshipSchema(BaseModel):
    """Schema for relationship creation in API requests"""
    model_config = ConfigDict(extra="forbid")

    source_entity: EntityReferenceSchema = Field(..., description="Source entity")
    target_entity: EntityReferenceSchema = Field(..., description="Target entity")
    relationship_type: str = Field(..., description="Relationship type")
    confidence: str = Field(..., description="Confidence level")
    evidence: List[RelationshipEvidenceSchema] = Field(default_factory=list, description="Supporting evidence")
    provenance: str = Field(..., description="Provenance tracking")
    temporal_context: Optional[Dict[str, Any]] = Field(None, description="Temporal context")
    confirmed: bool = Field(default=False, description="Confirmed vs inferred")
    conflicting_intelligence: Optional[List[Dict[str, Any]]] = Field(
        None, description="Preserved conflicting intelligence"
    )
    experimental_label: str = Field(default=EXPERIMENTAL_DEMO_DATA_ONLY, description="Experimental data labeling")

class RelationshipAnalysisRequest(BaseModel):
    """Schema for relationship analysis requests"""
    model_config = ConfigDict(extra="forbid")

    entity_id: str = Field(..., description="Entity identifier")
    entity_type: str = Field(..., description="Entity type")
    max_depth: Optional[int] = Field(3, description="Maximum traversal depth")
    relationship_types: Optional[List[str]] = Field(None, description="Filter by relationship types")
    experimental_label: str = Field(default=EXPERIMENTAL_DEMO_DATA_ONLY, description="Experimental data labeling")

class CampaignCorrelationRequest(BaseModel):
    """Schema for campaign correlation requests"""
    model_config = ConfigDict(extra="forbid")

    campaign_ids: List[str] = Field(..., description="Campaign identifiers")
    temporal_window: Optional[Dict[str, datetime]] = Field(None, description="Temporal window")
    experimental_label: str = Field(default=EXPERIMENTAL_DEMO_DATA_ONLY, description="Experimental data labeling")

class IntelligenceGraphRequest(BaseModel):
    """Schema for intelligence graph preparation requests"""
    model_config = ConfigDict(extra="forbid")

    entity_ids: List[str] = Field(..., description="Entity identifiers")
    entity_types: List[str] = Field(..., description="Entity types")
    experimental_label: str = Field(default=EXPERIMENTAL_DEMO_DATA_ONLY, description="Experimental data labeling")


# --- API MOUNTING INTERFACE (P1-05 + P2-01) ---

class ThreatIntelligenceAPI:
    """
    Threat Intelligence API Implementation & Mounting (P1-05 + P2-01)
    Integrates with Agent 1 Coordination Gateway and Agent 4 Frontend Contract.
    """

    def __init__(self, tenant_id: Optional[str] = None, experimental_label: Optional[str] = EXPERIMENTAL_DEMO_DATA_ONLY):
        self.tenant_id = tenant_id
        # Legacy dispatcher is demo-only, including when callers omit a label.
        self.experimental_label = EXPERIMENTAL_DEMO_DATA_ONLY
        self.provenance = "threat_intelligence_api_v1"
        self.confidence = 1.0  # Internal API confidence

        # Integration contracts
        self.agent_1_gateway_contract = "agent_1_coordination_v1"
        self.agent_4_frontend_contract = "agent_4_frontend_v1"

        # Initialize P2-01 Relationship Analysis Engine
        self.relationship_engine = RelationshipAnalysisEngine()

        # Mount points (simulated for P1-05 + P2-01)
        self._mounted_endpoints = {
            "/api/v1/threat-intelligence/actors": self._handle_actors,
            "/api/v1/threat-intelligence/malware": self._handle_malware,
            "/api/v1/threat-intelligence/campaigns": self._handle_campaigns,
            "/api/v1/threat-intelligence/ttps": self._handle_ttps,
            "/api/v1/threat-intelligence/mitre": self._handle_mitre,
            "/api/v1/threat-intelligence/relationships": self._handle_relationships,
            "/api/v1/threat-intelligence/enrichment": self._handle_enrichment,
            "/api/v1/threat-intelligence/collection": self._handle_collection,
            "/api/v1/threat-intelligence/mitre-ingestion": self._handle_mitre_ingestion,
            "/api/v1/threat-intelligence/cisa-kev": self._handle_cisa_kev,
            "/api/v1/threat-intelligence/vendor-advisories": self._handle_vendor_advisories,
            "/api/v1/threat-intelligence/osint-sources": self._handle_osint_sources,
            "/api/v1/threat-intelligence/source-adapters": self._handle_source_adapter,
            "/api/v1/threat-intelligence/relationship-analysis/traverse": self._handle_relationship_traversal,
            "/api/v1/threat-intelligence/campaign-correlation": self._handle_campaign_correlation,
            "/api/v1/threat-intelligence/intelligence-graph": self._handle_intelligence_graph,
            "/api/v1/threat-intelligence/relationship-analysis/resolve-conflict": self._handle_conflict_resolution,
            "/api/v1/threat-intelligence/threat-activity-timeline": self._handle_threat_activity_timeline,
        }

        # Security boundaries
        self._validation_enabled = True
        self._provenance_tracking = True
        self._audit_logging = True
        self._idempotency_enabled = True
        self._duplicate_detection = True

    def mount_endpoint(self, path: str, handler_func) -> bool:
        """Mount a new endpoint to the Threat Intelligence API (Agent 1/4 coordination)"""
        if not self._validation_enabled:
            raise SecurityError("Input validation disabled - security violation")

        self._mounted_endpoints[path] = handler_func
        self._log_ingestion_event("api_mount", path)
        return True

    def invoke_endpoint(self, path: str, request: ThreatIntelligenceRequest) -> ThreatIntelligenceResponse:
        """Invoke endpoint through the intended CICC integration path (Agent 1 gateway)"""
        self._validate_security_boundaries()

        if path not in self._mounted_endpoints:
            return ThreatIntelligenceResponse(
                status="error",
                data=None,
                total_count=0,
                has_more=False,
                provenance=self.provenance,
                confidence=self.confidence,
                experimental_label=self.experimental_label,
                timestamp=datetime.utcnow()
            ).model_dump()

        # Execute handler (Agent 1 coordination lifecycle)
        handler = self._mounted_endpoints[path]
        result_data = handler(request)

        # Agent 4 frontend contract compatibility
        response = ThreatIntelligenceResponse(
            status="success",
            data=result_data.get("data", []),
            total_count=result_data.get("total_count", 0),
            has_more=result_data.get("has_more", False),
            provenance=f"{self.provenance}::{path}",
            confidence=self.confidence,
            experimental_label=self.experimental_label,
            timestamp=datetime.utcnow()
        )

        self._log_ingestion_event("api_invocation", path)
        return response.model_dump()

    # --- HANDLERS (Integration with existing modules) ---

    def _handle_actors(self, request: ThreatIntelligenceRequest) -> Dict[str, Any]:
        """Handle Threat Actor Intelligence requests (Agent 1/4 contract)"""
        return {"data": [{"actor_id": "TA-001", "name": "Experimental Actor", "label": self.experimental_label}], "total_count": 1, "has_more": False}

    def _handle_malware(self, request: ThreatIntelligenceRequest) -> Dict[str, Any]:
        """Handle Malware Intelligence requests"""
        return {"data": [{"malware_id": "MW-001", "family": "Experimental Family", "label": self.experimental_label}], "total_count": 1, "has_more": False}

    def _handle_campaigns(self, request: ThreatIntelligenceRequest) -> Dict[str, Any]:
        """Handle Campaign Intelligence requests"""
        return {"data": [{"campaign_id": "CMP-001", "name": "Experimental Campaign", "label": self.experimental_label}], "total_count": 1, "has_more": False}

    def _handle_ttps(self, request: ThreatIntelligenceRequest) -> Dict[str, Any]:
        """Handle TTP Intelligence requests"""
        return {"data": [{"ttp_id": "TTP-001", "technique": "Experimental Technique", "label": self.experimental_label}], "total_count": 1, "has_more": False}

    def _handle_mitre(self, request: ThreatIntelligenceRequest) -> Dict[str, Any]:
        """Handle MITRE ATT&CK Mapping requests"""
        return {"data": [{"technique_id": "T1000", "name": "Experimental MITRE", "label": self.experimental_label}], "total_count": 1, "has_more": False}

    def _handle_relationships(self, request: ThreatIntelligenceRequest) -> Dict[str, Any]:
        """Handle Relationship Layer requests (Agent 1/4 contract) - P2-01 integration"""
        # Integration with apps/threat_intelligence/relationship_analysis.py (P2-01)
        return {"data": [{"relationship_id": "REL-001", "type": "ATTRIBUTED_TO", "label": self.experimental_label}], "total_count": 1, "has_more": False}

    def _handle_enrichment(self, request: ThreatIntelligenceRequest) -> Dict[str, Any]:
        """Handle Intelligence Enrichment requests"""
        return {"data": [{"enrichment_id": "ENR-001", "source": "Experimental", "label": self.experimental_label}], "total_count": 1, "has_more": False}

    def _handle_collection(self, request: ThreatIntelligenceRequest) -> Dict[str, Any]:
        """Handle Intelligence Collection/Normalization requests"""
        return {"data": [{"collection_id": "COL-001", "status": "completed", "label": self.experimental_label}], "total_count": 1, "has_more": False}

    def _handle_mitre_ingestion(self, request: ThreatIntelligenceRequest) -> Dict[str, Any]:
        """Handle MITRE Ingestion Pipeline requests (P1-01 integration)"""
        return {"data": [{"pipeline_id": "MITRE-001", "status": "simulated", "label": self.experimental_label}], "total_count": 1, "has_more": False}

    def _handle_cisa_kev(self, request: ThreatIntelligenceRequest) -> Dict[str, Any]:
        """Handle CISA KEV Integration Connector requests (P1-02 integration)"""
        return {"data": [{"connector_id": "KEV-001", "status": "simulated", "label": self.experimental_label}], "total_count": 1, "has_more": False}

    def _handle_vendor_advisories(self, request: ThreatIntelligenceRequest) -> Dict[str, Any]:
        """Handle Vendor Security Advisories Integration requests (P1-03 integration)"""
        return {"data": [{"framework_id": "VEND-001", "status": "simulated", "label": self.experimental_label}], "total_count": 1, "has_more": False}

    def _handle_osint_sources(self, request: ThreatIntelligenceRequest) -> Dict[str, Any]:
        """Handle OSINT Intelligence Sources Integration requests (P1-04 integration)"""
        return {"data": [{"source_id": "OSINT-001", "status": "simulated", "label": self.experimental_label}], "total_count": 1, "has_more": False}

    def _handle_source_adapter(self, request: ThreatIntelligenceRequest) -> Dict[str, Any]:
        """Handle Source Adapter Foundation requests (P1-05 Advancement)"""
        return {"data": [{"adapter_id": "ADAPT-001", "status": "simulated", "label": self.experimental_label, "network_access_blocked": True}], "total_count": 1, "has_more": False}

    # --- P2-01 RELATIONSHIP ANALYSIS HANDLERS ---

    def _handle_relationship_traversal(self, request: ThreatIntelligenceRequest) -> Dict[str, Any]:
        """Handle relationship traversal analysis (P2-01)"""
        # Integration with apps/threat_intelligence/relationship_analysis.py (P2-01)
        result = self.relationship_engine.traverse_relationships(
            start_entity_id="TA-001",  # Simulated from request
            start_entity_type="ThreatActor",  # Simulated from request
            max_depth=3
        )
        return {"data": [result], "total_count": 1, "has_more": False, "label": self.experimental_label}

    def _handle_campaign_correlation(self, request: ThreatIntelligenceRequest) -> Dict[str, Any]:
        """Handle campaign correlation analysis (P2-01)"""
        result = self.relationship_engine.correlate_campaigns(
            campaign_ids=["CMP-001"],  # Simulated from request
            temporal_window=None
        )
        return {"data": [result], "total_count": 1, "has_more": False, "label": self.experimental_label}

    def _handle_intelligence_graph(self, request: ThreatIntelligenceRequest) -> Dict[str, Any]:
        """Handle intelligence graph preparation (P2-01)"""
        result = self.relationship_engine.prepare_intelligence_graph(
            entity_ids=["TA-001", "MW-001"],  # Simulated from request
            entity_types=["ThreatActor", "Malware"]
        )
        return {"data": [result], "total_count": 1, "has_more": False, "label": self.experimental_label}

    def _handle_conflict_resolution(self, request: ThreatIntelligenceRequest) -> Dict[str, Any]:
        """Handle conflicting intelligence resolution (P2-01)"""
        result = self.relationship_engine.resolve_conflicting_intelligence(UUID("00000000-0000-0000-0000-000000000000"))
        return {"data": [result], "total_count": 1, "has_more": False, "label": self.experimental_label}

    def _handle_threat_activity_timeline(self, request: ThreatIntelligenceRequest) -> Dict[str, Any]:
        """Handle threat activity timeline generation (P2-01)"""
        result = self.relationship_engine.generate_threat_activity_timeline(
            entity_id="TA-001",  # Simulated from request
            entity_type="ThreatActor"
        )
        return {"data": [result], "total_count": 1, "has_more": False, "label": self.experimental_label}

    # --- SECURITY & INTEGRATION METHODS ---

    def _validate_security_boundaries(self) -> None:
        """Validate security and data integrity boundaries (Agent 1/4 requirement)"""
        if not self._validation_enabled:
            raise SecurityError("Input validation disabled - security violation")
        if not self._provenance_tracking:
            raise SecurityError("Provenance tracking disabled - security violation")
        if not self._audit_logging:
            raise SecurityError("Audit logging disabled - security violation")

    def _log_ingestion_event(self, event_type: str, entity_id: str) -> None:
        """Audit logging for API events (security requirement)"""
        # In production: write to audit log system and Agent 1 coordination
        pass

    def validate_external_request(self, request: ThreatIntelligenceRequest) -> bool:
        """Validate external API request (security measure)"""
        if not isinstance(request, ThreatIntelligenceRequest):
            raise ValueError("Invalid request format - must be ThreatIntelligenceRequest")

        # Check for malicious content patterns (simulated)
        if request.query and "malicious" in str(request.query).lower() and "test" not in str(request.query).lower():
            raise SecurityError("Malicious content detected in external request")

        return True

    def handle_malformed_request(self, error: Exception) -> Dict[str, Any]:
        """Handle malformed API request safely (security measure)"""
        # Safe error handling without exposing sensitive information
        # Audit logging of error event (Agent 1 coordination)
        return ThreatIntelligenceResponse(
            status="error",
            data=None,
            total_count=0,
            has_more=False,
            provenance=self.provenance,
            confidence=self.confidence,
            experimental_label=self.experimental_label,
            timestamp=datetime.utcnow()
        ).model_dump()

# --- INTEGRATION CONTRACTS (Agent 1 & Agent 4) ---

class Agent1CoordinationContract:
    """Contract compatibility with Agent 1 (Coordination & Domain Gateway)"""

    @staticmethod
    def register_domain_gateway(api: ThreatIntelligenceAPI) -> bool:
        """Register Threat Intelligence domain with Agent 1 Coordination Gateway"""
        # Simulated registration (Agent 1 ownership boundary)
        # In production: actual gateway registration via shared contract
        return True

    @staticmethod
    def invoke_through_gateway(path: str, request: ThreatIntelligenceRequest) -> ThreatIntelligenceResponse:
        """Invoke through Agent 1 Coordination Gateway (P1-05 requirement)"""
        api = ThreatIntelligenceAPI(tenant_id=request.tenant_id, experimental_label=request.experimental_label)
        return api.invoke_endpoint(path, request)


class Agent4FrontendContract:
    """Contract compatibility with Agent 4 (Frontend Integration)"""

    @staticmethod
    def validate_frontend_response(response: Dict[str, Any]) -> bool:
        """Validate response format for Agent 4 frontend consumption"""
        # Required fields for Agent 4: status, data, total_count, provenance, experimental_label
        required_fields = ["status", "data", "total_count", "provenance", "experimental_label"]
        for field in required_fields:
            if field not in response:
                return False
        return True

# --- SECURITY ERROR ---

class SecurityError(Exception):
    """Security violation exception for API boundaries"""
    pass

# --- FASTAPI ROUTER & APP (P1-05 + P2-01 MOUNTING) ---

from apps.threat_intelligence.relationship_api import router
app = FastAPI(title="CICC Threat Intelligence API", version="1.0.0")

# Avoid echoing untrusted input or credentials in validation responses. Host apps
# mounting the router must install an equivalent handler.
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

@app.exception_handler(Exception)
async def internal_error_handler(request: Request, exc: Exception):
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})

@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(status_code=422, content={"detail": "Invalid request"})

# Mount router to app
app.include_router(router)

# Export components
__all__ = [
    "ThreatIntelligenceAPI",
    "ThreatIntelligenceRequest",
    "ThreatIntelligenceResponse",
    "Agent1CoordinationContract",
    "Agent4FrontendContract",
    "SecurityError",
    "router",
    "app",
    "EXPERIMENTAL_DEMO_DATA_ONLY"
]
