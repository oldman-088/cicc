"""Read-only synthetic demonstration API. Never use for tenant data."""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .request_limits import ExperimentalBodyLimit
from pydantic import BaseModel

app = FastAPI(title="CICC Demo API", version="0.1.0", description="Synthetic data only. Not production ready.")
app.add_middleware(ExperimentalBodyLimit)
# Browser access is same-origin through the web application's proxy.
app.add_middleware(CORSMiddleware, allow_origins=[], allow_methods=["GET"], allow_headers=[])

class Record(BaseModel):
    id: str
    title: str
    category: str
    severity: str
    source: str
    observed_at: str
    confidence: int
    description: str
    synthetic: bool = True

RECORDS = [
    Record(id="DEMO-001", title="Suspicious infrastructure cluster", category="Infrastructure", severity="Critical", source="Synthetic exercise", observed_at="2026-10-31T09:42:00Z", confidence=78, description="Example infrastructure relationship for training; not an observed threat."),
    Record(id="DEMO-002", title="Credential phishing campaign", category="Campaign", severity="High", source="Synthetic exercise", observed_at="2026-10-30T16:15:00Z", confidence=64, description="Illustrative campaign record with no real-world attribution."),
    Record(id="DEMO-003", title="Potentially exposed service", category="Exposure", severity="Medium", source="Synthetic exercise", observed_at="2026-10-29T11:08:00Z", confidence=52, description="Example exposure requiring analyst verification."),
    Record(id="DEMO-004", title="Malware family association", category="Malware", severity="High", source="Synthetic exercise", observed_at="2026-10-28T08:23:00Z", confidence=71, description="Fictional association included for interface demonstration."),
]

@app.get('/health')
def health():
    return {"status": "ok", "mode": "synthetic-demo", "production_ready": False}

@app.get('/api/v1/overview')
def overview():
    return {"mode": "synthetic-demo", "notice": "All intelligence shown is synthetic demonstration data, not live intelligence.", "records": RECORDS, "sources": [{"name": "CISA KEV", "status": "not configured"}, {"name": "NIST NVD", "status": "not configured"}, {"name": "MITRE ATT&CK", "status": "not configured"}]}

# Disabled unless deliberately enabled with all required configuration.
import os
from .experimental_config import configure_experimental
configure_experimental(app, os.environ)
