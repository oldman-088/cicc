from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_health_discloses_mode():
    result = client.get('/health')
    assert result.status_code == 200
    assert result.json() == {'status': 'ok', 'mode': 'synthetic-demo', 'production_ready': False}

def test_overview_is_explicitly_synthetic_and_sources_unconfigured():
    data = client.get('/api/v1/overview').json()
    assert data['mode'] == 'synthetic-demo'
    assert 'synthetic' in data['notice'].lower()
    assert data['records'] and all(r['synthetic'] and r['source'] == 'Synthetic exercise' for r in data['records'])
    assert all(s['status'] == 'not configured' for s in data['sources'])

def test_no_mutation_endpoint():
    assert client.post('/api/v1/overview', json={}).status_code == 405
