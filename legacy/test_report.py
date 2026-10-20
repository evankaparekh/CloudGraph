import json
from pathlib import Path
from fastapi.testclient import TestClient
from backend.main import app
from backend.report import risk_summary
from backend.engine import analyze

ROOT = Path(__file__).resolve().parents[1]
ENV = json.loads((ROOT / 'samples/demo.json').read_text())
client = TestClient(app)

def test_risk_summary():
    summary = risk_summary(analyze(ENV))
    assert 0 <= summary['highest_score'] <= 100
    assert summary['total_paths'] >= 0
    assert 'CVSS' in summary['method']

def test_pdf_export():
    response = client.post('/api/report', json={'environment': ENV, 'disabled_edges': []})
    assert response.status_code == 200
    assert response.content.startswith(b'%PDF-')
    assert len(response.content) > 1000
    assert response.headers['content-type'] == 'application/pdf'

def test_invalid_edge_report():
    response = client.post('/api/report', json={'environment': ENV, 'disabled_edges': [9999]})
    assert response.status_code == 422

def test_summary_endpoint():
    response = client.post('/api/risk-summary', json={'environment': ENV})
    assert response.status_code == 200
    assert 'highest_score' in response.json()
