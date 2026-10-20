from fastapi.testclient import TestClient
from backend.main import app
from backend.scoring import enrich
import json
from pathlib import Path
client=TestClient(app)
ROOT=Path(__file__).resolve().parents[1]

def test_risk_factors_match_score():
    env=json.loads((ROOT/'samples/demo.json').read_text())
    response=client.post('/api/analyze',json={'environment':env})
    assert response.status_code==200
    for finding in response.json()['findings']:
        e=finding['risk_explanation'];assert e['score']==finding['score']
        assert e['score']==min(100,sum(e['factors'].values()))

def test_pdf_report_is_real_pdf():
    env=json.loads((ROOT/'samples/demo.json').read_text())
    response=client.post('/api/report/pdf',json={'environment':env,'disabled_edges':[0]})
    assert response.status_code==200
    assert response.headers['content-type']=='application/pdf'
    assert response.content.startswith(b'%PDF-')
    assert len(response.content)>1500

def test_pdf_rejects_invalid_edge():
    env=json.loads((ROOT/'samples/demo.json').read_text())
    assert client.post('/api/report/pdf',json={'environment':env,'disabled_edges':[999]}).status_code==422

def test_pdf_linked_demo():
    data=json.loads((ROOT/'samples/linked-demo.json').read_text())
    r=client.post('/api/report/pdf',json={**data,'disabled_edges':[]})
    assert r.status_code==200 and r.content.startswith(b'%PDF-')
