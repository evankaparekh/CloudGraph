from fastapi.testclient import TestClient
from backend.main import app

client = TestClient(app)

def test_api_demo_analysis_and_simulation():
    environment = client.get('/api/demo').json()
    assert client.post('/api/analyze', json={'environment': environment}).status_code == 200
    response = client.post('/api/simulate', json={'environment': environment, 'disabled_edges': [1, 5]})
    assert response.status_code == 200
    assert response.json()['removed_paths'] > 0

def test_api_rejects_invalid_index():
    environment = client.get('/api/demo').json()
    assert client.post('/api/simulate', json={'environment': environment, 'disabled_edges': [999]}).status_code == 422
