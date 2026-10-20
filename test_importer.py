import json
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from backend.importer import import_inventory
from backend.main import app
from backend.linked import linked_analysis

SAMPLE = json.loads((Path(__file__).resolve().parents[1]/'samples/aws-inventory.json').read_text())

def test_import_inventory_nodes_and_edges():
    result = import_inventory(SAMPLE)
    assert result['counts'] == {'roles':1,'resources':3,'instances':1}
    assert len(result['environment']['nodes']) == 6
    assert any(e['source']=='internet' for e in result['environment']['edges'])

def test_imported_paths():
    result = import_inventory(SAMPLE)
    assessment = linked_analysis(result['environment'],result['policies'])
    assert assessment['total_paths'] == 2

def test_explicit_deny_filters_resource():
    data = json.loads(json.dumps(SAMPLE))
    data['roles'][0]['policy']['Statement'].append({'Effect':'Deny','Action':'secretsmanager:GetSecretValue','Resource':'*'})
    result = import_inventory(data)
    assert not any(e['target'].startswith('secret:') for e in result['environment']['edges'])

def test_no_public_ingress():
    data = json.loads(json.dumps(SAMPLE))
    data['instances'][0]['public_ip'] = False
    result = import_inventory(data)
    assert not any(e['source']=='internet' for e in result['environment']['edges'])

def test_reject_unknown_role():
    data = json.loads(json.dumps(SAMPLE))
    data['instances'][0]['role'] = 'missing'
    with pytest.raises(ValueError,match='Unknown instance role'): import_inventory(data)

def test_reject_duplicate_resource():
    data = json.loads(json.dumps(SAMPLE))
    data['roles'].append(data['roles'][0])
    with pytest.raises(ValueError,match='Duplicate'): import_inventory(data)

def test_api_import():
    response = TestClient(app).post('/api/import/aws',json={'inventory':SAMPLE})
    assert response.status_code == 200
    assert response.json()['counts']['roles'] == 1

def test_invalid_schema_api():
    response = TestClient(app).post('/api/import/aws',json={'inventory':{'format':'wrong'}})
    assert response.status_code == 422
