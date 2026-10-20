import json
from pathlib import Path
import pytest
from backend.engine import analyze, simulate, validate_environment

DEMO = json.loads((Path(__file__).resolve().parents[1] / "samples/demo.json").read_text())

def test_demo_has_exposure_paths():
    result = analyze(DEMO)
    assert result["total_paths"] >= 3
    assert any(f["target"] == "secret" for f in result["findings"])

def test_remediation_removes_paths_without_mutating_original():
    before = analyze(DEMO)["total_paths"]
    outcome = simulate(DEMO, [1, 5])
    assert outcome["after"]["total_paths"] < before
    assert DEMO["edges"][1]["enabled"] is True

def test_invalid_edges_rejected():
    with pytest.raises(ValueError):
        simulate(DEMO, [999])

def test_invalid_resource_rejected():
    with pytest.raises(ValueError):
        validate_environment({"nodes": [{"id":"x", "kind":"invalid"}], "edges": []})

def test_disabled_edge_is_not_traversed():
    modified = json.loads(json.dumps(DEMO))
    modified["edges"][0]["enabled"] = False
    assert all(f["source"] != "internet" for f in analyze(modified)["findings"])

def test_cycle_terminates():
    modified = json.loads(json.dumps(DEMO))
    modified["edges"].append({"source":"role", "target":"web", "permission":"reachable"})
    assert analyze(modified)["total_paths"] >= 3
