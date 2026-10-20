"""CloudGraph API. Run: uvicorn backend.main:app --reload"""
from pathlib import Path
import json
from fastapi import FastAPI, HTTPException
from fastapi.responses import Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from .engine import analyze, simulate, validate_environment
from .iam import inspect_policy
from .linked import linked_analysis, linked_simulation
from .scoring import enrich
from .reports import create_report
from .importer import import_inventory

ROOT = Path(__file__).resolve().parent.parent
app = FastAPI(title="CloudGraph", version="0.5.0", description="Defensive cloud attack-path modeling demo")
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:8000", "http://127.0.0.1:8000"], allow_methods=["GET", "POST"], allow_headers=["Content-Type"])

class InventoryRequest(BaseModel):
    inventory: dict

class AnalysisRequest(BaseModel):
    environment: dict

class IAMRequest(BaseModel):
    policy: dict

class LinkedRequest(AnalysisRequest):
    policies: dict

class LinkedSimulationRequest(LinkedRequest):
    disabled_edges: list[int]

class ReportRequest(AnalysisRequest):
    policies: dict | None = None
    disabled_edges: list[int] = []

class SimulationRequest(AnalysisRequest):
    disabled_edges: list[int]

def invalid_to_http(function, *args):
    try:
        return function(*args)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

@app.get("/samples/aws-inventory.json")
def inventory_sample():
    return json.loads((ROOT / "samples" / "aws-inventory.json").read_text())

@app.post("/api/import/aws")
def import_aws(request: InventoryRequest):
    return invalid_to_http(import_inventory, request.inventory)

@app.get("/api/demo")
def demo():
    return json.loads((ROOT / "samples" / "demo.json").read_text())

@app.post("/api/analyze")
def analyze_route(request: AnalysisRequest):
    return enrich(invalid_to_http(analyze, request.environment), request.environment)

@app.post("/api/simulate")
def simulate_route(request: SimulationRequest):
    return invalid_to_http(simulate, request.environment, request.disabled_edges)

@app.get("/samples/linked-demo.json")
def linked_demo():
    return json.loads((ROOT / "samples" / "linked-demo.json").read_text())

@app.post("/api/linked/analyze")
def linked_route(request: LinkedRequest):
    return enrich(invalid_to_http(linked_analysis, request.environment, request.policies), request.environment)

@app.post("/api/linked/simulate")
def linked_sim_route(request: LinkedSimulationRequest):
    return invalid_to_http(linked_simulation, request.environment, request.policies, request.disabled_edges)

@app.get("/samples/iam-risky.json")
def iam_sample():
    return json.loads((ROOT / "samples" / "iam-risky.json").read_text())

@app.post("/api/iam/analyze")
def analyze_iam_route(request: IAMRequest):
    return invalid_to_http(inspect_policy, request.policy)

@app.post("/api/report/pdf")
def report_pdf(request: ReportRequest):
    content = invalid_to_http(create_report, request.environment, request.policies, request.disabled_edges)
    return Response(content=content, media_type="application/pdf", headers={"Content-Disposition":"attachment; filename=cloudgraph-security-report.pdf", "X-Content-Type-Options":"nosniff"})

app.mount("/", StaticFiles(directory=str(ROOT / "frontend"), html=True), name="frontend")
