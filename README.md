# CloudGraph

**Cloud security attack-path analysis and remediation simulation**

CloudGraph is a Python/FastAPI web application for exploring modeled cloud infrastructure, inspecting AWS-style IAM identity policies, identifying potential access paths, and comparing hypothetical remediation changes.

> **Scope:** This is an educational, offline security-analysis prototype. It does **not** implement AWS's complete authorization semantics and should not be used as a production cloud-security audit tool.

## Features

- Interactive cloud resource and relationship graph
- AWS-style IAM JSON policy inspector
- Simplified IAM-linked potential attack-path analysis
- Offline AWS-style inventory JSON importer
- Explainable risk scoring
- Simulated removal of risky graph connections
- Exportable PDF assessment reports
- Automated Python tests

## Run locally

Requires Python 3.

```bash
python -m pip install -r requirements.txt
python -m uvicorn backend.main:app --reload
```

Open http://127.0.0.1:8000 in your browser.

On Windows, use `py -m pip` and `py -m uvicorn` if the `python` command is unavailable.

## Run tests

```bash
python -m pytest -q
```

## Demo

The `samples/` folder contains synthetic, non-sensitive example infrastructure and IAM policies. Use the dashboard's sample-load actions to explore the analyzer and remediation simulator.

## Architecture

```text
Browser UI (frontend/)
      |
      v
FastAPI (backend/main.py)
      |-- Infrastructure graph engine (engine.py)
      |-- IAM policy inspector (iam.py)
      |-- IAM-linked path model (linked.py)
      |-- Inventory importer (importer.py)
      |-- Risk scoring (scoring.py)
      '-- PDF reporting (reports.py)
```

## Security and accuracy limitations

CloudGraph uses a simplified offline resource and authorization model. Results describe **potential modeled paths**, not verified exploitability. AWS IAM decisions also depend on context, resource-based policies, permission boundaries, service control policies, trust relationships, conditions, and other rules that this prototype does not comprehensively model.

Do not upload real credentials, secret values, or sensitive production configuration exports to public repositories.

## Roadmap

- [ ] Support selected native AWS Config export schemas
- [ ] Improve IAM condition and trust-policy modeling
- [ ] Add more validation fixtures and false-positive measurements
- [ ] Add screenshots and a short recorded demo
- [ ] Expand remediation comparisons

## License

No license has been selected yet. Add one if you intend to permit reuse.
