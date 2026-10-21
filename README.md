# CloudGraph — Cloud Security Digital Twin

CloudGraph is an educational, offline cloud security analysis application. It visualizes synthetic AWS-style infrastructure, inspects IAM identity policies, models potential access paths, and simulates remediation.

> **Important:** CloudGraph does not implement full AWS authorization semantics yet. Findings are illustrative potential paths, not verified exploitability or a production cloud audit.

## Features
- Interactive infrastructure graph and path analysis
- IAM JSON policy inspection and simplified IAM-linked path modeling
- Offline AWS-style inventory JSON importer
- Risk scoring and simulated remediation comparisons
- PDF assessment reports
- Python unit/API tests and GitHub Actions CI

## Quick start
Requires Python 3.10+.

```bash
python -m pip install -r requirements.txt
python -m uvicorn backend.main:app --reload
```

On Windows, substitute `py` for `python` if needed. Visit http://127.0.0.1:8000.

## Tests
```bash
python -m pytest -q
```

## Repository layout
- `backend/`: FastAPI, IAM inspection, graph analysis, inventory importer, PDF reporting
- `frontend/`: HTML, CSS and JavaScript dashboard
- `samples/`: fictional example data
- `tests/`: automated tests
- `.github/workflows/tests.yml`: continuous integration

## Limitations
The importer uses a defined offline AWS-style JSON inventory, **not** native AWS Config exports. Policy evaluation does not comprehensively model trust policies, resource-based policies, SCPs, permission boundaries, session policies, conditions, or effective AWS authorization. Scores are illustrative.

Do not commit credentials, secret values, or confidential production exports.

## Next steps
- Support selected native AWS Config export schemas
- Improve IAM condition and role-trust modeling
- Expand fixtures, edge cases and evaluation metrics

