## CloudGraph v0.4: IAM-linked graph analysis

The **IAM-linked attack paths** panel loads `samples/linked-demo.json`, which annotates graph edges with `iam_action` and `iam_resource` and maps role node IDs to sample identity policies. Click **Load linked demo**, then **Analyze IAM-linked paths**. Check graph edges and click **Simulate checked edge removals** to compare modeled paths before/after.

New endpoints: `POST /api/linked/analyze` with `{"environment": {...}, "policies": {"role_node_id": {"Statement": [...]}}}`; `POST /api/linked/simulate` with the same payload plus `"disabled_edges": [0]`.

**Interpretation:** An unconditional matching identity-policy Allow is labeled *potential*, never proof of effective authorization. Matching explicit Deny and absence of matching Allow exclude an IAM-annotated edge from this limited model. Conditional/unsupported statements produce *unknown* and are excluded from modeled paths rather than incorrectly asserting access. Edges without IAM annotations retain the original synthetic reachability assumption. This is not AWS IAM evaluation: trust policies, resource policies, SCPs, permission boundaries, session policies, principal context, action-resource semantics and many other AWS controls are not modeled. Scores remain illustrative. Do not use findings as proof of exploitable access or the absence of risk.

Run tests with `py -m pytest -q` (install `requirements.txt` first). This release adds six IAM-linkage tests.

---

# CloudGraph · Cloud Security Digital Twin

An interactive **defensive security** prototype that analyzes synthetic AWS-style resource graphs, identifies modeled access paths to sensitive resources, and simulates remediation by disabling relationships. Designed as a portfolio project and educational demonstration.

> **Scope:** This is not an AWS scanner or a validated exploitability assessment. It does not call AWS APIs, execute attack steps, or claim CVSS-compliant scores. All demo entities are fictional.

## Features

- FastAPI backend with input validation and JSON REST endpoints
- Graph traversal with cycle avoidance, depth limit, and deterministic finding ordering
- Exposure-path findings with illustrative severity scores
- Interactive SVG graph and remediation toggles
- Before/after path comparison without modifying original data
- Upload your own JSON graph (up to 250 nodes / 2,000 edges)
- Automated unit and API tests; Docker support; GitHub Actions CI

## Quick start

Requires Python 3.10+.

```bash
python -m venv .venv
# macOS/Linux: source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn backend.main:app --reload
```

Open **http://127.0.0.1:8000**. API docs: **http://127.0.0.1:8000/docs**.

Run tests:

```bash
pytest -q
```

Or use Docker:

```bash
docker build -t cloudgraph .
docker run --rm -p 8000:8000 cloudgraph
```

## Data model

See [`samples/demo.json`](samples/demo.json). `nodes` have unique `id`, `kind`, optional `label`, `sensitive`, and `compromised`. `edges` have `source`, `target`, `permission`, and optional `enabled` (defaults to true). Supported permissions: `reachable`, `assume-role`, `read`, `write`, `admin`.

The graph is intentionally simplified: an enabled directed edge is modeled as traversable, regardless of its permission label. **Real AWS effective access** depends on IAM policy evaluation, explicit denies, SCPs, resource policies, network paths, trust policies, conditions, and more. Future versions should implement those semantics before any real-world risk claim.

## API

- `GET /api/demo` — sample environment
- `POST /api/analyze` — `{ "environment": { ... } }`
- `POST /api/simulate` — `{ "environment": { ... }, "disabled_edges": [1, 5] }`

## Architecture

```text
Browser (HTML/CSS/JS + SVG graph)
       │ JSON requests
       ▼
FastAPI (input validation)
       │
       ▼
Graph engine (BFS-like path enumeration, severity model)
       │
       ▼
Findings + simulation comparison
```

## Engineering limitations / roadmap

1. Implement real IAM permission evaluation and policy-condition handling.
2. Add offline import of sanitized AWS configuration exports (never require secrets).
3. Add confidence and uncertainty explanations per finding.
4. Add realistic test fixtures, benchmarks, and a security threat model.
5. Add PostgreSQL persistence, authentication, audit trails, and report export.
6. Improve visualization layout and add accessible keyboard navigation.

## Responsible use

Only analyze environments you own or have permission to assess. Do not upload access keys, customer data, or confidential production configuration. The sample data is synthetic.

## Resume integrity

Describe only features you have implemented, tested, and can explain. This prototype is a **foundation** for a more advanced cloud security project, not a production-ready cloud security product.

## v0.2 — Offline IAM identity-policy inspector

The dashboard now includes an IAM policy inspector. Select **Load sample policy**, then **Inspect IAM policy** to see potential sensitive-permission indicators. You can paste your own identity-policy JSON (do not include credentials or confidential customer data). The sample includes a broad role-management Allow and an explicit Deny for secret reads.

**Important limitations:** This is a *pattern-based educational inspection*, **not** a full AWS IAM evaluator. It does not calculate effective permissions, evaluate conditions, SCPs, permissions boundaries, session or resource-based policies, role trust, or AWS action/resource compatibility. Conditional statements are flagged for review and not counted as unconditional findings. An explicit Deny is considered only for straightforward matching action/resource patterns; wildcard resource relationships are not fully modeled. Findings do not establish exploitable paths. The IAM inspector is separate from the synthetic attack-path graph.

API: `POST /api/iam/analyze` with `{ "policy": { ...AWS identity policy... } }`.

Tests: `python -m pytest -q` (includes IAM parser regression tests).


## v0.4 enhancements

- Explainable risk score factors for the synthetic graph analysis (impact, exposure, hop adjustment). These are **not CVSS scores**.
- PDF report export for the currently loaded environment, including selected simulated edge removals and optional IAM overlay. PDF is generated locally; no AWS credentials are required.
- Updated dashboard styling and report panel.
- Additional API and scoring tests.

To export, run the app and click **Export security PDF**. The server also exposes `POST /api/report/pdf` with `environment`, optional `policies`, and optional `disabled_edges`.

**Limitations:** no real AWS import, no comprehensive AWS effective-permissions evaluation, no production remediation, no exploit verification. Do not upload sensitive configurations to an untrusted deployment.

## v0.5: Offline AWS inventory import

Use **AWS inventory importer** on the dashboard, click **Load example inventory**, then **Import and map**. The existing IAM-linked analysis button can then analyze the imported graph. You can also select **Choose AWS inventory JSON** to import a locally saved JSON file. No AWS account, API keys, or network access to AWS are required.

The input is a **CloudGraph-defined export format**, not native AWS Config, Terraform, CloudFormation, or a complete AWS account export. See `samples/aws-inventory.json` for the supported schema (`format: cloudgraph-aws-inventory-v1`). Top-level lists: `roles` (name, inline `policy`), `instances` (id, role, public_ip, ingress CIDR/port), `buckets`, `databases`, and `secrets` (name, arn, sensitive). The current importer supports only public HTTP(S) ingress for IPv4/IPv6 CIDRs, selected read actions, and unconditional identity policy matching. It does **not** evaluate VPC routes, network ACLs, trust policies, SCPs, permission boundaries, resource policies, or effective AWS authorization. Role-to-resource edges and graph findings are **hypotheses** and must not be presented as proof of exploitability. Import only sanitized exports; do not upload credentials or sensitive secrets.

Test: `py -m pytest -q` (Windows) or `python -m pytest -q`.
