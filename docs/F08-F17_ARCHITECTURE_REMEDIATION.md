# Bahar F08–F17 Architectural Remediation

## Scope and assurance boundaries

This patch is an *implementation*, with regression tests, of the requested F08–F17 architecture corrections. It does **not** claim that the separate F01–F07 assessment-trust defects have been fixed. It is not a validated regulatory compliance product. In particular, PostgreSQL integration/concurrency behavior, legal source content, material-lot facts, physical packaging, and real individual authentication must be qualified before production claims.

The application has three claim levels: (1) lexical candidate observations; (2) reviewer-qualified *generic candidate identities*; (3) evidence-qualified regulatory assessment. Neither level (1) nor level (2) establishes material-lot truth, regulatory compliance or authority to release. The currently bundled editorial dataset cannot qualify production material origin. The governed production assessment route therefore **fails closed** when only editorial candidate reviews are available.

### Correction-by-correction mapping

| Finding | Implemented safeguard | Remaining verification / limitation |
|---|---|---|
| F08 | Distinct `governance_stage` and claim-level flags for `/api/ai/audit`, `/api/ai/compare`, and structured `/api/assess/governed`; untrusted rules forbidden on legacy `/api/assess`. | The two engines are not mathematically equivalent; they are intentionally separate stages. No such equivalence is asserted. |
| F09 | Stored lexical audits, source-snapshot-pinned, immutable candidate review records; reviewed-audit query; `candidate_audit_id`/candidate occurrence validation in governed structured assessments. Identifiers from review remain candidates, never automatically material truth. | Reviewer mutation is available only as a privileged Python service operation; not in the unauthenticated browser. A complete verified supplier-lot promotion and authentication UI remain to be built. |
| F10 | `POST /api/ai/compare`, source-version-aware comparison in browser; persistent immutable comparison record, local-impact-only and unknown downstream scope flags. | Comparison identifies generic reference-category change, not proven actual manufactured-product change. |
| F11 | Supplier corrections invoke release invalidation in the *same PostgreSQL transaction*, returning `impact_control` and suspended IDs. | No comprehensive external notification workflow yet. |
| F12 | Database material-record insert, conservative release suspension, version revision and audit event share one PostgreSQL transaction; SQLite equivalent tested with forced rollback. Tenant-scoped advisory lock serializes relevant release approval with change invalidation. | External object-store ingestion/OCR and independently reviewed facts are not one distributed ACID transaction. Implement a transactional outbox, durable staged artifacts, compensation/reconciliation and recovery tests before asserting full end-to-end atomicity. |
| F13 | `assess_governed` forbids arbitrary rule JSON and loads only `governed-rule:{id}:{version}` records. | Existing `AssessmentEngine.assess` remains a pure library function and must not itself be exposed as a trusted legal endpoint. |
| F14 | Rule registration requires a controlled source and an authenticated PostgreSQL `regulatory_approver` membership; source custody is matched to a governed artifact version and digest; approval identity must match principal. | Appointment authority and legal interpretation remain qualified human/institutional responsibilities. SQLite registry is explicitly demo-only. |
| F15 | `select_rules` no longer accepts precedence from assessment context. The privileged workflow loads a registered precedence policy and preselects its exact rule IDs, verifying jurisdiction and rule scope. | Precedence policies must be prepared and approved by qualified legal experts. |
| F16 | Material operational changes invalidate all current active releases (conservative until graph completeness is proven), and later release approval checks for relevant material events after the assessment snapshot. | New or third-party write paths must call the material-change invalidator; protect these through a database-level governance mechanism before allowing arbitrary integrations. Full automatic reassessment is *not* performed: the releases are suspended and flagged for review. |
| F17 | Graph `affected` results never claim definitive nonimpact on the basis of observed edges alone. Impact completeness remains `incomplete`; all active releases are conservatively suspended. | To safely narrow the affected set later, establish a separately governed *complete dependency inventory*, including unknown/missing sources and negative evidence of non-impact. |

## Public API (scope-aware)

- `POST /api/ai/audit`: untrusted lexical candidates; persists a source-snapshot-bound audit for later reviewer qualification; does not issue structured regulatory judgment.
- `POST /api/ai/reviewed`: reads the stored candidate-review state; **does not approve** a candidate.
- `POST /api/ai/compare`: before/after formulation comparison, with local-only category change and explicit unknown downstream completeness. Browser form included.
- `POST /api/assess`: compatibility demonstration route only. Refuses client-supplied regulatory rules, precedence maps and production mode.
- `POST /api/assess/governed`: server-resolved rule objects and precedence. Its result remains bounded by source/input qualification. Editorial candidates cannot authorize production.
- `POST /api/releases`: intentionally blocked until request-specific, independently authenticated identity is available.
- `POST /api/changes/impact`: intentionally blocked for unauthenticated browser callers. Actual material mutations trigger invalidation inside the operational service transaction.

### Privileged Python workflow API

`GovernedWorkflow(store, service)` exposes `review_candidate`, `reviewed_audit`, `register_source`, `register_rule`, `register_precedence`, `assess_governed`. **Do not publish the mutating methods through the current unauthenticated web router.** Production role checks are performed through PostgreSQL tenant membership for `reviewer` and `regulatory_approver`. Registered regulatory sources are cross-checked against physically retained governed artifact versions and SHA-256 digests. Local SQLite is demo-only.

The `candidate-review:*` records are immutable and idempotent. They bind the reviewer, observed source span, source audit digest, and source snapshot digest. A modified recipe/label requires a new audit and new review.

## Transactional scope and fail-closed impact policy

For `OperationsService.MATERIAL_ACTIONS`, each transaction commits (or rolls back) **all** of:

1. The operational source mutation.
2. Suspension of all tenant releases that were active within the same serialized decision boundary.
3. Immutable release revisions and hash-chained audit events.
4. The material-change audit event and explicit impact-completeness report.

The mechanism is deliberately conservative. Without certified graph coverage, `affected(...)` never returns `definitive_unaffected_claim_permitted=true`. A missing dependency edge is not evidence of independence. Changes to records outside `MATERIAL_ACTIONS` may also be relevant in certain deployments; these must be added to the governance trigger policy before rollout.

`PostgresBaharStore.lock_release_continuity()` takes a tenant-scoped PostgreSQL advisory transaction lock shared with release approval. Release approval additionally refuses a previously completed assessment when a relevant material mutation was audited at or after its recorded creation. **This is not evidence that every broader input snapshot is transactionally sealed:** full trusted input and outbox coordination remain required for production assessment.

## Development run (without Docker)

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
bahar serve --host 127.0.0.1 --port 8088
```

Open http://127.0.0.1:8088. On the BAHAR audit page, the **Recipe version impact** panel compares v1 and v2. Local SQLite does not provide production tenant/membership authentication; the browser is a demonstration environment. **Do not expose this server to the internet.**

Run tests:

```bash
PYTHONPATH=src python -m pytest -q
node --check web/app.js
```

PostgreSQL database integration tests only run when `BAHAR_TEST_DATABASE_URL` is configured. Do not report skipped tests as passing. No direct Postgres integration server was available during this patch's execution.

## Acceptance and release checklist

- [x] Legacy browser `/api/assess` rejects embedded regulatory rules / production claims.
- [x] Candidate-review immutable record is pinned to the source audit digest.
- [x] Changed or unsupported candidate review is rejected.
- [x] Governed structured demonstration cannot adopt caller-supplied accepted identity as verified material truth.
- [x] Before/after version comparison is accessible through a public endpoint and browser form.
- [x] Client-supplied precedence cannot silence a normative conflict.
- [x] Database invalidation rollback test proves no half-suspended SQLite transaction when audit persistence fails.
- [x] No known graph edge never yields definitive nonimpact.
- [x] Browser attempts to approve a release or invoke impact suspension are refused.
- [ ] PostgreSQL transactional tests in a real test database, including simultaneous approval/change and rollback.
- [ ] Material source-to-product dependency inventory independently completeness-certified.
- [ ] Authenticated per-request user identity and segregation of duties on every mutating route.
- [ ] Transactional outbox / durable recovery for artifact ingestion, extraction, and reviewed facts.
- [ ] Correct the separately documented F01–F07 assessment trust-boundary findings.
- [ ] Scientific and legal expert approval of production rules and data.

This is an engineering hardening patch, not a complete production certification.
