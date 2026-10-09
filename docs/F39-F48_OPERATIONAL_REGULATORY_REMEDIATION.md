# BAHAR Bahar Ω — F39–F48 Operational and Regulatory Scope Remediation

**Baseline:** `Bahar_F08-F38_input_ai_fixed.zip` (cumulative source). **Implementation date:** 9 October 2026. **Qualification:** engineering controls implemented and tested locally; production authority and external domain qualification are **NOT ESTABLISHED**.

## Engineering disposition

| Finding | Software change delivered | Actual production assurance still required |
|---|---|---|
| F39 | Source-bound legal interpretation record and two-person regulated-review interface; unqualified law returns `NOT_EVALUATED`. No advisory article auto-becomes executable law. | Obtain the consolidated binding legal texts and annexes and an accountable qualified Azerbaijani legal/regulatory approver. No approval supplied. |
| F40 | Per-obligation effective intervals, relevant event dates, distinct temporal selection, unresolved exception reporting and invalid-interval rejection. | A professional lawyer must verify each relevant event, exception, transitional provision, hierarchy, and historical legal edition. No finite test proves all legal scenarios. |
| F41 | Quantitative concentration-to-exposure screen with Decimal arithmetic and explicit uncertainty; missing reference-dose, sample, matrix, mitigation, or controls evidence prevents a result. Never autonomously recommends PAL. | Expert-approved reference doses, representative samples, relevant hazard data, mitigation evidence, and an actual qualified risk assessment. |
| F42 | Typed connector-receipt contract for supplier/ERP/MES/LIMS/packaging, source digest, source version, schema/mapping revisions, and separate transport/semantic/source states. Successful transport **never establishes physical truth**. | Actual manufacturer endpoints, credentials, schemas, pilot mapping, response acknowledgment, conflict resolution, and validation are absent. This is NOT an integrated live connector. |
| F43 | Explicit camera calibration, qualification, source-image, packaging-artwork, lot and sampling-plan prerequisites. Default conclusion stays sample-only; detected differences cannot assert batch conformity. | Actual imaging hardware, controlled illumination, performance limits, representative defect validation, calibration records, trained operators, and accepted sampling plans. |
| F44 | Chronologically checked, actor-identified sample custody events, analytical method/matrix qualification, calibration, LOD/LOQ consistency and document references. | Independent laboratory qualification, actual signed sample transfers and analytical results, validated recovery, uncertainty, and matrix performance. |
| F45 | Append-only incident lifecycle, legal state transitions, affected-lot obligations, retained evidence and explicit `NOT_SENT_BY_BAHAR` external-notification state. | Recall exercises, supply-chain contact lists, authorized personnel, notification service/authority acknowledgments, and real regulator procedures. This application does not initiate a real recall or send notices. |
| F46 | Role/action matrix for 23 operations; store-backed membership checks inside business transactions; denial of nonauthenticated Postgres HTTP operational writes and tenant-record reads; production release refused without authenticated membership and qualified basis. | Integrate per-request OIDC/SAML identity, scoped tenants/facilities, periodic access reviews, JIT access and 2-person approvals. The bundled HTTP server is **not** an identity provider. |
| F47 | Explicit identity over product, formulation, market, jurisdiction, package, artwork, label, language, site, event/date, purpose, and legal profile. Deterministic digest changes if any dimension changes. | Validate referenced objects, legal package requirements and production market configuration under real institution policies. |
| F48 | Planned vs consumed lot comparison with independent material record and physical-verification prerequisites; identical records are **documentary reconciliation only**, not physical certification. | Validated MES/material dispensing data, actual lot/line/rework/packaging verification, qualified inspectors, and physical production evidence. |

## Data and authority model

The new `operational_scope.py` is a **pure, conservative evaluation layer**. It does not query outside systems and it never upgrades input flags into trusted approval. `operational_workflow.py` adds an append-only operational ledger with distinct author and review records; `authorization.py` sets a deny-by-default action/role matrix.

Production PostgreSQL ledger requires migration `0003_operational_assurance.py`. Its rows have tenant-scoped RLS, immutable revision content, server-bound actor identity, digest, and audit events. For material events the ledger write, audit record, and **conservative active release suspension** execute in the same PostgreSQL transaction. This does not solve distributed object-storage + database atomicity or guarantee complete upstream data ingestion. The five legacy DB integration tests could not run without `BAHAR_TEST_DATABASE_URL`.

The approval helper `OperationalWorkflow.qualify` is a **service-only**, dual-actor documentary review. It checks membership-backed roles, exact source digests and governed basis references and records the reviewer separately. It does **not** turn documentary review into scientific truth or legal correctness. The public HTTP service cannot invoke this method.

The frontend's **Operational safeguards** tab uses only `POST /api/operational/preview` with `qualified=False` enforced on the server. The localhost SQLite demo may create non-authoritative incident records using `POST /api/operational/records`; a production Postgres HTTP request is forbidden until a separately authenticated application layer is deployed. The production `OperationsService` itself is callable only within a trusted membership-bound service environment, not through public HTTP. Production `BaharService.approve_release` requires PostgreSQL and additional qualified evidence. All demo UI labels and assessment outputs retain `NOT_ESTABLISHED` / `NOT_AUTHORIZED` boundaries.

## External legal source review, October 9, 2026

- Azerbaijani *Food Safety Law*, article 17.2, establishes food-label information duties including composition and allergens. Source: https://president.az/az/articles/view/56517 . This is a law text, not a legal opinion on a product-specific exception.
- AFSA announcement on 24 August 2026 reports adoption of an allergen list including 14 categories: https://afsa.gov.az/az/xeberler/allergenlerin-qida-mehsullarinin-etiketinde-gosterilmesine-dair-yeni-telebler-mueyyenlesdirilib . **The announcement is not the underlying Kollegiya decision and complete annex**. Do not promote it to an approved legal rule on its own.
- AFSA guidance on 2 September 2026 reports that a new requirement is to take effect on 1 January 2027: https://afsa.gov.az/az/xeberler/qida-istehsalcilari-ve-sahibkarlarin-nezerine-1 . This does not negate earlier legal duties and must not be assumed to govern every type of relevant event.
- Codex CAC49 precautionary allergen labeling updates are based on risk assessment of unintended presence, not a blanket obligation for "may contain": https://codex.fao.org/news/news-detail/2026/07/07/cac49-groundbreaking-guidelines-set-to-fundamentally-change-food-allergen-labelling . Codex and binding Azerbaijani rules must be represented distinctly.

**No Azerbaijani qualified approver, legal-exception adjudication, plant inspector, laboratory results, or manufacturer API credentials were supplied.** The engineering framework now refuses unsupported conclusions; it cannot truthfully claim the external evidence exists.

## Verification

Run in the project root:

```bash
python3 -m pip install -e '.[dev]'
PYTHONPATH=src python3 -m pytest -q
node --check web/app.js
python3 -m compileall -q src
```

The new regression suite `tests/test_operational_f39_f48.py` covers temporal boundaries, unresolved legal exceptions, PAL screen arithmetic, transport-vs-truth isolation, sample/lot scope, custody ordering and detection limits, incident transitions, role matrix, exact market configuration, unqualified material reconciliation, append-only demo versioning, and rejection of caller-provided actor authority. It is a synthetic **software-control test suite**, not empirical food safety or regulatory validation.

## Deployment constraints

1. Run migrations in a nonproduction staging database, verify transaction rollback and RLS with two independent users and tenants, and record all evidence. Do not deploy unverified migrations directly to manufacturing operations.
2. Integrate secure per-user authentication before enabling any production API write; the local HTTP implementation intentionally denies them.
3. Load full, versioned legal texts into governed custody; request qualified legal approval and conflict adjudication.
4. Acquire real supplier/ERP/MES/LIMS/packaging contracts and identity-bound credentials; verify schema and acknowledgments.
5. Perform food-science, camera, laboratory, packaging, batch traceability, and incident/recall qualification with accountable specialists.
6. Do not enable automated regulatory-compliance verdicts, PAL recommendations, physical-batch assurance, product release, or external notices from the demo.

**Acceptance conclusion:** F39–F48 are **partially remediated as executable controls with explicit fail-closed boundaries**. Their underlying real-world assurance gaps cannot be closed without qualified external evidence, integrations, legal review and production validation.
