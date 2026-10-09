> **Historical snapshot.** This file reflects an earlier requirements-status review. The implemented ingestion/extraction and frontend capabilities have subsequently changed. For current verified and unverified boundaries, consult `README.md` and `docs/FRONTEND_IMPLEMENTATION_AND_VERIFICATION.md`; this older file must not be used as the authoritative capability register.

# Requirements implementation status and remaining work

Status date: 9 October 2026.

## Executed verification

The suite contains the audit's 24 mandatory repaired-baseline scenarios plus transaction, concurrency, retry, and strict-JSON boundary tests. All 27 tests are executable in `tests/test_acceptance.py`.

| Area | Executed result |
|---|---|
| V01–V04 evidence, scope, identity, incomplete evidence | Implemented and passing |
| V05–V07 failed execution, incomplete assessment, missing checks | Implemented and passing |
| V08–V10 exceptions, future rules, normative conflicts | Implemented and passing |
| V11–V13 change impact, incomplete dependencies, history | Implemented and passing |
| V14–V16 physical sample, batch deviation, lab nondetect | Implemented and passing |
| V17–V18 untrusted source instructions and model-version manifests | Implemented and passing |
| V19–V21 authority, readiness, approval continuity | Implemented and passing |
| V22–V24 undefined metrics, demonstration isolation, visual emphasis | Implemented and passing |
| Lost-update prevention and idempotent retry | Implemented and passing |
| Duplicate-member and non-finite JSON rejection | Implemented and passing |

## New domains 31–42

| Domain | Current executable coverage | Status |
|---|---|---|
| 31 Assessment contracts and claim scope | Immutable identity/version/mode/scope, permitted claims, required checks, demo isolation | Implemented core |
| 32 Material identity and supplier-lot applicability | Immutable typed version records, receipt-compatible data storage, provenance, change dependency graph | Partial workflow |
| 33 Hierarchical formulation and transformation | Version-pinned nesting, recursion, cycle rejection, roles, typed quantities, no processing-elimination inference | Implemented core |
| 34 Artwork and physical labels | Digital text/artwork separation, visual evidence, sample-to-artwork comparison, sample-only generalization | Implemented core |
| 35 Batches and actual materials | Batch records, planned/actual deviation check, indeterminate missing actual-material state | Implemented core |
| 36 Legal declaration and presentation | Independent content and visual checks, exceptions, ingredient-list versus separate-statement rule field | Implemented core |
| 37 Legal time and normative conflict | Source authority class, effective dates, event policy, conflict detection, approved precedence hook | Implemented core |
| 38 PAL and risk coordination | Claim boundary and non-authorization controls; no fabricated quantitative result | Data-entry and quantitative workflow remaining |
| 39 Laboratory evidence | Sample-scoped result, method/matrix applicability, LOD, nondetect limitation | Implemented core; custody workflow remaining |
| 40 AI security and untrusted inputs | Source data never becomes instruction, fixed API surface, argument validation, size limit, no external tools | Single-tenant core; tenant isolation and external-provider policy remaining |
| 41 Reproducibility | Immutable manifest, versions/digests, idempotent commit, separate rerun identity inputs | Implemented core; sealed runtime image export remaining |
| 42 Incidents and response | Dependency impact and release suspension | Incident case management and external notification coordination remaining |

## Concrete remaining work for a production deployment

These are not missing lines of code in the assessment demonstration; they require deployment-specific records, integrations, or accountable approval.

1. **Original 360 requirement statements.** The supplied audit references them but does not include them. Importing their actual text is needed for a complete 480-row traceability matrix.
2. **Qualified Azerbaijani legal interpretation.** The e-qanun annex, connected labelling provisions, exceptions, transition rules, and visual-presentation obligations must be converted into approved executable rule records by the designated authority. The included rule is deliberately demonstration-scoped.
3. **Supplier/ERP/MES/packaging integrations.** Adapters must be written against the actual customer's source systems, authentication, identifiers, lot semantics, and transaction guarantees.
4. **Tenant and identity infrastructure.** The local app has no multi-tenant identity provider. Production needs organization boundaries across the database, retrieval cache, object storage, logs, and any external AI context.
5. **Document ingestion.** PDF/image OCR, signature validation, malware scanning, extraction review, and source-artifact storage are not included. The core accepts structured records so extraction candidates cannot bypass acceptance.
6. **Quantitative cross-contact/PAL.** Facility-specific hazard models, consumption amounts, reference-dose versions, action-level policy, sampling plans, analytical uncertainty, and authorized expert recommendations are required before enabling this claim type.
7. **Laboratory chain of custody.** The core represents method and sample limits; a production laboratory workflow needs actual LIMS integration, custody records, method accreditation, matrix validation, and sampling inference approval.
8. **Physical print inspection.** The implemented sample comparison accepts captured text. Production optical inspection needs camera qualification, OCR validation, legibility/emphasis measurement, sampling policy, and printer/line integration.
9. **Incident and recall workflow.** Internal incident registration, hold/quarantine approvals, regulator/customer notification, withdrawal/recall records, and corrective-action workflow must be bound to the organization's authorized procedures.
10. **Operational qualification.** Deployment-specific load, recovery, backup/restore, penetration, privacy, retention, observability, disaster-recovery, and user-acceptance evidence remain to be executed in the target environment.

## Claims enabled now

- Demonstration and governed internal assessment of structured recipe-to-label cases.
- Identification of supported, unsupported, conflicted, and unresolved allergen-related facts within the declared scope.
- Prospective testing of the recorded 2027 Azerbaijani allergen-list model.
- Technical readiness for authorized review.

## Claims deliberately not enabled

- Universal food safety.
- Complete food-label compliance beyond the selected allergen scope.
- Automatic legal certification or release.
- Quantitative cross-contact risk without qualified inputs.
- Proof that every manufactured unit matches a formula or packaging sample.

## October 9, 2026 — F39–F48 regulatory and operations engineering

Added append-only, tenant-scoped operational records, legal-event and quantitative-screen guards, connector receipt contracts, camera and laboratory qualification prerequisites, incident lifecycle semantics, exact market-package identity, role/action enforcement, and planned-versus-actual batch reconciliation. These are **engineering controls**; no actual Azerbaijani legal approval, real manufacturer integrations, production imaging qualification, accredited laboratory data, recall notification integration, or verified real manufacturing data are asserted. Refer to `F39-F48_OPERATIONAL_REGULATORY_REMEDIATION.md`.
