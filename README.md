> **F28–F38 input/AI behavior hardening:** The deterministic lexical engine remains **untrained, editorial, and not independently validated**. Added nonauthoritative spelling hints, conservative multilingual/structural uncertainty, per-page PDF coverage, mandatory dated model revision for external inference, and independent-corpus benchmark tooling. No real-world accuracy claim is established. See [F28–F38 remediation](docs/F28-F38_INPUT_AI_REMEDIATION.md).

> **Evidence-governance hardening (F18–F27):** This distribution includes the earlier F08–F17 work and an append-only scoped evidence ledger, replay-bound source manifest, provenance graphs, qualified-review states, and a local correction-history interface. See [the F18–F27 remediation report](docs/F18-F27_EVIDENCE_SEMANTICS_REMEDIATION.md). Local demonstration review must not be treated as regulatory certification or production authentication.

# Bahar Operations

Bahar Operations is a full local web application for evidence-governed supplier, formulation, label, artwork, manufacturing-batch, package-inspection, cross-contact, and recipe-to-label assessment workflows. Candidate extraction remains separate from accepted identity; evidence can be positive, negative, unknown, or conflicted; and execution, findings, technical readiness, and release approval remain separate states.

The application does not turn a successful software run into a legal or product-release decision. A successful scoped result is phrased as **“no discrepancy detected within the completed declared scope.”**

## Frontend modernization and responsive verification (October 9, 2026)

The UI retains the original Bahar branding, palette, and panels while adding responsive mobile navigation, semantic routes, readable assessment findings, structured forms with optional advanced JSON, explicit attempt/partial-success/error feedback, search and server-side record pagination, and basic accessibility controls.

See `docs/FRONTEND_IMPLEMENTATION_AND_VERIFICATION.md` for the full implementation inventory, deferred production requirements and test evidence. New independent browser regression checks can be run with `python scripts/verify_frontend.py` when Playwright and a local Chromium browser are installed. The screenshots in `artifacts/` use mocked API responses.

The implementation remains a scoped demonstration and operational foundation, not a qualified food-labeling compliance or production-release authority.

## Run the full localhost system

Docker Desktop is the only host prerequisite for the full stack. It starts PostgreSQL, an S3-compatible development object store, ClamAV, OCR support, database migrations, the backend API, and the browser application.

```bash
cd path/to/Bahar
docker compose up -d --build
```

Open `http://127.0.0.1:58088`. Stop the stack with `docker compose down`; do not add `-v` unless the local development database and object-store volumes are intentionally being discarded.

Run the local verification suite:

```bash
python3 -m pip install -e .
python3 -m pytest -q
BAHAR_TEST_DATABASE_URL='postgresql+psycopg://bahar_app:app-local-only@127.0.0.1:55432/bahar' \
  python3 -m pytest -q tests/test_operations_postgres.py
```

The original deterministic assessment demonstrations remain available:

```bash
bahar demo --case unsafe
bahar demo --case ready
```

The supplied BAHAR Bahar AI Core, updated with v0.5 extraction assurance, is vendored under `src/bahar_ai_core` and used as a deterministic lexical candidate engine. Its dataset and optional provider adapter are not model weights and never approve facts or releases automatically.

## Implemented end-to-end behavior

- Immutable assessment contracts with mode, scope, permitted claims, and required checks.
- Azerbaijani and English deterministic ingredient candidates with accepted identity kept separate.
- Explicit compound ingredients, nested versioned formulations, cycle detection, roles, quantities, and typed unit conversion.
- E322/lecithin origin remains unresolved unless accepted origin evidence is supplied; sunflower origin does not become soy, while verified soy origin maps to soybeans.
- Evidence qualification across source identity, integrity, relevance, applicability, and substantive qualification.
- Same-scope four-valued evidence semantics, including preserved `CONFLICTED_EVIDENCE`.
- Azerbaijan's future-effective 14-category allergen source modeled separately from the AQTA announcement and activated by the market-event date.
- Binding law, incorporated standard, voluntary standard, official guidance, and reference information remain distinct authority classes.
- Normative-conflict detection and optional approved precedence policy.
- Separate content, visual-artwork, physical-sample, batch, and laboratory checks.
- No conversion of laboratory nondetect into absolute absence.
- Complete/partial/not-run check coverage and deterministic technical gate calculation.
- Immutable manifests binding inputs, sources, rule versions, knowledge version, and AI execution identifiers.
- A standalone SQLite adapter remains available for core demonstrations; the full website uses PostgreSQL.
- PostgreSQL migrations, tenant row-level policies, optimistic concurrency, append-only records, and tamper-evident audit chaining.
- Encrypted, versioned S3-compatible custody for source documents and derived artifacts, with SHA-256 digests and retention classifications.
- MIME-independent ingestion, ClamAV scanning before parsing, archive/page limits, quarantine, immutable original bytes, and fail-closed malformed-input handling.
- Native PDF extraction, OCR for Azerbaijani/English/Russian, structured/CSV/spreadsheet extraction, coordinates, confidence, immutable extraction records, and review-only label candidates.
- Supplier identifiers, specification validity/retraction, material lots, receipts, declared/verified/laboratory origin separation, and correction impact sets without historical rewriting.
- Exact formulation/subrecipe versions, dimensional unit checks, cycle rejection, yields/losses/transformations/rework/processing aids, and indeterminate unsupported removal claims.
- Separate label text, artwork, language/package/printer specifications, visual measurements, and exact assessed-artifact custody.
- Production lines, equipment, consumed material lots, packaging lots, deviations, formula-versus-batch separation, substitution detection, and indeterminate missing actuals.
- Qualified-camera records, approved sampling plans, sample-scoped physical inspections, and explicit batch-inference policy.
- Cleaning evidence and facility-specific cross-contact snapshots that keep recipe-origin allergens separate from unintended-presence hazards.
- Release approval restricted to an exact registered production contract and an explicit `release_authority` role; demonstration results are rejected.
- Same-origin local API with a body-size limit, fixed static-file allowlist, strict JSON boundary, CSP, and no model-directed tool surface.

## Repository map

- `src/bahar/assessment.py` — fail-closed assessment and gate engine.
- `src/bahar/knowledge.py` — bilingual candidates and allergen-origin relationships.
- `src/bahar/rules.py` — legal-time, source-authority, and conflict selection.
- `src/bahar/evidence.py` — evidence qualification and four-valued support.
- `src/bahar/composition.py` — nested formulation and quantity integrity.
- `src/bahar/persistence.py` — PostgreSQL tenant context, transactions, and persistence boundary.
- `src/bahar/operations.py` — supplier-to-batch operational workflows and invariants.
- `src/bahar/ingestion.py` and `src/bahar/extraction.py` — secure document custody, OCR/layout, and review proposals.
- `src/bahar/bahar_adapter.py` — governed adapter for the supplied BAHAR engine.
- `src/bahar/api.py` — local HTTP application boundary.
- `migrations/versions/` — versioned PostgreSQL schema, RLS, and immutability controls.
- `web/` — responsive single-page operations interface.
- `data/az_rules.json` — governed seed record for the 2027 Azerbaijan allergen list.
- `tests/test_acceptance.py` — V01–V24 plus transaction, concurrency, retry, and strict-JSON acceptance tests.
- `docs/LITERATURE_AND_SOURCE_AUDIT.md` — source-grounded analysis and design consequences.
- `docs/REQUIREMENTS_STATUS.md` — implemented scope and exact remaining work.

## Validity boundary

The software's unconditional invariants are executable and tested: an incomplete run cannot issue a final outcome; a future rule cannot govern an earlier relevant event; a source document cannot grant authority; a demonstration cannot approve production release; and historical records are not overwritten.

Domain conclusions are conditional on their declared product, formulation, label, market, time, rule, and evidence scope. The repository contains a real runnable system, while `docs/REQUIREMENTS_STATUS.md` keeps the remaining production-integration and qualified-review work explicit.

## F08–F17 architecture hardening

The `docs/F08-F17_ARCHITECTURE_REMEDIATION.md` report describes the governed candidate-review boundary, controlled regulatory-rule resolution, web-based recipe comparison, and conservative atomic release suspension on material changes. It also lists explicit **remaining blockers**—most notably full distributed ingestion/outbox consistency, real PostgreSQL integration testing, individual HTTP authentication, and the independent F01–F07 assessment defects. This patch does **not** authorize production regulatory conclusions or product release.

## Operational and regulatory safeguards (F39–F48)

The cumulative F08–F48 release adds `bahar.operational_scope`, `bahar.operational_workflow`, `bahar.authorization`, PostgreSQL migration `0003_operational_assurance`, a local **Operational safeguards** browser tab, and a new adversarial test suite. A regulatory news release, a caller's `approved: true`, a calculated concentration, a scanned package image, and a manufacturer payload cannot automatically establish legal, laboratory, or production authority. Production HTTP mutations remain disabled until genuine per-user authentication is integrated. See [`docs/F39-F48_OPERATIONAL_REGULATORY_REMEDIATION.md`](docs/F39-F48_OPERATIONAL_REGULATORY_REMEDIATION.md) for implementation details and explicitly unmet real-world qualifications.

---

## Cumulative F08–F56 — production identity and approval hardening

This release retains the F08–F48 source and introduces an independently
verified **OpenID Connect resource-server** identity boundary. PostgreSQL
HTTP endpoints now require a per-request verified OAuth access token, a
selected tenant that the user actually belongs to, and an exact tenant-wide
role appointment. The server-side service principal is **not** a user login.

- Hosted IdP login through public-client Authorization Code + PKCE S256.
  Tokens are held in volatile browser memory and never persisted in
  `localStorage` or browser cookies. The one-time PKCE verifier/state is
  held in sessionStorage until the OAuth callback.
- Strict asymmetric JWT verification: trusted issuer, API audience, client
  `azp`/`client_id`, `sub`, timestamps, JWKS signature, and bounded token TTL.
- Tenant isolation: explicit tenant selection is confirmed against current
  organization-wide PostgreSQL memberships, then carried through a separate
  request-specific store and RLS transaction context.
- Role policy: exact method/path/action grants, privileged MFA freshness,
  restricted qualified reviewer roster, and separate human assignments,
  review decisions, regulatory decisions and final release attempts.
- No request-body `actor_id`, `authority_role`, `principal_id`, or
  `organization_id` is accepted as operational authority.
- No public `0.0.0.0` binding except an explicitly enabled private-container
  deployment; the shipped Docker port is host-loopback-only and requires a
  separate TLS reverse proxy for public browser SSO.

**Installation (source ZIP):**

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
pytest -q
# Local, clearly untrusted demonstration; no end-user SSO, no production release:
bahar serve --host 127.0.0.1 --port 8088
```

**Production setup requires additional independent infrastructure:** set all
`BAHAR_OIDC_*` variables shown in `.env.example`; configure a trusted
IdP with MFA and proper access-token claims; migrate PostgreSQL using
`alembic upgrade head`; register external subjects and memberships by a
separately authorized administrator; and terminate TLS in a trusted reverse
proxy. The historical `bootstrap-local` demo fixture is **not** automatically
created by the production Compose command.

See [`docs/F49-F56_IDENTITY_ACCESS_AUTHORITY_REMEDIATION.md`](docs/F49-F56_IDENTITY_ACCESS_AUTHORITY_REMEDIATION.md)
for the precise role matrix, deployment instructions, assurance boundaries,
regression-test coverage, and external qualifications still needed. Earlier
F01–F07 assessment-trust findings are **not** resolved by this authentication
patch; no regulated or production compliance assurance is implied.
