# Bahar — F18–F27 Evidence Governance Remediation

**Baseline:** the previously repaired F08–F17 project. The resulting folder contains **both** that work and these changes. This is an implemented, locally tested architectural hardening—not a certification of scientific truth, legal conformity, production security, or real-world supplier provenance.

## Remediation matrix

| Finding | Implemented change | Important boundary |
|---|---|---|
| F18 | Governed input refuses client `source_records` and `evidence`. Source versions in the governed manifest are derived from exact saved records and verified content SHA-256. The standalone engine always marks its source custody `false`. | The compatibility `/api/assess` endpoint is an **untrusted demonstration engine**. |
| F19 | Immutable retained UTF-8 content copies (up to 1 MiB), canonical object digests, immutable governed assessment-input snapshots, manifest-to-record references, saved-result and snapshot integrity verifier (`verify_assessment_replay`). | This verifies **retained inputs, bytes and hashes**. It does not re-execute external models or prove external supplier authenticity. Large binary ingestion still uses the separate object store; no complete binary-to-governed-assessment replay is established. |
| F20 | Traversable graph with source-span → assertion → review → finding links when explicitly evidenced; governed legal source → registered rule → finding links when explicitly referenced. Unlinked findings remain marked. | A graph cannot create evidence that was never recorded. It must not claim universal completion. |
| F21 | Six independent reviewer-adjudicated dimensions: authenticity, integrity, relevance, applicability, substantive verification, approval. Incomplete or contradictory interpretation cannot be promoted. Reviewer and reasoning recorded. | Review assertions document accountable judgments; no local review asserts independently verified objective truth or legally approved production release. |
| F22 | Three distinct assertion kinds: source claim, generic reference knowledge, material-lot claim. Generic reference knowledge cannot substantiate lot-specific origin. Lot assertions are applicable only to their exact supplier/material/lot/specification scope. | Current ingredient vocabulary and manufacturer-specific source truth remain limited. |
| F23 | `candidate`, `unknown`, `contested` identity states; unknown/contested cannot be positively adjudicated into a qualified assertion without a new supported interpretation. Literal source-region verification is mandatory. | This does not automatically discover every trade name, synonym, additive or processing exception. |
| F24 | Negative evidence needs exact material ID, supplier ID, lot ID and specification version. No cross-lot or source-unspecified inference. | Not-detected is not universal absence, and this model is not a quantitative allergen-risk assessment. |
| F25 | Reviewed retrieval universe manifests (expected, retrieved, unresolved), bound snapshots, explicit unknown/incomplete state, fail-closed evidence assurance, and no global-exhaustiveness claim. | Completeness is relative to a **declared source universe**. Independent discovery of every potentially relevant third-party source is not proven. |
| F26 | Source extraction integrity remains separate from factual qualification and approval; explicit withdrawal records and validity date intervals invalidate current-scoped evidence without erasing historic bytes. | Historical records may reflect information later found wrong. The correction workflow must not erase them. |
| F27 | Append-only, exact-region correction proposals; independent decision records; searchable complete correction history; accepted corrections produce new content versions with derivation lineage. A local Evidence & Corrections UI and GET readouts were added. | Local UI is demonstration-only. Public production correction mutations/readouts are denied until genuine per-user authentication exists. |

## Source snapshots and replay

The custody API is exposed through `EvidenceCustody(store)` in `src/bahar/evidence_governance.py`.

1. `retain_source(source_id, version, text, scope=...)` creates `evidence-source:<id>:<version>`. It stores exact UTF-8 bytes encoded as base64 plus a calculated SHA-256 and immutable canonical record digest. Caller-supplied hashes are not trusted.
2. `propose_assertion(...)` accepts only literal ranges that match the retained text and separately records proposition, polarity, scope, knowledge type, and candidate state.
3. `review_assertion(assertion_id, decisions, reason, basis_refs)` records the six independent review dimensions; a reviewer cannot create unqualified positive approval out of an unknown or contested interpretation.
4. `register_coverage(...)` identifies a bounded expected universe, including unresolved documents. It never claims global document exhaustiveness.
5. `register_bundle(...)` pins exact assertion and review digests together with the coverage digest.
6. `replay(bundle_ref, required_scope=...)` checks source bytes and referenced review/custody records; missing, corrupted, stale or withdrawn sources cannot satisfy a complete current assessment.
7. `GovernedWorkflow.assess_governed` refuses unregistered client-side evidence, derives source manifest entries from replay, requires exact assessed source bindings for stronger favorable claims, attaches traceable finding provenance, saves immutable engine input, and commits the result. Review-required findings and incomplete evidence remain unresolved.
8. `GovernedWorkflow.verify_assessment_replay(assessment_id)` verifies recorded source records, exact immutable input snapshot and result/manifest hashes. It **does not** claim deterministic regeneration of a previous external AI response.

### Required source bindings for favorable evidence assurance

The governed case may supply `source_bindings` with:

- `label`: exact `source_ref`, start and end offsets matching `label.ingredient_text`.
- `ingredients`: by ingredient occurrence ID, exact source region plus a reviewer-qualified `identity_assertion_ref` for any accepted identity; the proposition is `ingredient_identity:<occurrence-id>:<accepted-identity>`.
- `declarations`: by allergen, exact source region/quoted declaration plus a reviewer-qualified assertion whose proposition is `label_declares:<allergen>`.

Each assertion must refer to the same document and same character span as its respective input binding. Without such proof, a favorable governed assessment is withheld. **Neither a text-span match nor reviewer agreement by itself proves compliance.**

## Correction workflow

`propose_correction` requires exact original source text, offset range, proposed replacement, accountable actor and reason. `decide_correction` records acceptance/rejection as a separate immutable object; production reviewer and proposer must differ. `correction_history(source_ref)` enumerates **all** retained proposals for that source, not a subset chosen by the browser. `materialize_corrected_source` accepts only decided-and-accepted, nonoverlapping corrections, generates a separately versioned retained artifact, and preserves the original bytes.

## Browser and API

Navigate **Evidence & corrections** in the sidebar of the local server. The local interface provides JSON forms for retaining a source, candidate assertion, six-dimensional review, scoped retrieval coverage, bundle, correction proposal, correction decision, corrected derivative, and read-only historical trace viewing.

| Endpoint | Method | Local demo | Production HTTP |
|---|---|---|---|
| `/api/evidence/sources` | POST | Yes | Forbidden until per-request authentication |
| `/api/evidence/assertions` | POST | Yes | Forbidden |
| `/api/evidence/reviews` | POST | Yes | Forbidden |
| `/api/evidence/coverage` | POST | Yes | Forbidden |
| `/api/evidence/bundles` | POST | Yes | Forbidden |
| `/api/evidence/corrections` | POST | Yes | Forbidden |
| `/api/evidence/correction-decisions` | POST | Yes | Forbidden |
| `/api/evidence/derivatives` | POST | Yes | Forbidden |
| `/api/evidence/corrections?source_ref=…` | GET | Yes | Forbidden |
| `/api/assessments/<id>/provenance` | GET | Yes | Forbidden |
| `/api/assessments/<id>/verify-replay` | GET | Yes | Forbidden |

The trusted **Python service** can operate on the PostgreSQL store using its membership-backed `TenantContext` and `_require_role` checks. These do **not** supply request-bound browser authentication. Do not expose local demonstration server to untrusted network users.

## Verification

Execute from the extracted project root:

```bash
PYTHONPATH=src python -m pytest -q tests
node --check web/app.js
```

After modification, the complete suite passed **82 tests** and skipped **5 PostgreSQL integration tests** because `BAHAR_TEST_DATABASE_URL` was not configured. An additional live localhost HTTP smoke test verified the Evidence view, POST source retention and GET full correction history. Tests cover forged source metadata, immutability, exact evidence spans, independent review dimensions, lot scoping, vocabulary unknowns, missing retrieval, source withdrawal/expiry, replay snapshot verification, correction approval and derivation, and label-declaration binding.

## Not yet verified or not included

- Independent authenticating user identity in production HTTP requests and segregated reviewer/approver workflows end-to-end.
- PostgreSQL plus RLS integration tests, concurrency tests and clean deployment recovery tests in the target infrastructure.
- Encrypted and independently proven custody across the entire object-store / document-extraction / assessment chain for large binaries.
- External AI reproduction across model and provider changes; real-world authoritative laboratory, supplier, and legal validation.
- Exhaustive evidence discovery outside the reviewer-declared source inventory.
- Original separate assessment weaknesses **F01–F07**, unless a conservative evidence boundary explicitly prevents a stronger governed claim. Those earlier deficiencies were not generally repaired here.
- Existing F08–F17 distributed transaction and real identity limitations carried forward from the baseline.

**No production, safety, or legal certification claim is established by these changes.**
