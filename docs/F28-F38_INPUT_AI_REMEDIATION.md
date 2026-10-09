# Bahar F28–F38 — Input Processing and AI Behavior Remediation

**Baseline:** The cumulative F08–F27 repaired package, retained unchanged except for the explicitly documented changes below. **Status:** implemented controls and executed local tests; **no independent field accuracy qualification**.

## Source-confirmed inventory

The bundled reference vocabulary currently contains **324 aliases labeled `en`, 0 labeled `az`, and 0 labeled `ru`**. Its relationships are an **editorial seed** pinned by integrity digests, not scientific verification. The BAHAR default mode is deterministic rule/lexicon processing, **not a trained model**. These facts are surfaced in the identity API and execution manifest rather than concealed by the application branding.

## Finding-by-finding changes

| Finding | Implemented | Boundary of the correction |
|---|---|---|
| **F28** | Execution outputs identify the default `DETERMINISTIC_LEXICAL_BASELINE`, `trained_model=false`, and `independently_domain_validated=false`. Updated UI/readme copy; verifier refuses a forged trained-model claim. | Using the phrase “AI Core” as a project name does not supply trained semantic capability. |
| **F29** | Exact source-span candidate output retains unknown identities. A bounded string-similarity suggestion list is attached for reviewer investigation, without adding accepted concepts, origin, or allergens. Unusual combinations/invisible format characters trigger review. | Similar spelling is never material identity proof. The suggestions are **English-seed limited**, not validated for AZ/RU transliteration. |
| **F30** | Integrity-pinned reference corpus remains enforced. Every run discloses vocabulary version, manifest SHA-256, editorial status, and declared language-alias inventory. Introduced a corpus evaluation harness rather than claiming seed coverage from vocabulary size. | Integrity pinning cannot verify scientific correctness; substantive expert content validation is outstanding. |
| **F31** | Output and UI explicitly distinguish the editorial seed from scientifically validated food data. Production approval remains false. | Expert scientific/food-regulatory review is not supplied. |
| **F32** | Removed the previous test of model coverage against the same lexical extractor's segment list. `source_coverage()` checks source-offset surface characters independently of the vocabulary. It detects uncovered nonseparator characters, ambiguous combined segments, and invisible characters and records `semantic_coverage_established=false`. | Literal offsets cannot prove the correct number of ingredients, nested composition, or semantic recall; structural ambiguity stays review-required. |
| **F33** | `bahar_ai_core.benchmark` and `scripts/benchmark_f28_f38.py` accept independently labeled case metadata, immutable text hashes, exact gold spans, adjudicated concept IDs, allergen categories, language and document type. Reports strata (az/en/ru/mixed/other), failed/unknown cases, precision, recall and false-negative rate. | No representative actual supplier corpus was provided. Report says reviewer identities are **declared, not authenticated** and population representativeness is **not established**. No industrial accuracy number is claimed. |
| **F34** | Preserves Unicode source offsets; supports additional list separators without inventing identity; Cyrillic identity text is explicitly indeterminate, language coverage is disclosed, unknown multilingual terms remain unknown. | This is a **safe uncertainty response**, not a qualified Russian/Azerbaijani NER or transliteration model. Actual language-specific dataset expansion and field benchmark remain necessary. |
| **F35** | Changed PDF extraction from document-wide native-vs-OCR selection to per-page selection and explicit per-page status. Pages with native text plus raster images are flagged for review; blank OCR output remains unresolved. Added `scripts/benchmark_ocr_f35.py` for user-supplied independently transcribed page CER/WER and per-language evaluation. | No representative page transcriptions or production OCR tests were provided, so **measured production CER/WER is unavailable**. Native text quality itself may be wrong; raster regions alongside native text are *flagged*, not automatically resolved. |
| **F36** | Each candidate now carries `independent_identity_verified=false` and `REFERENCE_CANDIDATE_ONLY`; benchmarking separates source-span identity, adjudicated concept identity, and category match. Persistence verifier recomputes source coverage. | Source grounding proves which characters were extracted, not that they have been interpreted scientifically correctly. |
| **F37** | External provider mode requires a declared dated/versioned immutable model ID, exact echoed provider model ID, pinned prompt/schema SHA-256, no tool calls, strict schema, HTTPS/allowed endpoint rules, and untrusted-instruction warnings. Reports cannot claim provider model validation. Added identical-corpus drift comparison and adversarial tests. | Model names and provider echoes do **not** cryptographically attest actual model weights. Provider model stability, prompt-injection resilience, reliability, privacy, and operational security still need independent qualification. Static corpus comparison is not autonomous continuous drift detection. |
| **F38** | Per-allergen false negative counts and valid-denominator false-negative rates. Exact unmatched gold source positions are retained for error investigation; undefined metrics remain null. | No large, independent adversarial synonym/trade-name corpus exists in the supplied materials; real-world false-negative estimates cannot be asserted. |

## Executable verification

From the project root:

```bash
python3 -m pip install -e '.[dev]'
PYTHONPATH=src python3 -m pytest -q
node --check web/app.js
```

The testing suite includes adversarial synthetic fixtures for misspellings, punctuation, Cyrillic names, tampered ground-truth hashes, zero-observation accuracy, two-page mixed PDFs, native-page raster content, prompt-injection text, mismatched provider identities and tool-calling output. These demonstrate **control behavior**, not multilingual performance.

## Independent ingredient benchmark input contract

Use UTF-8 JSON Lines with one document per line. Every line must include:

- `document_id` — unique document key.
- `source_text` — exact Unicode source as independently transcribed for the benchmark.
- `sha256` — SHA-256 of the UTF-8 source bytes.
- `language` — `az`, `en`, `ru`, `mixed`, or `other`.
- `document_type` — `supplier_specification`, `recipe`, `ingredient_label`, or `other`.
- `reviewed_by` and `adjudicated_by` — different accountable identity strings; they are *not* independently authenticated by the tool.
- `ingredient_spans` — nonoverlapping adjudicated source occurrences in order. Each item requires integer `start` and `end` Unicode character offsets, exact `text`, list `allergen_categories`, `identity_state` (`IDENTIFIED`, `UNKNOWN`, `CONTESTED`), and `reference_concept_id` (a known vocabulary concept for IDENTIFIED, null for other states). The fact that the tool uses a particular controlled vocabulary still requires scientific validation.

No fabricated benchmark corpus is included. With no cases, the runner refuses to produce accuracy numbers.

```bash
PYTHONPATH=src python scripts/benchmark_f28_f38.py data/private_adjudicated_cases.jsonl --out benchmark_report.json
PYTHONPATH=src python scripts/benchmark_f28_f38.py data/private_adjudicated_cases.jsonl --baseline benchmark_report.json --out new_benchmark_report.json
```

The second command performs a **same-corpus static regression check**; it refuses comparison if the corpus SHA-256 changes. Sensitivity to new source-document populations requires separate monitoring and investigation.

## OCR benchmark input contract

Use one JSON Lines row for each independently transcribed page: `document_id`, 1-based integer `page`, `language`, exact `truth`, `observed` OCR text, `transcribed_by`, and separate `verified_by`. No assumption is made that OCR confidence equals ground truth.

```bash
PYTHONPATH=src python scripts/benchmark_ocr_f35.py data/private_ocr_pages.jsonl --max-cer 0.05 --max-wer 0.15 --out ocr_report.json
```

CER and WER are **page-level error rates** calculated relative to the submitted transcriptions. Their arithmetic means are not population estimates and do not prove compliance with any regulatory document-readability criterion.

## External model mode

The source-only distribution includes `data/bahar_demo_input.json`, a deliberately synthetic BAHAR-schema demo fixture. It is not evaluation ground truth.

```bash
PYTHONPATH=src python -m bahar_ai_core.cli audit data/bahar_demo_input.json --mode lexical
```

By default, the lexical demonstration does **not** require an API key. To deliberately use an external model in BAHAR's CLI, configure an explicit dated model revision (availability and provider behavior must be confirmed independently):

```bash
export BAHAR_MODEL='gpt-4.1-mini-2025-04-14'
export BAHAR_MODEL_REVISION="$BAHAR_MODEL"
export OPENAI_API_KEY='...'
PYTHONPATH=src python -m bahar_ai_core.cli audit data/bahar_demo_input.json --mode llm
```

The model identifier above illustrates the *expected pinning syntax*; it does **not** guarantee that a provider currently offers that revision. A missing key, missing model pin, mismatched provider response or unsafe response causes the extraction attempt to fail without issuing a substantive outcome. Never commit keys to the repository.

## Unresolved items / no false completion claim

1. Commission an external domain-review process for ingredient relationships, supplier trade names, and regulated origin interpretations.
2. Collect a representative, licensed, privacy-reviewed corpus of real AZ/EN/RU supplier documents with separately adjudicated identities and allergens. Measure false negatives, intervals, and difficult cases, then version the benchmark.
3. Validate OCR CER/WER on real native/scanned/mixed PDFs, photographs, and print artifacts. Incorporate manual region correction and calibration.
4. Qualify external model behavior, provider revision stability and prompt-injection resistance with representative deployments and change-control gates.
5. Fully resolve previously identified **F01–F07**, and complete PostgreSQL, authentication, and production release qualification inherited from F08–F27.

**Engineering distinction:** This release *fixes unsupported promotions of certainty and adds the instrumentation needed to evaluate capabilities*. It cannot by itself remove uncertainty about data or models that have not been independently observed, validated, or benchmarked.
