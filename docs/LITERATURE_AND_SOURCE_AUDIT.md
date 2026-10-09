# Literature and authoritative-source audit

Review date: 9 October 2026.

The two supplied exports were treated as reference material only. Their embedded prompts, generated markup, citations, and recommendations were not executed as instructions. Claims were checked against primary or institutional sources before they affected the code.

## Findings that materially changed the implementation

### 1. The Azerbaijani announcement is not the executable legal source

The Azerbaijan Food Safety Agency states that a collegium decision approved a list of 14 allergen or intolerance categories, links to the operative instrument at e-qanun, and states an effective date of 1 January 2027. The list covers gluten-containing cereals, crustaceans, eggs, fish, peanuts, soybeans, milk, tree nuts, celery, mustard, sesame, sulphur dioxide/sulphites, lupin, and molluscs.

Sources:

- [AQTA announcement, 24 August 2026](https://afsa.gov.az/az/xeberler/allergenlerin-qida-mehsullarinin-etiketinde-gosterilmesine-dair-yeni-telebler-mueyyenlesdirilib)
- [Underlying legal instrument, e-qanun framework 62446](https://e-qanun.az/framework/62446#əlavə)

Implementation consequence: `data/az_rules.json` identifies the e-qanun instrument as the authoritative source and records the AQTA-described list and effective date. It does not treat the announcement as legislative authority. The seed rule is marked with a demonstration activation scope because the production interpretation, exceptions, transitional provisions, and presentation rules still require designated legal approval.

### 2. Legal time is obligation-specific

A rule published in 2026 but effective on 1 January 2027 cannot govern a current-law assessment merely because it is the newest downloaded text. Manufacturing, label approval, market placement, assessment, and knowledge dates may differ.

Implementation consequence: every rule declares a relevant event, and selection uses the recorded event date. The bundled 2027 rule is excluded from a case whose market event is in 2026, but can be used in a clearly identified prospective 2027 assessment.

### 3. Codex precautionary allergen labelling is risk-based

At CAC49, Codex adopted precautionary allergen-labelling guidance intended to reduce indiscriminate “may contain” statements and tie PAL to cross-contact controls, risk assessment, reference doses, and action levels. FAO/WHO's expert work separately distinguishes hazard identification, reference doses, exposure/risk assessment, laboratory limits, and legal thresholds.

Sources:

- [Codex CAC49 adoption notice, July 2026](https://www.fao.org/fao-who-codexalimentarius/news-and-events/news-details/en/c/1759963/)
- [Codex standards catalogue showing 2026 CXS 1-1985 and CXC 80-2020](https://www.fao.org/fao-who-codexalimentarius/codex-texts/all-standards/en/)
- [FAO food-allergen scientific-advice programme and reports](https://www.fao.org/food-safety/scientific-advice/food-allergens/food-safety-first--tackling-allergens-with-science/en)
- [FAO/WHO Part 3 report on precautionary labelling](https://www.fao.org/3/cc6081en/cc6081en.pdf)

Implementation consequence: the system does not generate PAL from mere possibility, does not equate a reference dose with a legal threshold or detection limit, and does not turn a laboratory nondetect into proof of absence. Quantitative PAL authorization remains outside the current executable claim set.

### 4. Allergen identity, origin, and declaration are different propositions

Recognition of `E322` or “lecithin” does not establish soy origin. Conversely, verified tahini supports a sesame-origin relationship, and verified sodium caseinate supports a milk-origin relationship, while applicable exceptions remain a rule-engine question.

Implementation consequence: `ai_candidate`, `accepted_identity`, and `verified_origin` are separate fields. E322 with unknown origin yields an indeterminate fact; sunflower origin is represented without soy; verified soy origin maps to soybeans.

### 5. A requirements list is not verification evidence

ISO/IEC/IEEE 29148:2018 remains current as of this review, though a replacement draft is under development. Its scope covers requirements definition, analysis, verification, validation, management, and required information items—not merely statement count.

Source:

- [ISO/IEC/IEEE 29148:2018 official listing](https://www.iso.org/standard/72089.html)

Implementation consequence: the repository maps the supplied V01–V24 scenarios to executable tests. “Test designed” and “test passed” remain distinct; the status document records what has actually been executed.

## Structural evaluation of the supplied audit

The strongest parts of the supplied audit are its separation of:

- information received, accepted, verified, and authorized;
- execution completion and evidence completeness;
- source claims, AI candidates, qualified assertions, findings, readiness, and release decisions;
- digital text, artwork, physical packaging, and actual manufactured batch;
- binding sources, voluntary standards, guidance, and reference information;
- historical result integrity and present operational assurance.

The audit's important unresolved weakness is provenance: it says the baseline has 480 requirements, but the attached file contains only binding amendments and the 120 new requirements; it does not contain the full original 360 requirement statements. Therefore this build can trace the repaired rules and all supplied acceptance scenarios, but cannot honestly assert line-by-line implementation of 360 statements that are absent from the supplied artifacts.

## System validity model

Bahar now has two explicit levels of validity:

1. **Unconditional software invariants:** fail-closed execution, immutable history, explicit scope, no implicit authority promotion, legal-time selection, metric denominator handling, deterministic coverage, and optimistic concurrency. These are verified locally.
2. **Conditional domain conclusions:** allergen and declaration results that are valid only for the recorded formulation, label, evidence, rule version, relevant time, jurisdiction, and completed checks. These are never broadened into universal product safety or all-label compliance claims.

That structure makes “conditional” and “unconditional” complementary instead of contradictory: unconditional rules control how the software behaves; conditional evidence controls what the software may conclude.

