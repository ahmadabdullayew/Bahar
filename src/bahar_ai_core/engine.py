"""Evidence-constrained demonstration assessor. NEVER product or legal approval."""
from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from uuid import uuid4
import json
from .knowledge import label_mentions, VOCABULARY_DIGEST, KNOWLEDGE, BY_ID, KnowledgeRepository, DEFAULT_PROFILE, cereal_source_for_concept, textual_label_conflicts
from .extraction import LexicalExtractor, OpenAICompatibleExtractor, ExtractionError, Candidate, MAX_SOURCE_CHARS, candidate_diagnostics, source_coverage
from .evidence import summarize, validate_assertions, evidence_digest
from .gates import readiness

ENGINE_VERSION = "0.5.0"
REVIEW_CAVEAT_FLAGS = frozenset({
    "PROCESS_REVIEW", "COMPOUND_REVIEW", "SOURCE_REVIEW", "LEGAL_EXCEPTION_REVIEW",
    "CONCENTRATION_REQUIRED", "SOURCE_NOT_PROTEIN_PROOF", "WHEAT_CO_INGREDIENT_POSSIBLE"
})
CONTRACT = {
    "id": "LG-DEMO-INGREDIENT-LABEL-CONSISTENCY", "version": ENGINE_VERSION,
    "mode": "DEMONSTRATION_ONLY", "jurisdiction": "NONE_DEMO_PROFILE",
    "claims": ["potential_ingredient_allergen_declaration_discrepancy", "uncertainty", "local_change_impact"],
    "exclusions": ["legal_compliance", "product_safety", "actual_batch_composition",
                   "cross_contact_risk", "physical_packaging_accuracy", "release_authorization"],
    "required_checks": ["candidate_extraction", "ingredient_origin", "label_comparison"],
    "rule_profile": "LG-DATASET-REFERENCE-TEXT-MENTION-v0.4",
    "reference_profile": KNOWLEDGE.profile, "knowledge_seed_version": KNOWLEDGE.manifest["version"],
}
LIMITATIONS = [
    "DEMO ONLY: no regulatory, food-safety, physical manufacturing or release certification",
    "The 160-concept ingredient dataset is an unreviewed editorial seed, not a validated scientific or legal ontology",
    "Lexical baseline is deterministic rules and NOT a trained or externally validated semantic AI model",
    "Exact source coverage is not semantic recall or complete ingredient recognition",
    "AZ/EN/RU, misspellings, transliteration, supplier nomenclature and OCR have no independent representative accuracy estimate",
    "Every identified allergen source/category is a candidate reference association, NOT accepted material-lot truth",
    "The reference taxonomy differs by jurisdiction; it does NOT supply country-specific legal rules",
    "Documented ingredients do not establish actual produced-batch composition",
    "Positive textual allergen mentions are not proof of legally adequate declaration or visual presentation",
    "Input-qualified evidence is USER-DECLARED, not independently authenticated or scientifically verified",
    "A completed processing attempt and technical readiness do not establish legal compliance",
]

@dataclass(frozen=True)
class Input:
    product_id: str
    recipe_version: str
    recipe_text: str
    label_version: str
    label_text: str
    evidence_assertions: tuple[dict, ...] = ()


def stable_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


def snapshot_value(item: Input) -> dict:
    return {"product_id": item.product_id, "recipe_version": item.recipe_version,
            "recipe_text": item.recipe_text, "label_version": item.label_version,
            "label_text": item.label_text, "evidence_assertions": list(item.evidence_assertions)}


def _sha(value: object) -> str:
    return sha256(stable_json(value).encode("utf-8")).hexdigest()


def _validate_input(item: Input) -> None:
    if not isinstance(item, Input):
        raise ValueError("Input must be a typed assessment input")
    for field in ("product_id", "recipe_version", "label_version"):
        value = getattr(item, field)
        if not isinstance(value, str) or not value.strip() or len(value) > 256:
            raise ValueError(f"Invalid required identity: {field}")
    for field in ("recipe_text", "label_text"):
        value = getattr(item, field)
        if not isinstance(value, str) or len(value) > MAX_SOURCE_CHARS:
            raise ValueError(f"Invalid or oversized text field: {field}")
    if not item.recipe_text.strip():
        raise ValueError("Empty formulation text is not assessable")
    validate_assertions(item.evidence_assertions)


def _candidate_row(c: Candidate, item: Input, knowledge: KnowledgeRepository) -> dict:
    return {"candidate_id": c.candidate_id, "text": c.text, "span": [c.start, c.end],
            "proposed_concept": c.proposed_concept,
            "accepted_concepts": list(c.accepted_concepts), "allergens": list(c.allergens),
            "matched_knowledge_concept_candidates": list(c.accepted_concepts),
            "reference_category_candidates": list(c.allergens),
            "ingredient_knowledge_status": "EDITORIAL_SEED_NOT_INDEPENDENTLY_VERIFIED",
            "identity_assurance": candidate_diagnostics(c.text, c.accepted_concepts, knowledge),
            "recognized_identity_is_material_truth": False,
            "knowledge_caveat_flags": sorted({flag for cid in c.accepted_concepts for flag in knowledge.concepts[cid].caveats}),
            "declaration_verdict": "NOT_EVALUATED",
            "approved_for_production": False,
            "unresolved": c.unresolved, "extraction_origin": c.origin,
            "source_ref": f"recipe:{item.recipe_version}",
            "candidate_not_material_truth": True}


def run(item: Input, *, mode: str = "lexical", extractor=None, reference_profile: str = DEFAULT_PROFILE) -> dict:
    """Runs on a fresh immutable input snapshot; failure never produces a final assessment.

    extractor injection is for deterministic testing only, and is not exposed on the CLI.
    """
    knowledge = KNOWLEDGE if reference_profile == DEFAULT_PROFILE else KnowledgeRepository(profile=reference_profile)
    if extractor is not None and reference_profile != DEFAULT_PROFILE:
        raise ValueError('Custom test extractors require the default reference profile')
    now = datetime.now(timezone.utc).isoformat()
    base = {
        "assessment_id": uuid4().hex, "engine_version": ENGINE_VERSION,
        "assessment_contract": {**CONTRACT, "reference_profile": knowledge.profile}, "created_at": now,
        "context": {}, "execution_manifest": {"engine": ENGINE_VERSION, "mode": mode,
           "vocabulary_sha256": knowledge.digest, "rule_profile": CONTRACT["rule_profile"],
           "knowledge_dataset_id": knowledge.manifest["dataset_id"],
           "knowledge_dataset_version": knowledge.manifest["version"],
           "knowledge_manifest_sha256": knowledge.manifest_sha256,
           "knowledge_selection_sha256": knowledge.digest,
           "reference_profile": knowledge.profile, "reference_profile_mode": knowledge.profiles[knowledge.profile]["mode"],
           "editorial_alias_language_counts": knowledge.alias_language_counts,
           "editorial_alias_review_status": knowledge.alias_review_status},
        "snapshot_sha256": None, "source_snapshot": None,
        "execution_status": "CREATED", "technical_readiness": "NOT_ISSUED",
        "findings": [], "candidates": [], "evidence_states": {}, "evidence_assertions": [],
        "label_mentions": [], "recipe_allergens": [], "label_allergen_mentions": [],
        "knowledge_status": "EDITORIAL_SEED_NOT_DOMAIN_VALIDATED", "legal_verdict": "NOT_EVALUATED",
        "checks": {name: "NOT_RUN" for name in CONTRACT["required_checks"]},
        "coverage": {"required": list(CONTRACT["required_checks"]), "completed": [], "ratio": 0.0},
        "limitations": list(LIMITATIONS),
        "assurance_version": "structural-0.5",
        "extraction_capability": {
            "lexical": {"kind": "DETERMINISTIC_LEXICAL_BASELINE", "trained_model": False,
                        "independently_domain_validated": False},
            "llm": {"kind": "EXTERNAL_UNQUALIFIED_MODEL_CANDIDATES", "trained_model": True,
                    "independently_domain_validated": False},
        }[mode] if mode in ("lexical", "llm") else {"kind": "UNSUPPORTED"},
        "evaluation_status": "NO_INDEPENDENT_REPRESENTATIVE_BENCHMARK",

    }
    if isinstance(item, Input):
        base["context"] = {"product_id": item.product_id, "recipe_version": item.recipe_version,
                           "label_version": item.label_version}

    def mark(name: str, state: str):
        base["checks"][name] = state
        complete = [k for k in CONTRACT["required_checks"]
                    if base["checks"][k] in ("PASS", "FAIL", "INDETERMINATE")]
        base["coverage"] = {"required": list(CONTRACT["required_checks"]),
                            "completed": complete, "ratio": len(complete)/len(CONTRACT["required_checks"])}

    try:
        _validate_input(item)
        if mode not in ("lexical", "llm"):
            raise ValueError("Unsupported extraction mode")
        base["source_snapshot"] = snapshot_value(item)
        base["snapshot_sha256"] = _sha(base["source_snapshot"])
        base["execution_manifest"]["evidence_sha256"] = evidence_digest(item.evidence_assertions)
        base["execution_manifest"]["recipe_sha256"] = sha256(item.recipe_text.encode()).hexdigest()
        base["execution_manifest"]["label_sha256"] = sha256(item.label_text.encode()).hexdigest()
        evidence = summarize(item.evidence_assertions)
        base["evidence_states"] = evidence
        base["evidence_assertions"] = validate_assertions(item.evidence_assertions)
        base["unqualified_evidence"] = [r for r in base["evidence_assertions"]
                                         if r["qualification_origin"] == "UNREVIEWED"]
        selected = extractor if extractor is not None else (
            LexicalExtractor(knowledge) if mode == "lexical" else OpenAICompatibleExtractor(knowledge=knowledge))
        base["execution_manifest"]["extractor"] = getattr(selected, "name", "custom_test_extractor")
        if mode == "llm":
            base["execution_manifest"]["model"] = getattr(selected, "model", "unspecified")
            base["execution_manifest"]["pinned_model_revision"] = getattr(selected, "model_revision", None)
        candidates = selected.extract(item.recipe_text)
        if mode == "llm" and extractor is None:
            base["execution_manifest"]["external_model_request"] = selected.last_request_manifest
        if not isinstance(candidates, list) or not candidates or len(candidates) > 200:
            raise ExtractionError("No valid candidate set established")
        if any(not isinstance(c, Candidate) for c in candidates):
            raise ExtractionError("Extraction returned invalid candidate type")
        candidates.sort(key=lambda c: (c.start, c.end))
        if any(a.end > b.start for a, b in zip(candidates, candidates[1:])):
            raise ExtractionError("Overlapping candidate source spans")
        if any(item.recipe_text[c.start:c.end] != c.text for c in candidates):
            raise ExtractionError("Source text changed or candidates not grounded")
        # Surface coverage is computed over source offsets, NOT against another
        # lexical extractor's segmentation or its editorial vocabulary.
        coverage_assurance = source_coverage(item.recipe_text, candidates)
        base["extraction_surface_assurance"] = coverage_assurance
        # Instructions embedded in supplier documents are data, not commands.
        from .extraction import suspect_source_instructions
        source_instructions = suspect_source_instructions(item.recipe_text)
        if source_instructions:
            base["findings"].append({"code": "UNTRUSTED_SOURCE_INSTRUCTION_DETECTED",
                "source_spans": source_instructions,
                "message": "Source text resembles prompt instructions; identity and coverage need human review. No source instruction has authority."})
        missing_segments = coverage_assurance["uncovered_nonseparator_spans"]
        unexpected_segments = coverage_assurance["structural_warnings"]
        mark("candidate_extraction", "INDETERMINATE" if (missing_segments or unexpected_segments or source_instructions) else "PASS")
        base["candidates"] = [_candidate_row(c, item, knowledge) for c in candidates]
        known = {}
        unresolved = []
        review_caveats = []
        for c in candidates:
            flags = sorted({flag for cid in c.accepted_concepts for flag in knowledge.concepts[cid].caveats})
            blocking_flags = [f for f in flags if f in REVIEW_CAVEAT_FLAGS]
            if blocking_flags:
                review_caveats.append((c, blocking_flags))
            if c.unresolved:
                unresolved.append(c)
            for allergen in c.allergens:
                known.setdefault(allergen, []).append({"text": c.text, "span": [c.start, c.end],
                                                        "source_ref": f"recipe:{item.recipe_version}",
                                                        "candidate_id": c.candidate_id})
        ambiguous_language = [c for c in candidates if "CYRILLIC_TEXT_WITHOUT_QUALIFIED_LANGUAGE_BENCHMARK"
                              in candidate_diagnostics(c.text, c.accepted_concepts, knowledge)["review_reasons"]]
        mark("ingredient_origin", "INDETERMINATE" if (unresolved or ambiguous_language) else "PASS")
        if ambiguous_language:
            base["findings"].append({"code": "LANGUAGE_REVIEW_REQUIRED",
                "candidate_ids": [c.candidate_id for c in ambiguous_language],
                "message": "Cyrillic ingredient text requires qualified language-specific identification; transliteration is not identity verification"})
        base["recipe_allergens"] = sorted(known)
        if missing_segments or unexpected_segments:
            base["findings"].append({
                "code": "EXTRACTION_COVERAGE_INCOMPLETE", "fragments": missing_segments,
                "structural_parse_warnings": unexpected_segments,
                "message": "Non-separator source content remains uncovered or parsing shows structural ambiguity; no complete ingredient coverage",
            })
        if item.label_text.strip():
            mentions = label_mentions(item.label_text, knowledge)
            base["label_mentions"] = mentions
            contradictions = textual_label_conflicts(item.label_text, knowledge)
            if contradictions:
                base["findings"].append({
                    "code": "LABEL_TEXT_INTERPRETATION_UNCERTAIN", "conflicts": contradictions,
                    "legal_violation_confirmed": False,
                    "message": "Text includes apparently incompatible positive and negative reference-category mentions; no declaration conclusion",
                })
            known_mentions = {m["allergen"] for m in mentions}
            base["label_allergen_mentions"] = sorted(known_mentions)
            for allergen, references in sorted(known.items()):
                related = [(c, flags) for c, flags in review_caveats if allergen in c.allergens]
                if related:
                    base["findings"].append({
                        "code": "REFERENCE_RELATION_REQUIRES_REVIEW", "category": allergen,
                        "caveats": sorted({f for _, flags in related for f in flags}),
                        "message": "Seed association has processing, quantitative, compound, or legal-review caveats; no definitive declaration conclusion",
                        "legal_violation_confirmed": False,
                        "source_candidates": [c.candidate_id for c, _ in related],
                    })
                    continue
                if allergen not in known_mentions:
                    base["findings"].append({
                        "code": "POTENTIAL_MISSING_DISCLOSURE", "allergen": allergen,
                        "certainty": "DEMO_TEXT_MENTION_DIFFERENCE",
                        "message": "Recipe identifies this origin category but assessed label has no positive textual mention in the limited demo profile; qualified review required",
                        "recipe_evidence": references, "label_ref": f"label:{item.label_version}",
                        "legal_violation_confirmed": False,
                        "knowledge_status": "EDITORIAL_SEED_NOT_INDEPENDENTLY_VERIFIED",
                        "reference_profile": knowledge.profile,
                    })
            cereal_source_candidates = {
                src for c in candidates for cid in c.accepted_concepts
                for src in [cereal_source_for_concept(cid, knowledge)] if src is not None
            }
            cereal_source_mentions = {m['cereal_source'] for m in mentions if m.get('cereal_source')}
            if cereal_source_candidates and 'gluten_cereal' in known_mentions and not cereal_source_candidates.issubset(cereal_source_mentions):
                base['findings'].append({
                    'code':'CEREAL_SOURCE_REVIEW_REQUIRED',
                    'source_candidates':sorted(cereal_source_candidates),
                    'source_mentions':sorted(cereal_source_mentions),
                    'message':'Gluten-cereal reference category alone does not prove that each relevant cereal source is represented in the label',
                    'legal_violation_confirmed':False})
            mark("label_comparison", "FAIL" if any(f["code"] == "POTENTIAL_MISSING_DISCLOSURE" for f in base["findings"]) else "PASS")
        else:
            base["findings"].append({"code": "LABEL_NOT_AVAILABLE", "message": "Cannot execute label comparison"})
            mark("label_comparison", "NOT_RUN")
        for c, flags in review_caveats:
            base['findings'].append({
                'code':'INGREDIENT_KNOWLEDGE_REVIEW_REQUIRED',
                'fragment':c.text,
                'candidate_id':c.candidate_id,
                'caveats':flags,
                'legal_violation_confirmed':False,
                'message':'Curated reference ingredient has unresolved source, processing, compound, quantitative, or exception caveats'
            })
        for c in unresolved:
            base["findings"].append({
                "code": "INGREDIENT_ORIGIN_UNRESOLVED", "fragment": c.text, "certainty": "UNKNOWN_OR_PARTIAL",
                "message": "Ingredient identity or material-origin coverage incomplete under limited vocabulary",
                "recipe_evidence": {"source_ref": f"recipe:{item.recipe_version}", "span": [c.start, c.end],
                                    "candidate_id": c.candidate_id},
            })
        for key, state in evidence.items():
            if state["state"] == "CONFLICTED_EVIDENCE":
                base["findings"].append({
                    "code": "CONFLICTED_EVIDENCE", "claim": key,
                    "positive_refs": state["positive_refs"], "negative_refs": state["negative_refs"],
                    "qualification_origin": state["qualification_origin"],
                    "message": "Conflicting user-declared evidence requires verification; no authoritative source inferred",
                })
        if base["unqualified_evidence"]:
            base["findings"].append({
                "code": "EVIDENCE_QUALIFICATION_REQUIRED",
                "evidence_ids": sorted({a["evidence_id"] for a in base["unqualified_evidence"]}),
                "message": "Submitted unreviewed evidence has no qualified support status; scope and relevance require review",
                "legal_violation_confirmed": False,
            })
        base["execution_status"] = "COMPLETED"
        base["technical_readiness"] = readiness(base["execution_status"], base["coverage"],
                                               base["checks"], base["findings"])
        return base
    except (ExtractionError, ValueError, TypeError, KeyError) as exc:
        base.update(execution_status="FAILED", technical_readiness="NOT_ISSUED",
                    findings=[], candidates=[], recipe_allergens=[], label_allergen_mentions=[], label_mentions=[],
                    error_code="INVALID_INPUT_OR_EXTRACTION", error=str(exc)[:200])
        return base


def compare(before: Input, after: Input, *, mode: str = "lexical", reference_profile: str = DEFAULT_PROFILE) -> dict:
    if before.product_id != after.product_id:
        raise ValueError("Versions of different products are not comparable")
    first = run(before, mode=mode, reference_profile=reference_profile)
    second = run(after, mode=mode, reference_profile=reference_profile)
    if any(r["execution_status"] != "COMPLETED" for r in (first, second)):
        return {"status": "NOT_ISSUED", "before": first, "after": second,
                "impact_completeness": "UNKNOWN", "reason": "At least one assessment failed"}
    old, new = set(first["recipe_allergens"]), set(second["recipe_allergens"])
    return {
        "status": "COMPLETED", "product_id": before.product_id,
        "versions": [before.recipe_version, after.recipe_version],
        "added_allergen_categories": sorted(new-old),
        "removed_allergen_categories": sorted(old-new),
        "reassessment_required": (first["snapshot_sha256"] != second["snapshot_sha256"]),
        "impact_completeness": "LOCAL_INPUTS_ONLY",
        "conclusion_scope": "Changes to observed supported categories, not proof of actual composition changes",
        "note": "No upstream material-lot, downstream manufacturing or product-market dependency completeness established",
        "knowledge_manifest_sha256": first["execution_manifest"]["knowledge_manifest_sha256"],
        "knowledge_dataset_version": first["execution_manifest"]["knowledge_dataset_version"],
        "before": first, "after": second,
    }
