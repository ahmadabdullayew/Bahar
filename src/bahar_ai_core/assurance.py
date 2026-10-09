"""Fail-closed assessment structural verifier; no claim of independent source authenticity.

This validates that a persisted demonstration result is internally consistent with its
immutable snapshot and bounded execution contract. It cannot prevent a privileged
attacker from modifying both implementation and stored records.
"""
from __future__ import annotations
from collections import Counter
from hashlib import sha256
import json
import re

DIGEST = re.compile(r"[0-9a-f]{64}\Z")
STATES = {"CREATED", "COMPLETED", "FAILED"}
GATES = {"NOT_ISSUED", "BLOCKED", "NEEDS_REVIEW", "READY_FOR_REVIEW"}
CHECKS = {"PASS", "FAIL", "INDETERMINATE", "NOT_RUN", "ERROR"}
REQUIRED = ("candidate_extraction", "ingredient_origin", "label_comparison")


class AssuranceError(ValueError):
    pass


def digest_json(value):
    return sha256(json.dumps(value, sort_keys=True, ensure_ascii=False,
                             separators=(",", ":"), allow_nan=False).encode("utf-8")).hexdigest()


def validate_assessment(result: dict) -> None:
    """Validate structural/snapshot invariants before storage; not scientific correctness."""
    from .engine import CONTRACT, ENGINE_VERSION
    from .gates import readiness
    from .knowledge import classify_fragment, label_mentions
    from .knowledge import KNOWLEDGE, KnowledgeRepository
    if not isinstance(result, dict):
        raise AssuranceError("Assessment must be an object")
    if not isinstance(result.get("assessment_id"), str) or not re.fullmatch(r"[0-9a-f]{32}", result["assessment_id"]):
        raise AssuranceError("Invalid generated assessment identity")
    if result.get("engine_version") != ENGINE_VERSION:
        raise AssuranceError("Assessment engine version mismatch")
    contract = result.get("assessment_contract")
    if not isinstance(contract, dict) or any(contract.get(k) != v for k, v in CONTRACT.items() if k != "reference_profile"):
        raise AssuranceError("Unknown or modified assessment contract")
    if contract.get("reference_profile") not in KNOWLEDGE.profiles:
        raise AssuranceError("Unknown reference profile")
    if result.get("knowledge_status") != "EDITORIAL_SEED_NOT_DOMAIN_VALIDATED" or result.get("legal_verdict") != "NOT_EVALUATED":
        raise AssuranceError("Unsupported authoritative status in demonstration assessment")
    snap = result.get("source_snapshot")
    if not isinstance(snap, dict) or set(snap) != {"product_id", "recipe_version", "recipe_text", "label_version", "label_text", "evidence_assertions"}:
        raise AssuranceError("Source snapshot malformed")
    digest = result.get("snapshot_sha256")
    if not isinstance(digest, str) or not DIGEST.fullmatch(digest) or digest_json(snap) != digest:
        raise AssuranceError("Snapshot integrity mismatch")
    if result.get("context") != {k: snap[k] for k in ("product_id", "recipe_version", "label_version")}:
        raise AssuranceError("Assessment context does not match snapshot")
    manifest = result.get("execution_manifest")
    if not isinstance(manifest, dict):
        raise AssuranceError("Execution manifest missing")
    repo = KNOWLEDGE if contract["reference_profile"] == KNOWLEDGE.profile else KnowledgeRepository(profile=contract["reference_profile"])
    expected = {"engine": ENGINE_VERSION, "reference_profile": repo.profile,
                "knowledge_dataset_id": repo.manifest["dataset_id"],
                "knowledge_dataset_version": repo.manifest["version"],
                "knowledge_manifest_sha256": repo.manifest_sha256,
                "knowledge_selection_sha256": repo.digest,
                "vocabulary_sha256": repo.digest,
                "reference_profile_mode": repo.profiles[repo.profile]["mode"],
                "editorial_alias_language_counts": repo.alias_language_counts,
                "editorial_alias_review_status": repo.alias_review_status,
                "rule_profile": CONTRACT["rule_profile"],
                "recipe_sha256": sha256(snap["recipe_text"].encode()).hexdigest(),
                "label_sha256": sha256(snap["label_text"].encode()).hexdigest()}
    if any(manifest.get(k) != v for k, v in expected.items()):
        raise AssuranceError("Manifest conflicts with snapshot, dataset or executable contract")
    capability = result.get("extraction_capability")
    if not isinstance(capability, dict) or capability.get("independently_domain_validated") is not False:
        raise AssuranceError("Extraction capability claim cannot assert unverified validation")
    if manifest.get("mode") == "lexical" and (capability.get("trained_model") is not False or
            capability.get("kind") != "DETERMINISTIC_LEXICAL_BASELINE"):
        raise AssuranceError("Lexical output misrepresented as trained AI")
    if manifest.get("mode") == "llm" and result.get("execution_status") == "COMPLETED":
        request = manifest.get("external_model_request")
        if (not isinstance(request, dict) or request.get("provider_model_version_verified") is not True
                or request.get("requested_model_revision") != manifest.get("model")
                or manifest.get("pinned_model_revision") != manifest.get("model")):
            raise AssuranceError("Unpinned or unverified external-model execution")
    if manifest.get("mode") not in ("lexical", "llm"):
        raise AssuranceError("Unknown extraction mode")
    if result.get("execution_status") not in STATES or result.get("technical_readiness") not in GATES:
        raise AssuranceError("Unknown execution or readiness state")
    if result["execution_status"] != "COMPLETED" and result["technical_readiness"] != "NOT_ISSUED":
        raise AssuranceError("Non-completed execution has issued a technical result")
    checks = result.get("checks")
    if not isinstance(checks, dict) or set(checks) != set(REQUIRED) or any(x not in CHECKS for x in checks.values()):
        raise AssuranceError("Invalid mandatory check inventory")
    coverage = result.get("coverage")
    complete = [k for k in REQUIRED if checks[k] in ("PASS", "FAIL", "INDETERMINATE")]
    if (not isinstance(coverage, dict) or coverage.get("required") != list(REQUIRED)
            or coverage.get("completed") != complete
            or coverage.get("ratio") != len(complete)/len(REQUIRED)):
        raise AssuranceError("Inconsistent check coverage")
    candidates = result.get("candidates")
    if not isinstance(candidates, list) or len(candidates) > 200:
        raise AssuranceError("Invalid candidates")
    spans = []
    for c in candidates:
        if not isinstance(c, dict) or not isinstance(c.get("text"), str):
            raise AssuranceError("Malformed candidate")
        start_end = c.get("span")
        if not isinstance(start_end, list) or len(start_end) != 2 or any(type(x) is not int for x in start_end):
            raise AssuranceError("Malformed candidate span")
        start, end = start_end
        source = snap["recipe_text"]
        if not 0 <= start < end <= len(source) or source[start:end] != c["text"]:
            raise AssuranceError("Candidate not grounded in input snapshot")
        if c.get("candidate_id") != sha256(f"{start}|{end}|{c['text']}".encode()).hexdigest()[:24]:
            raise AssuranceError("Candidate identity mismatch")
        ids = c.get("matched_knowledge_concept_candidates")
        if (not isinstance(ids, list) or any(cid not in repo.concepts for cid in ids)
                or c.get("accepted_concepts") != ids):
            raise AssuranceError("Invalid reference concepts")
        expected_ids, recognized_categories, expected_unresolved = classify_fragment(c["text"], repo)
        if ids != list(expected_ids) or c.get("unresolved") != expected_unresolved:
            raise AssuranceError("Candidate identity or uncertainty differs from pinned vocabulary")
        expected_categories = sorted({cat for cid in ids for cat in repo.concepts[cid].allergens})
        # Standalone generic category candidates have no identity; preserve this narrow exception.
        actual = c.get("reference_category_candidates")
        if (not isinstance(actual, list) or any(cat not in repo.raw_categories for cat in actual)
                or c.get("allergens") != actual):
            raise AssuranceError("Candidate reference categories malformed")
        if sorted(actual) != sorted(recognized_categories):
            raise AssuranceError("Candidate categories do not match the pinned knowledge reference")
        spans.append((start, end))
    if spans != sorted(spans) or any(a[1] > b[0] for a,b in zip(spans, spans[1:])):
        raise AssuranceError("Unsorted or overlapping candidates")
    if len(set(c["candidate_id"] for c in candidates)) != len(candidates):
        raise AssuranceError("Duplicate candidate identity")
    if not isinstance(result.get("findings"), list):
        raise AssuranceError("Invalid findings")
    if result.get("recipe_allergens") != sorted({cat for c in candidates for cat in c["allergens"]}):
        raise AssuranceError("Recipe category aggregate differs from candidates")
    if result["execution_status"] == "COMPLETED":
        from .extraction import source_coverage, Candidate
        reconstructed = [Candidate(c["text"], c["span"][0], c["span"][1],
                                   c["proposed_concept"], tuple(c["accepted_concepts"]),
                                   tuple(c["allergens"]), c["unresolved"], c["extraction_origin"])
                         for c in candidates]
        if result.get("extraction_surface_assurance") != source_coverage(snap["recipe_text"], reconstructed):
            raise AssuranceError("Surface coverage assurance differs from source bytes and candidate spans")
        actual_mentions = label_mentions(snap["label_text"], repo) if snap["label_text"].strip() else []
        if result.get("label_mentions") != actual_mentions:
            raise AssuranceError("Label mentions do not match pinned text parser")
        if result.get("label_allergen_mentions") != sorted({m["allergen"] for m in actual_mentions}):
            raise AssuranceError("Label category aggregate mismatch")
        if result.get("technical_readiness") != readiness(result["execution_status"], coverage, checks, result["findings"]):
            raise AssuranceError("Technical gate does not match the formal policy")
    if result["execution_status"] != "COMPLETED" and result["findings"]:
        raise AssuranceError("Noncompleted assessment contains final findings")
    if result["execution_status"] == "COMPLETED":
        findings = result["findings"]
        if result["technical_readiness"] == "NOT_ISSUED":
            raise AssuranceError("Completed result lacks technical gate")
        if result["technical_readiness"] == "READY_FOR_REVIEW" and any(x in ("NOT_RUN", "INDETERMINATE", "ERROR") for x in checks.values()):
            raise AssuranceError("Incomplete assessment was marked ready")
        if any(not isinstance(f, dict) or f.get("legal_violation_confirmed") is True for f in findings):
            raise AssuranceError("Invalid or unsupported finding")
    if result["execution_status"] == "FAILED" and candidates:
        raise AssuranceError("Failed evaluation cannot persist accepted final candidates")
    # In lexical mode, the engine is deterministic over its frozen source snapshot.
    # Recompute every critical output; this prevents a tampered yet internally
    # plausible finding set being accepted as the engine's own result. External
    # model calls are intentionally NEVER repeated by this verifier.
    if result["execution_status"] == "COMPLETED" and manifest["mode"] == "lexical":
        from .engine import Input, run
        if manifest.get("extractor") != "lexical_baseline_v0_4_dataset":
            raise AssuranceError("Nonstandard lexical extractor cannot be claimed as baseline on persistence")
        replay = run(Input(snap["product_id"], snap["recipe_version"], snap["recipe_text"],
                           snap["label_version"], snap["label_text"],
                           tuple(snap["evidence_assertions"])),
                     mode="lexical", reference_profile=repo.profile)
        for name in ("candidates", "checks", "coverage", "findings", "label_mentions",
                     "label_allergen_mentions", "recipe_allergens", "evidence_states",
                     "evidence_assertions", "unqualified_evidence", "technical_readiness"):
            if result.get(name) != replay.get(name):
                raise AssuranceError(f"Lexical deterministic replay mismatch: {name}")


def assert_consistent_for_review(assessment: dict, candidate: dict, concept_id: str) -> None:
    """Demo review cannot silently accept an unrelated identity as if validated."""
    if concept_id not in candidate.get("matched_knowledge_concept_candidates", []):
        raise AssuranceError("Reviewer cannot accept an ungrounded concept via this demo API; request evidence instead")
