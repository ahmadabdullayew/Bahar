"""Pure demonstration gate policy shared by execution and persistence validation."""

INVESTIGATION_CODES = frozenset({
    "INGREDIENT_ORIGIN_UNRESOLVED", "CONFLICTED_EVIDENCE",
    "EXTRACTION_COVERAGE_INCOMPLETE", "REFERENCE_RELATION_REQUIRES_REVIEW",
    "CEREAL_SOURCE_REVIEW_REQUIRED", "INGREDIENT_KNOWLEDGE_REVIEW_REQUIRED",
    "EVIDENCE_QUALIFICATION_REQUIRED", "LABEL_TEXT_INTERPRETATION_UNCERTAIN",
    "UNTRUSTED_SOURCE_INSTRUCTION_DETECTED", "LANGUAGE_REVIEW_REQUIRED"
})


def readiness(execution_status: str, coverage: dict, checks: dict, findings: list[dict]) -> str:
    """Internal demo review gate; NEVER food-safety, compliance or release authorization."""
    if execution_status != "COMPLETED":
        return "NOT_ISSUED"
    if any(f.get("code") == "POTENTIAL_MISSING_DISCLOSURE" for f in findings):
        return "BLOCKED"
    if (coverage.get("ratio") != 1.0
            or any(state != "PASS" for state in checks.values())
            or any(f.get("code") in INVESTIGATION_CODES for f in findings)):
        return "NEEDS_REVIEW"
    return "READY_FOR_REVIEW"
