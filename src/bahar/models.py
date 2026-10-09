from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Iterable


class ExecutionState(StrEnum):
    CREATED = "created"
    RUNNING = "running"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
    CANCELLED = "cancelled"


class CheckState(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    INDETERMINATE = "indeterminate"
    NOT_RUN = "not_run"
    ERROR = "error"


class GateState(StrEnum):
    NOT_ISSUED = "not_issued"
    BLOCKED = "blocked"
    NEEDS_REVIEW = "needs_review"
    READY_FOR_REVIEW = "ready_for_review"


class EvidenceState(StrEnum):
    UNKNOWN = "unknown"
    SUPPORTED_POSITIVE = "supported_positive"
    SUPPORTED_NEGATIVE = "supported_negative"
    CONFLICTED = "conflicted_evidence"


class AuthorityKind(StrEnum):
    BINDING_LAW = "binding_law"
    INCORPORATED_STANDARD = "incorporated_standard"
    VOLUNTARY_STANDARD = "voluntary_standard"
    OFFICIAL_GUIDANCE = "official_guidance"
    REFERENCE = "reference"


class AssessmentMode(StrEnum):
    DEMONSTRATION = "demonstration"
    PRODUCTION = "production"


class ClaimType(StrEnum):
    INGREDIENT_EXTRACTION = "ingredient_extraction"
    FORMULATION_CONSISTENCY = "formulation_consistency"
    REGULATORY_APPLICABILITY = "regulatory_applicability"
    EXPOSURE_RISK = "exposure_risk"
    TECHNICAL_READINESS = "technical_readiness"
    BATCH_COMPOSITION = "batch_composition"


FINAL_CHECK_STATES = {
    CheckState.PASS,
    CheckState.FAIL,
    CheckState.INDETERMINATE,
}


@dataclass(frozen=True)
class EvidencePair:
    positive: bool
    negative: bool

    @property
    def state(self) -> EvidenceState:
        return {
            (False, False): EvidenceState.UNKNOWN,
            (True, False): EvidenceState.SUPPORTED_POSITIVE,
            (False, True): EvidenceState.SUPPORTED_NEGATIVE,
            (True, True): EvidenceState.CONFLICTED,
        }[(self.positive, self.negative)]


def coverage(required: Iterable[str], checks: dict[str, dict[str, Any]]) -> float | None:
    required_set = set(required)
    if not required_set:
        return None
    executed = sum(
        1
        for check_id in required_set
        if CheckState(checks.get(check_id, {}).get("state", CheckState.NOT_RUN))
        in FINAL_CHECK_STATES
    )
    return executed / len(required_set)


def metric(numerator: int, denominator: int) -> float | None:
    """Return a metric value without manufacturing a value for 0/0."""
    return None if denominator == 0 else numerator / denominator

