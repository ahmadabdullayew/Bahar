from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from .assessment import digest

from bahar_ai_core.engine import ENGINE_VERSION, Input, compare, run
from bahar_ai_core.knowledge import KNOWLEDGE


class BaharAIError(RuntimeError):
    pass


@dataclass(frozen=True)
class BaharAIIdentity:
    engine: str
    version: str
    dataset_id: str
    dataset_version: str
    manifest_sha256: str
    concept_count: int
    alias_count: int
    mode: str
    alias_language_counts: dict[str, int]
    scientifically_validated: bool


class BaharAIAdapter:
    """Application boundary for the versioned hardened BAHAR candidate engine.

    The imported core is deterministic candidate extraction plus an editorial
    knowledge seed. This adapter preserves those limitations and never promotes
    a candidate into supplier-lot truth, legal compliance, or release approval.
    """

    def __init__(self, governed_store: Any | None = None) -> None:
        self.store = governed_store
        self.identity = BaharAIIdentity(
            engine="BAHAR Bahar AI Core",
            version=ENGINE_VERSION,
            dataset_id=str(KNOWLEDGE.manifest["dataset_id"]),
            dataset_version=str(KNOWLEDGE.manifest["version"]),
            manifest_sha256=KNOWLEDGE.manifest_sha256,
            concept_count=len(KNOWLEDGE.concepts),
            alias_count=len(KNOWLEDGE.alias_index),
            mode="deterministic_lexical_candidate_engine",
            alias_language_counts=KNOWLEDGE.alias_language_counts,
            scientifically_validated=False,
        )

    def audit(
        self,
        *,
        product_id: str,
        formulation_version: str,
        formulation_text: str,
        label_version: str,
        label_text: str,
        evidence_assertions: list[dict[str, Any]] | None = None,
        persist: bool = True,
    ) -> dict[str, Any]:
        assessment = run(Input(
            product_id=product_id,
            recipe_version=formulation_version,
            recipe_text=formulation_text,
            label_version=label_version,
            label_text=label_text,
            evidence_assertions=tuple(evidence_assertions or ()),
        ))
        assessment["integrated_core"] = self.identity.__dict__
        if persist and self.store is not None and assessment["execution_status"] == "COMPLETED":
            self.store.put_object(
                f"bahar-ai:{assessment['assessment_id']}",
                "bahar_ai_assessment",
                assessment,
                actor_id=str(self.store.context.principal_id) if hasattr(self.store, "context") else "LOCAL_DEMONSTRATION_ONLY",
                operation_id=f"bahar-ai:{assessment['assessment_id']}:commit",
                expected_latest_version=0,
            )
        return assessment

    def compare(
        self,
        *,
        product_id: str,
        before: dict[str, str],
        after: dict[str, str],
    ) -> dict[str, Any]:
        outcome = compare(
            Input(product_id, before["formulation_version"], before["formulation_text"],
                  before["label_version"], before.get("label_text", "")),
            Input(product_id, after["formulation_version"], after["formulation_text"],
                  after["label_version"], after.get("label_text", "")),
        )
        outcome['governance_stage'] = 'LEXICAL_VERSION_COMPARISON_ONLY'
        outcome['definitive_unaffected_claim_permitted'] = False
        outcome['dependency_knowledge'] = 'unknown'
        outcome['reassessment_required'] = outcome.get('reassessment_required', True)
        outcome['comparison_id'] = digest({'product_id': product_id, 'before': before, 'after': after})
        if self.store is not None and outcome.get('status') == 'COMPLETED':
            key = f"bahar-comparison:{outcome['comparison_id']}"
            previous = self.store.get_object(key)
            if previous is None:
                self.store.put_object(key, 'bahar_candidate_comparison', outcome,
                    actor_id=str(self.store.context.principal_id) if hasattr(self.store, 'context') else 'LOCAL_DEMONSTRATION_ONLY',
                    operation_id=f'{key}:record', expected_latest_version=0)
            elif previous['digest'] != digest(outcome):
                # Each run carries varying timestamps/assessment IDs: do not silently
                # rewrite the earlier immutable comparison.
                outcome['stored_comparison_digest'] = previous['digest']
        return outcome

    def lookup(self, ingredient_text: str) -> dict[str, Any]:
        result = KNOWLEDGE.lookup(ingredient_text)
        return {**result, "integrated_core": self.identity.__dict__}
