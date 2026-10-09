from __future__ import annotations

import uuid
from dataclasses import asdict
from typing import Any

from sqlalchemy import text

from .ai_extraction import GovernedAIRun, InterpretationRevision
from .audit import stable_bytes
from .extraction import Correction, ExtractionResult
from .knowledge import AssertionRevision, Concept, GovernedName


class GovernanceRepositoryError(RuntimeError):
    pass


class PostgresExtractionRepository:
    def __init__(self, store: Any) -> None:
        self.store = store

    def save(self, result: ExtractionResult, *, artifact_id: str, artifact_version: int) -> None:
        organization_id = str(self.store.context.organization_id)
        with self.store.transaction(serializable=True) as connection:
            connection.execute(
                text(
                    """
                    INSERT INTO extraction_runs (
                      organization_id, extraction_id, artifact_id, artifact_version, method,
                      engine_name, engine_version, language_profile, configuration, state, completed_at
                    ) VALUES (
                      :organization_id, :extraction_id, :artifact_id, :artifact_version, :method,
                      :engine_name, :engine_version, :language_profile, '{}'::jsonb, 'completed', clock_timestamp()
                    )
                    """
                ),
                {
                    "organization_id": organization_id, "extraction_id": result.extraction_id,
                    "artifact_id": artifact_id, "artifact_version": artifact_version,
                    "method": result.method, "engine_name": result.engine_name,
                    "engine_version": result.engine_version, "language_profile": result.language_profile,
                },
            )
            for region in result.regions:
                connection.execute(
                    text(
                        """
                        INSERT INTO extracted_regions (
                          organization_id, extraction_id, region_id, page_number, region_type,
                          source_text, normalized_polygon, pixel_polygon, confidence, unresolved, style
                        ) VALUES (
                          :organization_id, :extraction_id, :region_id, :page_number, :region_type,
                          :source_text, CAST(:normalized_polygon AS jsonb), CAST(:pixel_polygon AS jsonb),
                          :confidence, :unresolved, CAST(:style AS jsonb)
                        )
                        """
                    ),
                    {
                        "organization_id": organization_id, "extraction_id": result.extraction_id,
                        "region_id": region.region_id, "page_number": region.page_number,
                        "region_type": region.region_type, "source_text": region.source_text,
                        "normalized_polygon": stable_bytes(region.normalized_polygon).decode("utf-8"),
                        "pixel_polygon": stable_bytes(region.pixel_polygon).decode("utf-8") if region.pixel_polygon else None,
                        "confidence": region.confidence, "unresolved": region.unresolved,
                        "style": stable_bytes(region.style).decode("utf-8"),
                    },
                )
            self.store._audit(
                connection, action="extraction_completed", target_type="extraction",
                target_id=result.extraction_id, target_revision=1, outcome="success",
                reason="immutable extraction regions recorded",
                operation_id=f"extraction:{result.extraction_id}:complete",
                detail={"regions": len(result.regions), "unresolved_regions": result.unresolved_regions},
            )

    def save_correction(self, correction: Correction) -> None:
        with self.store.transaction() as connection:
            connection.execute(
                text(
                    """
                    INSERT INTO extraction_corrections (
                      organization_id, correction_id, extraction_id, region_id, corrected_text,
                      corrected_polygon, reason, corrected_by, review_state
                      , supersedes_correction_id
                    ) VALUES (
                      :organization_id, :correction_id, :extraction_id, :region_id, :corrected_text,
                      CAST(:corrected_polygon AS jsonb), :reason, :corrected_by, :review_state
                      , :supersedes_correction_id
                    )
                    """
                ),
                {
                    "organization_id": str(self.store.context.organization_id),
                    "correction_id": correction.correction_id, "extraction_id": correction.extraction_id,
                    "region_id": correction.region_id, "corrected_text": correction.corrected_text,
                    "corrected_polygon": stable_bytes(correction.corrected_polygon).decode("utf-8") if correction.corrected_polygon else None,
                    "reason": correction.reason, "corrected_by": correction.corrected_by,
                    "review_state": correction.review_state,
                    "supersedes_correction_id": correction.supersedes_correction_id,
                },
            )


class PostgresAIRepository:
    def __init__(self, store: Any) -> None:
        self.store = store

    def save_run(self, run: GovernedAIRun, *, input_manifest: dict[str, Any]) -> None:
        manifest = run.manifest
        with self.store.transaction() as connection:
            connection.execute(
                text(
                    """
                    INSERT INTO ai_runs (
                      organization_id, ai_run_id, provider_id, model_id, model_version,
                      prompt_id, prompt_version, prompt_sha256, schema_id, schema_version,
                      schema_sha256, safety_policy_version, temperature, seed, input_manifest,
                      output_sha256, state, started_at, completed_at
                    ) VALUES (
                      :organization_id, :ai_run_id, :provider_id, :model_id, :model_version,
                      :prompt_id, :prompt_version, :prompt_sha256, :schema_id, :schema_version,
                      :schema_sha256, :safety_policy_version, :temperature, :seed,
                      CAST(:input_manifest AS jsonb), :output_sha256, :state, :started_at, :completed_at
                    )
                    """
                ),
                {
                    "organization_id": str(self.store.context.organization_id),
                    "ai_run_id": run.ai_run_id, **asdict(manifest),
                    "input_manifest": stable_bytes(input_manifest).decode("utf-8"),
                    "output_sha256": run.raw_output_sha256, "state": run.state,
                    "started_at": run.started_at, "completed_at": run.completed_at,
                },
            )

    def save_interpretation(
        self,
        revision: InterpretationRevision,
        *,
        ai_run_id: str | None,
        extraction_id: str | None,
        region_ids: tuple[str, ...] = (),
    ) -> None:
        with self.store.transaction() as connection:
            connection.execute(
                text(
                    """
                    INSERT INTO interpretations (
                      organization_id, interpretation_id, revision, ai_run_id, extraction_id,
                      region_ids, proposition, state, reviewer_id, decision_reason,
                      supersedes_revision, created_at
                    ) VALUES (
                      :organization_id, :interpretation_id, :revision, :ai_run_id, :extraction_id,
                      CAST(:region_ids AS uuid[]), CAST(:proposition AS jsonb), :state, :reviewer_id,
                      :decision_reason, :supersedes_revision, :created_at
                    )
                    """
                ),
                {
                    "organization_id": str(self.store.context.organization_id),
                    "interpretation_id": revision.interpretation_id, "revision": revision.revision,
                    "ai_run_id": ai_run_id, "extraction_id": extraction_id,
                    "region_ids": "{" + ",".join(region_ids) + "}",
                    "proposition": stable_bytes(revision.proposition).decode("utf-8"),
                    "state": revision.state, "reviewer_id": revision.reviewer_id,
                    "decision_reason": revision.reason,
                    "supersedes_revision": revision.supersedes_revision,
                    "created_at": revision.created_at,
                },
            )


class PostgresKnowledgeRepository:
    def __init__(self, store: Any) -> None:
        self.store = store

    def save_concept(self, concept: Concept) -> None:
        with self.store.transaction() as connection:
            connection.execute(
                text(
                    """
                    INSERT INTO ingredient_concepts (
                      organization_id, concept_id, concept_kind, public_identifier, state
                    ) VALUES (
                      :organization_id, :concept_id, :concept_kind, :public_identifier, :state
                    )
                    """
                ),
                {"organization_id": str(self.store.context.organization_id), **asdict(concept)},
            )

    def save_name(self, name: GovernedName) -> None:
        with self.store.transaction() as connection:
            connection.execute(
                text(
                    """
                    INSERT INTO ingredient_names (
                      organization_id, name_id, concept_id, lexical_value, language_tag,
                      label_kind, search_value, source_artifact_id, approval_state
                    ) VALUES (
                      :organization_id, :name_id, :concept_id, :lexical_value, :language_tag,
                      :label_kind, :search_value, :source_artifact_id, :approval_state
                    )
                    """
                ),
                {
                    "organization_id": str(self.store.context.organization_id),
                    "name_id": name.name_id, "concept_id": name.concept_id,
                    "lexical_value": name.lexical_value, "language_tag": name.language_tag,
                    "label_kind": name.label_kind, "search_value": name.lexical_value.casefold().strip(),
                    "source_artifact_id": name.source.artifact_id, "approval_state": name.approval_state,
                },
            )

    def save_assertion(self, assertion: AssertionRevision) -> None:
        with self.store.transaction() as connection:
            connection.execute(
                text(
                    """
                    INSERT INTO knowledge_assertions (
                      organization_id, assertion_id, revision, subject_id, predicate, object_id,
                      polarity, evidence_state, scope_kind, scope, source_artifact_id,
                      source_artifact_version, valid_from, valid_until, approval_state,
                      approved_by, supersedes_revision
                    ) VALUES (
                      :organization_id, :assertion_id, :revision, :subject_id, :predicate, :object_id,
                      :polarity, :evidence_state, :scope_kind, CAST(:scope AS jsonb), :source_artifact_id,
                      :source_artifact_version, :valid_from, :valid_until, :approval_state,
                      :approved_by, :supersedes_revision
                    )
                    """
                ),
                {
                    "organization_id": str(self.store.context.organization_id),
                    "assertion_id": assertion.assertion_id, "revision": assertion.revision,
                    "subject_id": assertion.subject_id, "predicate": assertion.predicate,
                    "object_id": assertion.object_id, "polarity": assertion.polarity,
                    "evidence_state": (
                        "supported_positive" if assertion.approval_state == "accepted" and assertion.polarity == "positive"
                        else "supported_negative" if assertion.approval_state == "accepted"
                        else "unknown"
                    ),
                    "scope_kind": assertion.scope_kind,
                    "scope": stable_bytes(assertion.scope).decode("utf-8"),
                    "source_artifact_id": assertion.source.artifact_id,
                    "source_artifact_version": assertion.source.artifact_version,
                    "valid_from": assertion.valid_from, "valid_until": assertion.valid_until,
                    "approval_state": assertion.approval_state,
                    "approved_by": assertion.approved_by,
                    "supersedes_revision": assertion.supersedes_revision,
                },
            )
