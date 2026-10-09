from __future__ import annotations

from pathlib import Path
from typing import Any
import os
import uuid

from .assessment import AssessmentEngine, digest
from .models import AssessmentMode
from .store import BaharStore, StoreError
from .persistence import PostgresBaharStore, TenantContext


class BaharService:
    def __init__(self, database: str | Path = ":memory:", *, store: Any | None = None):
        self.engine = AssessmentEngine()
        self.store = store if store is not None else BaharStore(database)

    @classmethod
    def from_environment(cls) -> "BaharService":
        database_url = os.environ["BAHAR_DATABASE_URL"]
        organization_id = uuid.UUID(os.environ["BAHAR_ORGANIZATION_ID"])
        principal_id = uuid.UUID(os.environ["BAHAR_PRINCIPAL_ID"])
        audit_key = os.environ["BAHAR_AUDIT_HMAC_KEY"].encode("utf-8")
        return cls(store=PostgresBaharStore(
            database_url,
            TenantContext(organization_id, principal_id, "bahar-api"),
            audit_key,
        ))

    def close(self) -> None:
        self.store.close()

    def assess(self, case: dict[str, Any], *, commit: bool = True) -> dict[str, Any]:
        result = self.engine.assess(case)
        return self.store.commit_assessment(result) if commit else result

    def approve_release(
        self,
        release_id: str,
        assessment_id: str,
        *,
        actor_id: str,
        authority_role: str,
        reason: str,
    ) -> dict[str, Any]:
        assessment = self.store.get_assessment(assessment_id)
        if assessment is None:
            raise StoreError("assessment not found")
        # Demonstration results can never satisfy the production release gate.
        contract = assessment["manifest"]["assessment_contract"]
        # Mode is bound indirectly to the immutable input digest, but release needs
        # an explicit production record. The committed result carries the scope only;
        # callers must register the contract object and provide its mode here.
        registered = self.store.get_object(str(contract["id"]))
        if contract.get("mode") != AssessmentMode.PRODUCTION.value:
            raise StoreError("demonstration assessments cannot authorize production release")
        # F46: SQLite has no independent per-user membership authority. It
        # must never mint a production approval from a caller-provided role.
        if not isinstance(self.store,PostgresBaharStore):
            raise StoreError('production release authority requires authenticated PostgreSQL membership')
        if (
            not registered
            or registered["body"].get("mode") != AssessmentMode.PRODUCTION.value
            or registered["body"].get("version") != contract.get("version")
            or registered["digest"] != contract.get("digest")
        ):
            raise StoreError("a registered production assessment contract is required")
        from .operational_scope import context_identity
        identity = context_identity(assessment.get('scope', {}))
        if identity['state'] != 'identity_defined_not_verified':
            raise StoreError('complete product-market-package-event identity required before release')
        if not assessment['manifest'].get('source_custody_verified',False):
            raise StoreError('release requires independently verified source custody')
        # No production release can be inferred from a few successful checks.
        # Until a qualified release policy and external production evidence are
        # bound to the manifest, deny instead of generating a fictitious approval.
        if not assessment['manifest'].get('qualified_operational_release_basis'):
            raise StoreError('qualified operational release basis has not been verified')
        from .reviewer_workflow import ReviewerWorkflow
        ReviewerWorkflow(self.store).require_release_reviews(assessment_id, actor_id)
        return self.store.create_release(
            release_id,
            assessment_id,
            scope_digest=digest(assessment.get("scope", {})),
            configuration_digest=assessment["manifest"]["input_digest"],
            evidence_snapshot_digest=digest(assessment["manifest"].get("source_versions", [])),
            authority_id=actor_id,
            authority_role=authority_role,
            reason=reason,
            operation_id=f"release:{release_id}:approve",
        )

    def process_change(
        self,
        changed_object_id: str,
        *,
        actor_id: str,
        authority_role: str,
        reason: str,
    ) -> dict[str, Any]:
        """Traverse known dependencies and suspend affected active approvals.

        This does not rewrite the historical approval; it creates a new release
        state revision and reports incomplete dependency discovery separately.
        """
        impact = self.store.invalidate_releases(changed_object_id, reason=reason)
        return {
            "impact": impact,
            "suspended_release_ids": impact["suspended_release_ids"],
            "continuity_review_initiated": True,
            "impact_completeness": "incomplete",
            "definitive_unaffected_claim_permitted": False,
        }
