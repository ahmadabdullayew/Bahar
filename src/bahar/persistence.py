from __future__ import annotations

import json
import random
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Iterator, TypeVar

from sqlalchemy import Engine, create_engine, text
from sqlalchemy.engine import Connection
from sqlalchemy.exc import DBAPIError, IntegrityError

from .assessment import digest
from .audit import GENESIS_HMAC, event_hmac, stable_bytes
from .audit import verify_chain as verify_audit_events
from .store import ConcurrencyConflict, ImmutableConflict, StoreError


T = TypeVar("T")


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _sqlstate(exc: BaseException) -> str | None:
    candidate: Any = exc
    while candidate is not None:
        value = getattr(candidate, "sqlstate", None) or getattr(candidate, "pgcode", None)
        if value:
            return str(value)
        candidate = getattr(candidate, "orig", None)
    return None


@dataclass(frozen=True)
class TenantContext:
    organization_id: uuid.UUID
    principal_id: uuid.UUID
    service_identity: str | None = None


class PostgresBaharStore:
    """PostgreSQL production persistence with RLS and transactional audit.

    A store is bound to one verified tenant/principal context. Callers must create
    a new context after authentication or membership changes; tenant identifiers
    from business payloads are never used as authority.
    """

    def __init__(
        self,
        database_url: str,
        context: TenantContext,
        audit_hmac_key: bytes,
        *,
        audit_key_id: str = "audit-hmac-v1",
        engine: Engine | None = None,
    ):
        if not database_url.startswith(("postgresql://", "postgresql+psycopg://")):
            raise StoreError("production persistence requires PostgreSQL")
        if len(audit_hmac_key) < 32:
            raise StoreError("audit HMAC key must contain at least 32 bytes")
        self.context = context
        self.audit_hmac_key = audit_hmac_key
        self.audit_key_id = audit_key_id
        self.engine = engine or create_engine(
            database_url,
            pool_pre_ping=True,
            pool_size=5,
            max_overflow=10,
            pool_recycle=1800,
        )

    def close(self) -> None:
        self.engine.dispose()

    def _bind_context(self, connection: Connection) -> None:
        connection.execute(
            text("SELECT set_config('app.organization_id', :organization_id, true)"),
            {"organization_id": str(self.context.organization_id)},
        )
        connection.execute(
            text("SELECT set_config('app.principal_id', :principal_id, true)"),
            {"principal_id": str(self.context.principal_id)},
        )

    @contextmanager
    def transaction(self, *, serializable: bool = False) -> Iterator[Connection]:
        connection = self.engine.connect()
        if serializable:
            connection = connection.execution_options(isolation_level="SERIALIZABLE")
        transaction = connection.begin()
        try:
            self._bind_context(connection)
            yield connection
        except BaseException:
            transaction.rollback()
            connection.close()
            raise
        else:
            transaction.commit()
            connection.close()

    def retry_serializable(self, operation: Callable[[], T], *, attempts: int = 5) -> T:
        for attempt in range(attempts):
            try:
                return operation()
            except DBAPIError as exc:
                if _sqlstate(exc) not in {"40001", "40P01"} or attempt == attempts - 1:
                    raise
                time.sleep((0.01 * (2**attempt)) + random.uniform(0, 0.02))
        raise AssertionError("unreachable")

    def _audit(
        self,
        connection: Connection,
        *,
        action: str,
        target_type: str,
        target_id: str,
        target_revision: int | None,
        outcome: str,
        reason: str,
        operation_id: str,
        detail: dict[str, Any],
        idempotency_key: str | None = None,
    ) -> None:
        organization_id = str(self.context.organization_id)
        connection.execute(
            text(
                """
                INSERT INTO audit_streams (organization_id, key_id)
                VALUES (:organization_id, :key_id)
                ON CONFLICT (organization_id, epoch) DO NOTHING
                """
            ),
            {"organization_id": organization_id, "key_id": self.audit_key_id},
        )
        stream = connection.execute(
            text(
                """
                SELECT stream_id, epoch, next_sequence, head_hmac, key_id
                FROM audit_streams
                WHERE organization_id = :organization_id
                ORDER BY epoch DESC
                LIMIT 1
                FOR UPDATE
                """
            ),
            {"organization_id": organization_id},
        ).mappings().one()
        sequence = int(stream["next_sequence"])
        previous = str(stream["head_hmac"] or GENESIS_HMAC)
        created_at = utc_now()
        event = {
            "actor_id": str(self.context.principal_id),
            "service_identity": self.context.service_identity,
            "action": action,
            "target_type": target_type,
            "target_id": target_id,
            "target_revision": target_revision,
            "outcome": outcome,
            "reason": reason,
            "operation_id": operation_id,
            "idempotency_key": idempotency_key,
            "detail": detail,
            "created_at": created_at.isoformat(),
        }
        signature = event_hmac(
            self.audit_hmac_key,
            stream_id=str(stream["stream_id"]),
            epoch=int(stream["epoch"]),
            sequence=sequence,
            previous_hmac=previous,
            event=event,
        )
        connection.execute(
            text(
                """
                INSERT INTO audit_events (
                  organization_id, stream_id, epoch, sequence, actor_id, service_identity,
                  action, target_type, target_id, target_revision, outcome, reason,
                  operation_id, idempotency_key, detail, previous_hmac, event_hmac,
                  key_id, created_at
                ) VALUES (
                  :organization_id, :stream_id, :epoch, :sequence, :actor_id, :service_identity,
                  :action, :target_type, :target_id, :target_revision, :outcome, :reason,
                  :operation_id, :idempotency_key, CAST(:detail AS jsonb), :previous_hmac,
                  :event_hmac, :key_id, :created_at
                )
                """
            ),
            {
                "organization_id": organization_id,
                "stream_id": str(stream["stream_id"]),
                "epoch": int(stream["epoch"]),
                "sequence": sequence,
                "actor_id": str(self.context.principal_id),
                "service_identity": self.context.service_identity,
                "action": action,
                "target_type": target_type,
                "target_id": target_id,
                "target_revision": target_revision,
                "outcome": outcome,
                "reason": reason,
                "operation_id": operation_id,
                "idempotency_key": idempotency_key,
                "detail": stable_bytes(detail).decode("utf-8"),
                "previous_hmac": previous,
                "event_hmac": signature,
                "key_id": str(stream["key_id"]),
                "created_at": created_at,
            },
        )
        connection.execute(
            text(
                """
                UPDATE audit_streams
                SET next_sequence = :next_sequence, head_hmac = :head_hmac
                WHERE organization_id = :organization_id AND stream_id = :stream_id
                """
            ),
            {
                "next_sequence": sequence + 1,
                "head_hmac": signature,
                "organization_id": organization_id,
                "stream_id": str(stream["stream_id"]),
            },
        )

    def _outbox(
        self,
        connection: Connection,
        *,
        topic: str,
        aggregate_type: str,
        aggregate_id: uuid.UUID,
        aggregate_revision: int | None,
        payload: dict[str, Any],
    ) -> None:
        connection.execute(
            text(
                """
                INSERT INTO transaction_outbox (
                  organization_id, topic, aggregate_type, aggregate_id, aggregate_revision, payload
                ) VALUES (
                  :organization_id, :topic, :aggregate_type, :aggregate_id, :aggregate_revision,
                  CAST(:payload AS jsonb)
                )
                """
            ),
            {
                "organization_id": str(self.context.organization_id),
                "topic": topic,
                "aggregate_type": aggregate_type,
                "aggregate_id": str(aggregate_id),
                "aggregate_revision": aggregate_revision,
                "payload": stable_bytes(payload).decode("utf-8"),
            },
        )

    def put_object(
        self,
        object_id: str,
        object_type: str,
        body: dict[str, Any],
        *,
        actor_id: str,
        operation_id: str,
        expected_latest_version: int | None,
    ) -> dict[str, Any]:
        del actor_id  # Authority comes from the verified TenantContext.
        if not object_id or not object_type:
            raise StoreError("object id and type are required")
        expected = 0 if expected_latest_version is None else int(expected_latest_version)
        body_sha256 = digest(body)
        organization_id = str(self.context.organization_id)

        def operation() -> dict[str, Any]:
            with self.transaction(serializable=True) as connection:
                row = connection.execute(
                    text(
                        """
                        SELECT entity_id, current_revision, entity_type
                        FROM governed_entities
                        WHERE organization_id = :organization_id
                          AND entity_type = :entity_type
                          AND external_key = :external_key
                        """
                    ),
                    {
                        "organization_id": organization_id,
                        "entity_type": object_type,
                        "external_key": object_id,
                    },
                ).mappings().first()
                if row is None:
                    if expected != 0:
                        raise ConcurrencyConflict(f"expected version {expected}, current version is 0")
                    entity_id = uuid.uuid4()
                    connection.execute(
                        text(
                            """
                            INSERT INTO governed_entities (
                              organization_id, entity_id, external_key, entity_type, current_revision,
                              state, created_by
                            ) VALUES (
                              :organization_id, :entity_id, :external_key, :entity_type, 1,
                              'draft', :principal_id
                            )
                            """
                        ),
                        {
                            "organization_id": organization_id,
                            "entity_id": str(entity_id),
                            "external_key": object_id,
                            "entity_type": object_type,
                            "principal_id": str(self.context.principal_id),
                        },
                    )
                    revision = 1
                else:
                    if str(row["entity_type"]) != object_type:
                        raise ImmutableConflict("object type cannot change")
                    current = int(row["current_revision"])
                    if current != expected:
                        raise ConcurrencyConflict(f"expected version {expected}, current version is {current}")
                    latest = connection.execute(
                        text(
                            """
                            SELECT body_sha256 FROM entity_revisions
                            WHERE organization_id = :organization_id AND entity_id = :entity_id
                              AND revision = :revision
                            """
                        ),
                        {
                            "organization_id": organization_id,
                            "entity_id": str(row["entity_id"]),
                            "revision": current,
                        },
                    ).scalar_one()
                    if str(latest) == body_sha256:
                        raise ImmutableConflict("identical content already exists as the latest version")
                    entity_id = uuid.UUID(str(row["entity_id"]))
                    update = connection.execute(
                        text(
                            """
                            UPDATE governed_entities
                            SET current_revision = current_revision + 1, updated_at = clock_timestamp()
                            WHERE organization_id = :organization_id AND entity_id = :entity_id
                              AND current_revision = :expected
                            RETURNING current_revision
                            """
                        ),
                        {
                            "organization_id": organization_id,
                            "entity_id": str(entity_id),
                            "expected": expected,
                        },
                    ).scalar_one_or_none()
                    if update is None:
                        raise ConcurrencyConflict("object changed concurrently")
                    revision = int(update)
                connection.execute(
                    text(
                        """
                        INSERT INTO entity_revisions (
                          organization_id, entity_id, revision, predecessor_revision, body,
                          body_sha256, reason, author_id
                        ) VALUES (
                          :organization_id, :entity_id, :revision, :predecessor_revision,
                          CAST(:body AS jsonb), :body_sha256, :reason, :author_id
                        )
                        """
                    ),
                    {
                        "organization_id": organization_id,
                        "entity_id": str(entity_id),
                        "revision": revision,
                        "predecessor_revision": revision - 1 if revision > 1 else None,
                        "body": stable_bytes(body).decode("utf-8"),
                        "body_sha256": body_sha256,
                        "reason": "governed object revision",
                        "author_id": str(self.context.principal_id),
                    },
                )
                self._audit(
                    connection,
                    action="object_version_created",
                    target_type=object_type,
                    target_id=object_id,
                    target_revision=revision,
                    outcome="success",
                    reason="governed object revision",
                    operation_id=operation_id,
                    detail={"body_sha256": body_sha256, "entity_id": str(entity_id)},
                )
                self._outbox(
                    connection,
                    topic="governed-object.revised",
                    aggregate_type=object_type,
                    aggregate_id=entity_id,
                    aggregate_revision=revision,
                    payload={"external_key": object_id, "body_sha256": body_sha256},
                )
                return {"id": object_id, "type": object_type, "version": revision, "digest": body_sha256}

        try:
            return self.retry_serializable(operation)
        except IntegrityError as exc:
            raise ConcurrencyConflict("object changed concurrently") from exc

    def get_object(self, object_id: str, version: int | None = None) -> dict[str, Any] | None:
        with self.transaction() as connection:
            row = connection.execute(
                text(
                    """
                    SELECT ge.external_key, ge.entity_type, er.revision, er.body, er.body_sha256, er.created_at
                    FROM governed_entities ge
                    JOIN entity_revisions er
                      ON er.organization_id = ge.organization_id AND er.entity_id = ge.entity_id
                    WHERE ge.organization_id = :organization_id AND ge.external_key = :external_key
                      AND er.revision = COALESCE(:revision, ge.current_revision)
                    """
                ),
                {
                    "organization_id": str(self.context.organization_id),
                    "external_key": object_id,
                    "revision": version,
                },
            ).mappings().first()
        if row is None:
            return None
        body = row["body"] if isinstance(row["body"], dict) else json.loads(row["body"])
        return {
            "id": str(row["external_key"]),
            "type": str(row["entity_type"]),
            "version": int(row["revision"]),
            "digest": str(row["body_sha256"]),
            "body": body,
            "created_at": row["created_at"].isoformat(),
        }

    def _require_role(self, connection: Connection, role_name: str) -> None:
        permitted = connection.execute(
            text(
                """
                SELECT EXISTS (
                  SELECT 1 FROM memberships
                  WHERE organization_id = :organization_id
                    AND principal_id = :principal_id
                    AND role_name = :role_name
                    AND facility_id IS NULL
                    AND valid_from <= clock_timestamp()
                    AND (valid_until IS NULL OR valid_until > clock_timestamp())
                )
                """
            ),
            {
                "organization_id": str(self.context.organization_id),
                "principal_id": str(self.context.principal_id),
                "role_name": role_name,
            },
        ).scalar_one()
        if not permitted:
            raise StoreError(f"actor lacks {role_name.replace('_', ' ')} role")

    def commit_assessment(self, result: dict[str, Any]) -> dict[str, Any]:
        manifest = result["manifest"]
        external_key = str(result["assessment_id"])
        assessment_id = uuid.uuid5(self.context.organization_id, "assessment:" + external_key)
        organization_id = str(self.context.organization_id)
        with self.transaction(serializable=True) as connection:
            existing = connection.execute(
                text(
                    """
                    SELECT input_sha256, result FROM assessments
                    WHERE organization_id = :organization_id AND external_key = :external_key
                    """
                ),
                {"organization_id": organization_id, "external_key": external_key},
            ).mappings().first()
            if existing:
                if str(existing["input_sha256"]) != str(manifest["input_digest"]):
                    raise ImmutableConflict("assessment identity is bound to a different input snapshot")
                return existing["result"] if isinstance(existing["result"], dict) else json.loads(existing["result"])
            duplicate = connection.execute(
                text(
                    """
                    SELECT result FROM assessments
                    WHERE organization_id = :organization_id AND manifest_sha256 = :manifest_sha256
                    """
                ),
                {"organization_id": organization_id, "manifest_sha256": manifest["manifest_digest"]},
            ).scalar_one_or_none()
            if duplicate is not None:
                return duplicate if isinstance(duplicate, dict) else json.loads(duplicate)
            connection.execute(
                text(
                    """
                    INSERT INTO assessments (
                      organization_id, assessment_id, external_key, manifest_sha256, input_sha256,
                      result, execution_state, technical_readiness
                    ) VALUES (
                      :organization_id, :assessment_id, :external_key, :manifest_sha256, :input_sha256,
                      CAST(:result AS jsonb), :execution_state, :technical_readiness
                    )
                    """
                ),
                {
                    "organization_id": organization_id,
                    "assessment_id": str(assessment_id),
                    "external_key": external_key,
                    "manifest_sha256": manifest["manifest_digest"],
                    "input_sha256": manifest["input_digest"],
                    "result": stable_bytes(result).decode("utf-8"),
                    "execution_state": result["execution_state"],
                    "technical_readiness": result["technical_readiness"],
                },
            )
            self._audit(
                connection, action="assessment_committed", target_type="assessment",
                target_id=external_key, target_revision=1, outcome="success",
                reason="deterministic assessment committed",
                operation_id=f"assessment:{external_key}:commit",
                detail={"manifest_sha256": manifest["manifest_digest"]},
            )
        return result

    def get_assessment(self, assessment_id: str) -> dict[str, Any] | None:
        with self.transaction() as connection:
            value = connection.execute(
                text(
                    """
                    SELECT result FROM assessments
                    WHERE organization_id = :organization_id AND external_key = :external_key
                    """
                ),
                {"organization_id": str(self.context.organization_id), "external_key": assessment_id},
            ).scalar_one_or_none()
        if value is None:
            return None
        return value if isinstance(value, dict) else json.loads(value)

    def create_release(
        self,
        release_id: str,
        assessment_id: str,
        *,
        scope_digest: str,
        configuration_digest: str,
        evidence_snapshot_digest: str,
        authority_id: str,
        authority_role: str,
        reason: str,
        operation_id: str,
    ) -> dict[str, Any]:
        if authority_role != "release_authority":
            raise StoreError("actor lacks release authority")
        if authority_id != str(self.context.principal_id):
            raise StoreError("authority identity does not match authenticated principal")
        if not reason.strip():
            raise StoreError("release reason is required")
        organization_id = str(self.context.organization_id)
        with self.transaction(serializable=True) as connection:
            self.lock_release_continuity(connection)
            self._require_role(connection, "release_authority")
            assessment = connection.execute(
                text(
                    """
                    SELECT assessment_id, technical_readiness, created_at FROM assessments
                    WHERE organization_id = :organization_id AND external_key = :external_key
                    """
                ),
                {"organization_id": organization_id, "external_key": assessment_id},
            ).mappings().first()
            if assessment is None:
                raise StoreError("assessment not found")
            if assessment["technical_readiness"] != "ready_for_review":
                raise StoreError("assessment is not technically ready for authorized review")
            # Material changes after this snapshot invalidate its release authority,
            # even if there was no pre-existing release to suspend.
            newer_changes = connection.execute(text("""
                SELECT EXISTS(SELECT 1 FROM audit_events
                  WHERE organization_id=:org AND created_at >= :assessment_time
                    AND action IN (
                      'material_specification_registered','material_receipt_registered',
                      'origin_finding_recorded','supplier_correction_recorded',
                      'formulation_version_registered','label_text_registered',
                      'artwork_registered','artwork_assessed',
                      'manufacturing_batch_recorded','physical_package_inspected',
                      'cleaning_event_recorded','cross_contact_assessed',
                      'packaging_lot_registered')
                )
            """), {'org': organization_id, 'assessment_time': assessment['created_at']}).scalar_one()
            if newer_changes:
                raise StoreError('material records changed after assessment; reassessment is mandatory')
            internal_release_id = uuid.uuid4()
            connection.execute(
                text(
                    """
                    INSERT INTO releases (
                      organization_id, release_id, external_key, assessment_id, state, revision,
                      scope_sha256, configuration_sha256, evidence_snapshot_sha256,
                      authority_id, reason
                    ) VALUES (
                      :organization_id, :release_id, :external_key, :assessment_id, 'approved', 1,
                      :scope_sha256, :configuration_sha256, :evidence_snapshot_sha256,
                      :authority_id, :reason
                    )
                    """
                ),
                {
                    "organization_id": organization_id,
                    "release_id": str(internal_release_id),
                    "external_key": release_id,
                    "assessment_id": str(assessment["assessment_id"]),
                    "scope_sha256": scope_digest,
                    "configuration_sha256": configuration_digest,
                    "evidence_snapshot_sha256": evidence_snapshot_digest,
                    "authority_id": authority_id,
                    "reason": reason,
                },
            )
            connection.execute(
                text(
                    """
                    INSERT INTO release_revisions (
                      organization_id, release_id, revision, state, authority_id, reason
                    ) VALUES (:organization_id, :release_id, 1, 'approved', :authority_id, :reason)
                    """
                ),
                {
                    "organization_id": organization_id, "release_id": str(internal_release_id),
                    "authority_id": authority_id, "reason": reason,
                },
            )
            self._audit(
                connection, action="release_approved", target_type="release", target_id=release_id,
                target_revision=1, outcome="success", reason=reason, operation_id=operation_id,
                detail={"assessment_id": assessment_id, "scope_sha256": scope_digest},
            )
        return self.get_release(release_id) or {}

    def update_release(
        self,
        release_id: str,
        new_state: str,
        *,
        expected_revision: int,
        actor_id: str,
        authority_role: str,
        reason: str,
        operation_id: str,
    ) -> dict[str, Any]:
        if authority_role != "release_authority" or actor_id != str(self.context.principal_id):
            raise StoreError("actor lacks release authority")
        transitions = {"approved": {"suspended", "withdrawn"}, "suspended": {"approved", "withdrawn"}, "withdrawn": set()}
        organization_id = str(self.context.organization_id)
        with self.transaction(serializable=True) as connection:
            self._require_role(connection, "release_authority")
            current = connection.execute(
                text(
                    """
                    SELECT release_id, state, revision FROM releases
                    WHERE organization_id = :organization_id AND external_key = :external_key
                    FOR UPDATE
                    """
                ),
                {"organization_id": organization_id, "external_key": release_id},
            ).mappings().first()
            if current is None:
                raise StoreError("release not found")
            if int(current["revision"]) != expected_revision:
                raise ConcurrencyConflict("release revision changed")
            if new_state not in transitions[str(current["state"])]:
                raise StoreError("illegal release transition")
            revision = expected_revision + 1
            updated = connection.execute(
                text(
                    """
                    UPDATE releases SET state = :state, revision = :revision, authority_id = :authority_id,
                      reason = :reason, updated_at = clock_timestamp()
                    WHERE organization_id = :organization_id AND release_id = :release_id
                      AND revision = :expected_revision
                    """
                ),
                {
                    "state": new_state, "revision": revision, "authority_id": actor_id,
                    "reason": reason, "organization_id": organization_id,
                    "release_id": str(current["release_id"]), "expected_revision": expected_revision,
                },
            )
            if updated.rowcount != 1:
                raise ConcurrencyConflict("release revision changed")
            connection.execute(
                text(
                    """
                    INSERT INTO release_revisions (
                      organization_id, release_id, revision, state, authority_id, reason, predecessor_revision
                    ) VALUES (
                      :organization_id, :release_id, :revision, :state, :authority_id, :reason, :predecessor
                    )
                    """
                ),
                {
                    "organization_id": organization_id, "release_id": str(current["release_id"]),
                    "revision": revision, "state": new_state, "authority_id": actor_id,
                    "reason": reason, "predecessor": expected_revision,
                },
            )
            self._audit(
                connection, action=f"release_{new_state}", target_type="release", target_id=release_id,
                target_revision=revision, outcome="success", reason=reason,
                operation_id=operation_id, detail={"previous_state": str(current["state"])},
            )
        return self.get_release(release_id) or {}

    def get_release(self, release_id: str) -> dict[str, Any] | None:
        with self.transaction() as connection:
            row = connection.execute(
                text(
                    """
                    SELECT r.external_key AS release_id, a.external_key AS assessment_id, r.state,
                      r.revision, r.scope_sha256 AS scope_digest,
                      r.configuration_sha256 AS configuration_digest,
                      r.evidence_snapshot_sha256 AS evidence_snapshot_digest,
                      r.authority_id, r.reason, r.created_at, r.updated_at
                    FROM releases r JOIN assessments a
                      ON a.organization_id = r.organization_id AND a.assessment_id = r.assessment_id
                    WHERE r.organization_id = :organization_id AND r.external_key = :external_key
                    """
                ),
                {"organization_id": str(self.context.organization_id), "external_key": release_id},
            ).mappings().first()
        if row is None:
            return None
        result = dict(row)
        result["authority_id"] = str(result["authority_id"])
        result["created_at"] = result["created_at"].isoformat()
        result["updated_at"] = result["updated_at"].isoformat()
        return result

    def list_releases(self) -> list[dict[str, Any]]:
        with self.transaction() as connection:
            identifiers = connection.execute(
                text(
                    "SELECT external_key FROM releases WHERE organization_id = :organization_id ORDER BY external_key"
                ),
                {"organization_id": str(self.context.organization_id)},
            ).scalars().all()
        return [release for identifier in identifiers if (release := self.get_release(str(identifier))) is not None]

    def _resolve_dependency_target(self, connection: Connection, external_key: str) -> tuple[str, uuid.UUID]:
        governed = connection.execute(
            text(
                """
                SELECT entity_type, entity_id FROM governed_entities
                WHERE organization_id = :organization_id AND external_key = :external_key
                """
            ),
            {"organization_id": str(self.context.organization_id), "external_key": external_key},
        ).mappings().first()
        if governed:
            return str(governed["entity_type"]), uuid.UUID(str(governed["entity_id"]))
        release = connection.execute(
            text(
                """
                SELECT release_id FROM releases
                WHERE organization_id = :organization_id AND external_key = :external_key
                """
            ),
            {"organization_id": str(self.context.organization_id), "external_key": external_key},
        ).scalar_one_or_none()
        if release:
            return "release", uuid.UUID(str(release))
        raise StoreError(f"dependency target is not governed: {external_key}")

    def add_dependency(
        self, upstream_id: str, downstream_id: str, relation: str, knowledge_state: str
    ) -> None:
        if knowledge_state not in {"complete", "partial", "unknown"}:
            raise StoreError("invalid dependency knowledge state")
        if not relation.strip():
            raise StoreError("dependency relation is required")
        with self.transaction(serializable=True) as connection:
            upstream_type, upstream_uuid = self._resolve_dependency_target(connection, upstream_id)
            downstream_type, downstream_uuid = self._resolve_dependency_target(connection, downstream_id)
            dependency_id = uuid.uuid5(
                self.context.organization_id,
                f"dependency:{upstream_type}:{upstream_uuid}:{downstream_type}:{downstream_uuid}:{relation}",
            )
            current = connection.execute(
                text(
                    """
                    SELECT COALESCE(MAX(revision), 0) FROM dependency_revisions
                    WHERE organization_id = :organization_id AND dependency_id = :dependency_id
                    """
                ),
                {"organization_id": str(self.context.organization_id), "dependency_id": str(dependency_id)},
            ).scalar_one()
            connection.execute(
                text(
                    """
                    INSERT INTO dependency_revisions (
                      organization_id, dependency_id, revision, upstream_type, upstream_id,
                      downstream_type, downstream_id, relation, completeness, state
                    ) VALUES (
                      :organization_id, :dependency_id, :revision, :upstream_type, :upstream_id,
                      :downstream_type, :downstream_id, :relation, :completeness, 'active'
                    )
                    """
                ),
                {
                    "organization_id": str(self.context.organization_id), "dependency_id": str(dependency_id),
                    "revision": int(current) + 1, "upstream_type": upstream_type,
                    "upstream_id": str(upstream_uuid), "downstream_type": downstream_type,
                    "downstream_id": str(downstream_uuid), "relation": relation,
                    "completeness": knowledge_state,
                },
            )
            self._audit(
                connection, action="dependency_recorded", target_type="dependency",
                target_id=str(dependency_id), target_revision=int(current) + 1, outcome="success",
                reason="dependency graph revision", operation_id=f"dependency:{dependency_id}:{int(current) + 1}",
                detail={"upstream": upstream_id, "downstream": downstream_id, "completeness": knowledge_state},
            )

    def lock_release_continuity(self, connection: Connection) -> None:
        """Serialize release approval with material-change invalidation per tenant.

        Both operations take this lock before checking or changing release state;
        an approval cannot slip between a source mutation's impact scan and its
        commit. Collisions in hashtext may cause additional contention, not unsafe
        results. This does not create distributed storage atomicity.
        """
        connection.execute(text('SELECT pg_advisory_xact_lock(47117, hashtext(:org))'),
                           {'org': str(self.context.organization_id)})

    def suspend_active_releases_in_transaction(
        self, connection: Connection, *, change_key: str, reason: str,
    ) -> dict[str, Any]:
        """Conservative invalidation, inside caller's existing transaction.

        Until a qualified *complete* source-to-product dependency inventory
        exists, every active release is potentially affected. Never imply
        definitive non-impact from an incomplete dependency graph.
        """
        organization_id = str(self.context.organization_id)
        self.lock_release_continuity(connection)
        current = connection.execute(text("""
            SELECT release_id, external_key, revision FROM releases
            WHERE organization_id=:org AND state='approved'
            ORDER BY release_id FOR UPDATE
        """), {'org': organization_id}).mappings().all()
        suspended = []
        for row in current:
            release_id = str(row['release_id'])
            new_revision = int(row['revision']) + 1
            changed = connection.execute(text("""
                UPDATE releases SET state='suspended', revision=:revision,
                  authority_id=:actor, reason=:reason, updated_at=clock_timestamp()
                WHERE organization_id=:org AND release_id=:rid
                  AND revision=:previous AND state='approved'
            """), {'revision': new_revision, 'actor': str(self.context.principal_id),
                    'reason': reason, 'org': organization_id, 'rid': release_id,
                    'previous': row['revision']})
            if changed.rowcount != 1:
                raise ConcurrencyConflict('release state changed while invalidating')
            connection.execute(text("""
                INSERT INTO release_revisions (
                    organization_id, release_id, revision, state, authority_id,
                    reason, predecessor_revision
                ) VALUES (:org,:rid,:revision,'suspended',:actor,:reason,:previous)
            """), {'org': organization_id, 'rid': release_id, 'revision': new_revision,
                    'actor': str(self.context.principal_id), 'reason': reason,
                    'previous': row['revision']})
            self._audit(connection, action='release_suspended_due_to_change', target_type='release',
                        target_id=str(row['external_key']), target_revision=new_revision,
                        outcome='success', reason=reason,
                        operation_id=f"material-change:{change_key}:release:{release_id}:revision:{new_revision}",
                        detail={'change_key': change_key, 'dependency_knowledge': 'unknown',
                                'impact_completeness': 'incomplete'})
            suspended.append(str(row['external_key']))
        return {'changed_object_id': change_key, 'dependency_knowledge': 'unknown',
                'impact_completeness': 'incomplete', 'definitive_unaffected_claim_permitted': False,
                'suspended_release_ids': sorted(suspended),
                'reassessment_required': True, 'impact_scope': 'all_active_releases_conservative'}

    def invalidate_releases(self, changed_object_id: str, *, reason: str) -> dict[str, Any]:
        if not changed_object_id or not reason.strip():
            raise StoreError('source and reason required for change processing')
        def operation() -> dict[str, Any]:
            with self.transaction(serializable=True) as connection:
                return self.suspend_active_releases_in_transaction(
                    connection, change_key=changed_object_id, reason=reason)
        return self.retry_serializable(operation)

    def affected(self, upstream_id: str) -> dict[str, Any]:
        with self.transaction() as connection:
            _, source_id = self._resolve_dependency_target(connection, upstream_id)
            rows = connection.execute(
                text(
                    """
                    WITH RECURSIVE latest AS (
                      SELECT DISTINCT ON (dependency_id) dependency_id, upstream_id, downstream_id,
                        downstream_type, completeness, state
                      FROM dependency_revisions
                      WHERE organization_id = :organization_id
                      ORDER BY dependency_id, revision DESC
                    ), graph AS (
                      SELECT downstream_id, downstream_type, completeness, ARRAY[upstream_id, downstream_id] AS path
                      FROM latest WHERE state = 'active' AND upstream_id = :source_id
                      UNION ALL
                      SELECT edge.downstream_id, edge.downstream_type, edge.completeness,
                        graph.path || edge.downstream_id
                      FROM graph JOIN latest edge ON edge.upstream_id = graph.downstream_id
                      WHERE edge.state = 'active' AND NOT edge.downstream_id = ANY(graph.path)
                    )
                    SELECT graph.downstream_id, graph.downstream_type, graph.completeness,
                      COALESCE(ge.external_key, r.external_key) AS external_key
                    FROM graph
                    LEFT JOIN governed_entities ge
                      ON ge.organization_id = :organization_id AND ge.entity_id = graph.downstream_id
                    LEFT JOIN releases r
                      ON r.organization_id = :organization_id AND r.release_id = graph.downstream_id
                    """
                ),
                {"organization_id": str(self.context.organization_id), "source_id": str(source_id)},
            ).mappings().all()
        states = {str(row["completeness"]) for row in rows}
        completeness = "unknown" if "unknown" in states else "partial" if "partial" in states or not states else "complete"
        return {
            "changed_object_id": upstream_id,
            "potentially_affected_ids": sorted({str(row["external_key"]) for row in rows if row["external_key"]}),
            "dependency_knowledge": completeness,
            "impact_completeness": "incomplete",  # graph edges cannot prove universe coverage
            "definitive_unaffected_claim_permitted": False,
            "unknown_downstream_dependencies_possible": True,
        }

    def verify_audit_chain(self) -> dict[str, Any]:
        with self.transaction() as connection:
            streams = connection.execute(
                text(
                    """
                    SELECT stream_id, epoch FROM audit_streams
                    WHERE organization_id = :organization_id ORDER BY epoch
                    """
                ),
                {"organization_id": str(self.context.organization_id)},
            ).mappings().all()
            reports: list[dict[str, Any]] = []
            for stream in streams:
                rows = connection.execute(
                    text(
                        """
                        SELECT sequence, previous_hmac, event_hmac, actor_id, service_identity,
                          action, target_type, target_id, target_revision, outcome, reason,
                          operation_id, idempotency_key, detail, created_at
                        FROM audit_events
                        WHERE organization_id = :organization_id AND stream_id = :stream_id
                          AND epoch = :epoch ORDER BY sequence
                        """
                    ),
                    {
                        "organization_id": str(self.context.organization_id),
                        "stream_id": str(stream["stream_id"]), "epoch": int(stream["epoch"]),
                    },
                ).mappings().all()
                events = []
                for row in rows:
                    detail = row["detail"] if isinstance(row["detail"], dict) else json.loads(row["detail"])
                    events.append({
                        "sequence": int(row["sequence"]), "previous_hmac": str(row["previous_hmac"]),
                        "event_hmac": str(row["event_hmac"]),
                        "event": {
                            "actor_id": str(row["actor_id"]) if row["actor_id"] else None,
                            "service_identity": row["service_identity"], "action": row["action"],
                            "target_type": row["target_type"], "target_id": row["target_id"],
                            "target_revision": row["target_revision"], "outcome": row["outcome"],
                            "reason": row["reason"], "operation_id": row["operation_id"],
                            "idempotency_key": row["idempotency_key"], "detail": detail,
                            "created_at": row["created_at"].isoformat(),
                        },
                    })
                report = verify_audit_events(
                    self.audit_hmac_key, str(stream["stream_id"]), int(stream["epoch"]), events
                )
                reports.append({"stream_id": str(stream["stream_id"]), "epoch": int(stream["epoch"]), **report.__dict__})
        return {"valid": all(report["valid"] for report in reports), "streams": reports}

    def verify_rls_posture(self) -> list[str]:
        """Return production posture defects; an empty list is the acceptance condition."""
        defects: list[str] = []
        with self.engine.connect() as connection:
            role = connection.execute(
                text(
                    """
                    SELECT rolsuper, rolbypassrls
                    FROM pg_roles WHERE rolname = current_user
                    """
                )
            ).mappings().one()
            if role["rolsuper"]:
                defects.append("runtime database role is superuser")
            if role["rolbypassrls"]:
                defects.append("runtime database role has BYPASSRLS")
            rows = connection.execute(
                text(
                    """
                    SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity,
                           EXISTS (SELECT 1 FROM pg_policy p WHERE p.polrelid = c.oid) AS has_policy
                    FROM pg_class c
                    JOIN pg_namespace n ON n.oid = c.relnamespace
                    WHERE n.nspname = 'public' AND c.relkind = 'r'
                      AND EXISTS (
                        SELECT 1 FROM information_schema.columns i
                        WHERE i.table_schema = 'public' AND i.table_name = c.relname
                          AND i.column_name = 'organization_id'
                      )
                    """
                )
            ).mappings()
            for row in rows:
                if not row["relrowsecurity"]:
                    defects.append(f"{row['relname']}: RLS disabled")
                if not row["relforcerowsecurity"]:
                    defects.append(f"{row['relname']}: FORCE RLS disabled")
                if not row["has_policy"]:
                    defects.append(f"{row['relname']}: no RLS policy")
        return defects
