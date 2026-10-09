from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from .assessment import canonical_json, digest


class StoreError(RuntimeError):
    pass


class ConcurrencyConflict(StoreError):
    pass


class ImmutableConflict(StoreError):
    pass


SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS objects (
    object_id TEXT NOT NULL,
    object_type TEXT NOT NULL,
    version INTEGER NOT NULL,
    body_json TEXT NOT NULL,
    body_digest TEXT NOT NULL,
    supersedes_version INTEGER,
    created_at TEXT NOT NULL,
    PRIMARY KEY (object_id, version)
);
CREATE TABLE IF NOT EXISTS dependencies (
    upstream_id TEXT NOT NULL,
    downstream_id TEXT NOT NULL,
    relation TEXT NOT NULL,
    knowledge_state TEXT NOT NULL CHECK (knowledge_state IN ('complete','partial','unknown')),
    created_at TEXT NOT NULL,
    PRIMARY KEY (upstream_id, downstream_id, relation)
);
CREATE TABLE IF NOT EXISTS assessments (
    assessment_id TEXT PRIMARY KEY,
    manifest_digest TEXT NOT NULL UNIQUE,
    input_digest TEXT NOT NULL,
    result_json TEXT NOT NULL,
    execution_state TEXT NOT NULL,
    technical_readiness TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS releases (
    release_id TEXT PRIMARY KEY,
    assessment_id TEXT NOT NULL REFERENCES assessments(assessment_id),
    state TEXT NOT NULL,
    revision INTEGER NOT NULL,
    scope_digest TEXT NOT NULL,
    configuration_digest TEXT NOT NULL,
    evidence_snapshot_digest TEXT NOT NULL,
    authority_id TEXT NOT NULL,
    authority_role TEXT NOT NULL,
    reason TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    operation_id TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    action TEXT NOT NULL,
    target_id TEXT NOT NULL,
    detail_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
"""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class BaharStore:
    def __init__(self, path: str | Path):
        self.path = str(path)
        self._lock = threading.RLock()
        self.connection = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.connection.executescript(SCHEMA)

    def close(self) -> None:
        self.connection.close()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            self.connection.execute("BEGIN IMMEDIATE")
            try:
                yield self.connection
            except Exception:
                self.connection.execute("ROLLBACK")
                raise
            else:
                self.connection.execute("COMMIT")

    def append_audit(
        self,
        connection: sqlite3.Connection,
        operation_id: str,
        actor_id: str,
        action: str,
        target_id: str,
        detail: dict[str, Any],
    ) -> None:
        connection.execute(
            "INSERT INTO audit_events(operation_id,actor_id,action,target_id,detail_json,created_at) VALUES(?,?,?,?,?,?)",
            (operation_id, actor_id, action, target_id, canonical_json(detail).decode(), utc_now()),
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
        if not object_id or not object_type:
            raise StoreError("object id and type are required")
        with self.transaction() as connection:
            current = connection.execute(
                "SELECT version,body_digest FROM objects WHERE object_id=? ORDER BY version DESC LIMIT 1",
                (object_id,),
            ).fetchone()
            current_version = int(current["version"]) if current else 0
            if expected_latest_version != current_version:
                raise ConcurrencyConflict(
                    f"expected version {expected_latest_version}, current version is {current_version}"
                )
            body_digest = digest(body)
            if current and current["body_digest"] == body_digest:
                raise ImmutableConflict("identical content already exists as the latest version")
            version = current_version + 1
            connection.execute(
                "INSERT INTO objects(object_id,object_type,version,body_json,body_digest,supersedes_version,created_at) VALUES(?,?,?,?,?,?,?)",
                (
                    object_id,
                    object_type,
                    version,
                    canonical_json(body).decode(),
                    body_digest,
                    current_version or None,
                    utc_now(),
                ),
            )
            self.append_audit(
                connection,
                operation_id,
                actor_id,
                "object_version_created",
                object_id,
                {"version": version, "type": object_type, "body_digest": body_digest},
            )
        return {"id": object_id, "type": object_type, "version": version, "digest": body_digest}

    def get_object(self, object_id: str, version: int | None = None) -> dict[str, Any] | None:
        if version is None:
            row = self.connection.execute(
                "SELECT * FROM objects WHERE object_id=? ORDER BY version DESC LIMIT 1", (object_id,)
            ).fetchone()
        else:
            row = self.connection.execute(
                "SELECT * FROM objects WHERE object_id=? AND version=?", (object_id, version)
            ).fetchone()
        if row is None:
            return None
        return {
            "id": row["object_id"],
            "type": row["object_type"],
            "version": row["version"],
            "digest": row["body_digest"],
            "body": json.loads(row["body_json"]),
            "created_at": row["created_at"],
        }

    def add_dependency(
        self,
        upstream_id: str,
        downstream_id: str,
        relation: str,
        knowledge_state: str,
    ) -> None:
        if knowledge_state not in {"complete", "partial", "unknown"}:
            raise StoreError("invalid dependency knowledge state")
        with self.transaction() as connection:
            connection.execute(
                "INSERT OR REPLACE INTO dependencies VALUES(?,?,?,?,?)",
                (upstream_id, downstream_id, relation, knowledge_state, utc_now()),
            )

    def invalidate_releases(self, changed_object_id: str, *, reason: str) -> dict[str, Any]:
        """Development persistence: commit all suspensions and audit entries atomically."""
        if not changed_object_id or not reason.strip():
            raise StoreError('source and reason required for change processing')
        with self.transaction() as connection:
            rows = connection.execute(
                "SELECT release_id,revision FROM releases WHERE state='approved' ORDER BY release_id"
            ).fetchall()
            suspended = []
            for row in rows:
                rid = str(row['release_id'])
                revision = int(row['revision']) + 1
                updated = connection.execute("""
                    UPDATE releases SET state='suspended', revision=?, reason=?, updated_at=?
                    WHERE release_id=? AND revision=? AND state='approved'
                """, (revision, reason, utc_now(), rid, row['revision']))
                if updated.rowcount != 1:
                    raise ConcurrencyConflict('release changed during invalidation')
                self.append_audit(connection, f'change:{changed_object_id}:release:{rid}:revision:{revision}',
                                  'LOCAL_SYSTEM', 'release_suspended_due_to_change', rid,
                                  {'source': changed_object_id, 'reason': reason, 'revision': revision})
                suspended.append(rid)
            self.append_audit(connection, f'change:{changed_object_id}:record',
                              'LOCAL_SYSTEM', 'source_change_requires_review', changed_object_id,
                              {'suspended_release_ids': suspended, 'dependency_knowledge': 'unknown'})
        return {'changed_object_id': changed_object_id, 'dependency_knowledge': 'unknown',
                'impact_completeness': 'incomplete', 'definitive_unaffected_claim_permitted': False,
                'suspended_release_ids': sorted(suspended), 'reassessment_required': True,
                'impact_scope': 'all_active_releases_conservative'}

    def affected(self, upstream_id: str) -> dict[str, Any]:
        seen = {upstream_id}
        frontier = [upstream_id]
        affected: set[str] = set()
        states: set[str] = set()
        while frontier:
            current = frontier.pop()
            rows = self.connection.execute(
                "SELECT downstream_id,knowledge_state FROM dependencies WHERE upstream_id=?",
                (current,),
            ).fetchall()
            for row in rows:
                downstream = str(row["downstream_id"])
                states.add(str(row["knowledge_state"]))
                affected.add(downstream)
                if downstream not in seen:
                    seen.add(downstream)
                    frontier.append(downstream)
        if "unknown" in states:
            completeness = "unknown"
        elif "partial" in states or not states:
            completeness = "partial"
        else:
            completeness = "complete"
        return {
            "changed_object_id": upstream_id,
            "potentially_affected_ids": sorted(affected),
            "dependency_knowledge": completeness,
            "impact_completeness": "incomplete",
            "unknown_downstream_dependencies_possible": True,
            "definitive_unaffected_claim_permitted": False,
        }

    def commit_assessment(self, result: dict[str, Any]) -> dict[str, Any]:
        manifest = result["manifest"]
        assessment_id = str(result["assessment_id"])
        with self.transaction() as connection:
            by_identity = connection.execute(
                "SELECT input_digest,result_json FROM assessments WHERE assessment_id=?",
                (assessment_id,),
            ).fetchone()
            if by_identity:
                if by_identity["input_digest"] != manifest["input_digest"]:
                    raise ImmutableConflict(
                        "assessment identity is already bound to a different input snapshot"
                    )
                return json.loads(by_identity["result_json"])
            existing = connection.execute(
                "SELECT result_json FROM assessments WHERE manifest_digest=?",
                (manifest["manifest_digest"],),
            ).fetchone()
            if existing:
                return json.loads(existing["result_json"])
            connection.execute(
                "INSERT INTO assessments VALUES(?,?,?,?,?,?,?)",
                (
                    assessment_id,
                    manifest["manifest_digest"],
                    manifest["input_digest"],
                    canonical_json(result).decode(),
                    result["execution_state"],
                    result["technical_readiness"],
                    utc_now(),
                ),
            )
        return result

    def get_assessment(self, assessment_id: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT result_json FROM assessments WHERE assessment_id=?", (assessment_id,)
        ).fetchone()
        return json.loads(row["result_json"]) if row else None

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
        assessment = self.get_assessment(assessment_id)
        if assessment is None:
            raise StoreError("assessment not found")
        if assessment.get("technical_readiness") != "ready_for_review":
            raise StoreError("assessment is not technically ready for authorized review")
        with self.transaction() as connection:
            connection.execute(
                "INSERT INTO releases VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    release_id,
                    assessment_id,
                    "approved",
                    1,
                    scope_digest,
                    configuration_digest,
                    evidence_snapshot_digest,
                    authority_id,
                    authority_role,
                    reason,
                    utc_now(),
                    utc_now(),
                ),
            )
            self.append_audit(
                connection,
                operation_id,
                authority_id,
                "release_approved",
                release_id,
                {"assessment_id": assessment_id, "scope_digest": scope_digest},
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
        if authority_role != "release_authority":
            raise StoreError("actor lacks release authority")
        transitions = {
            "approved": {"suspended", "withdrawn"},
            "suspended": {"approved", "withdrawn"},
            "withdrawn": set(),
        }
        with self.transaction() as connection:
            row = connection.execute("SELECT * FROM releases WHERE release_id=?", (release_id,)).fetchone()
            if row is None:
                raise StoreError("release not found")
            if int(row["revision"]) != expected_revision:
                raise ConcurrencyConflict("release revision changed")
            if new_state not in transitions.get(str(row["state"]), set()):
                raise StoreError("illegal release transition")
            revision = expected_revision + 1
            updated = connection.execute(
                "UPDATE releases SET state=?,revision=?,reason=?,updated_at=? WHERE release_id=? AND revision=?",
                (new_state, revision, reason, utc_now(), release_id, expected_revision),
            )
            if updated.rowcount != 1:
                raise ConcurrencyConflict("release revision changed")
            self.append_audit(
                connection,
                operation_id,
                actor_id,
                f"release_{new_state}",
                release_id,
                {"reason": reason, "revision": revision},
            )
        return self.get_release(release_id) or {}

    def get_release(self, release_id: str) -> dict[str, Any] | None:
        row = self.connection.execute("SELECT * FROM releases WHERE release_id=?", (release_id,)).fetchone()
        return dict(row) if row else None

    def list_releases(self) -> list[dict[str, Any]]:
        return [dict(row) for row in self.connection.execute("SELECT * FROM releases ORDER BY release_id")]
