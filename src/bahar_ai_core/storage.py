"""Transactional, single-user DEMO SQLite assessment/review ledger.

Not encrypted, not multi-tenant, and not an institutional identity or authorization service.
"""
from __future__ import annotations
from datetime import datetime, timezone
from pathlib import Path
import json
import sqlite3
from hashlib import sha256
from .engine import stable_json
from .assurance import validate_assessment, AssuranceError, assert_consistent_for_review

class StoreError(ValueError):
    pass

class SQLiteStore:
    def __init__(self, path: str):
        self.path = str(Path(path))
        self.db = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        self.db.execute("PRAGMA foreign_keys = ON")
        self.db.execute("PRAGMA busy_timeout = 10000")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS assessment(
                id TEXT PRIMARY KEY, snapshot_sha256 TEXT NOT NULL,
                assessment_json TEXT NOT NULL, payload_sha256 TEXT NOT NULL, created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS idempotency(
                key TEXT PRIMARY KEY, snapshot_sha256 TEXT NOT NULL,
                execution_manifest_sha256 TEXT NOT NULL, assessment_id TEXT NOT NULL REFERENCES assessment(id)
            );
            CREATE TABLE IF NOT EXISTS candidate_review(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                assessment_id TEXT NOT NULL REFERENCES assessment(id),
                candidate_id TEXT NOT NULL, reviewer TEXT NOT NULL,
                decision TEXT NOT NULL CHECK(decision IN ('ACCEPT_CANDIDATE','REJECT_CANDIDATE','REQUEST_EVIDENCE')),
                concept_id TEXT, rationale TEXT NOT NULL, created_at TEXT NOT NULL
            );
        """)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()

    def close(self):
        self.db.close()

    def save(self, result: dict, *, idempotency_key: str | None = None) -> dict:
        if not isinstance(result, dict) or not isinstance(result.get("assessment_id"), str):
            raise StoreError("Assessment ID is mandatory")
        try:
            validate_assessment(result)
        except (AssuranceError, TypeError, KeyError, ValueError) as exc:
            raise StoreError("Assessment failed structural assurance validation") from exc
        snap = result.get("snapshot_sha256")
        if not isinstance(snap, str) or len(snap) != 64:
            raise StoreError("Cannot persist a result without a valid input snapshot digest")
        if sha256(stable_json(result.get("source_snapshot")).encode("utf-8")).hexdigest() != snap:
            raise StoreError("Input snapshot digest mismatch")
        if idempotency_key is not None and not (isinstance(idempotency_key, str) and 1 <= len(idempotency_key) <= 128):
            raise StoreError("Invalid idempotency key")
        manifest = result.get("execution_manifest", {})
        if not isinstance(manifest.get("mode"), str):
            raise StoreError("Missing execution mode")
        manifest_hash = sha256(stable_json(manifest).encode("utf-8")).hexdigest()
        payload = stable_json(result)
        payload_hash = sha256(payload.encode("utf-8")).hexdigest()
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            if idempotency_key:
                old = self.db.execute("SELECT snapshot_sha256,execution_manifest_sha256,assessment_id FROM idempotency WHERE key=?", (idempotency_key,)).fetchone()
                if old:
                    if old[:2] != (snap, manifest_hash):
                        raise StoreError("Idempotency key already used for different input or execution manifest")
                    return self.get(old[2])
            try:
                self.db.execute("INSERT INTO assessment(id,snapshot_sha256,assessment_json,payload_sha256,created_at) VALUES(?,?,?,?,?)",
                                (result["assessment_id"], snap, payload, payload_hash, result["created_at"]))
            except sqlite3.IntegrityError as exc:
                raise StoreError("Assessment identifier already exists") from exc
            if idempotency_key:
                self.db.execute("INSERT INTO idempotency(key,snapshot_sha256,execution_manifest_sha256,assessment_id) VALUES(?,?,?,?)",
                                (idempotency_key, snap, manifest_hash, result["assessment_id"]))
        return result

    def get(self, assessment_id: str) -> dict:
        row = self.db.execute("SELECT assessment_json,payload_sha256 FROM assessment WHERE id=?", (assessment_id,)).fetchone()
        if row is None:
            raise StoreError("Assessment not found")
        if sha256(row[0].encode("utf-8")).hexdigest() != row[1]:
            raise StoreError("Assessment payload integrity failure")
        document = json.loads(row[0])
        digest = sha256(stable_json(document.get("source_snapshot")).encode("utf-8")).hexdigest()
        if digest != document.get("snapshot_sha256"):
            raise StoreError("Input snapshot provenance integrity failure")
        try:
            validate_assessment(document)
        except (AssuranceError, TypeError, KeyError, ValueError) as exc:
            raise StoreError("Stored assessment failed structural assurance validation") from exc
        return document

    def list_assessments(self, limit: int = 20) -> list[dict]:
        if type(limit) is not int or not 1 <= limit <= 100:
            raise StoreError("Invalid page limit")
        ids = self.db.execute("SELECT id FROM assessment ORDER BY created_at DESC,id DESC LIMIT ?", (limit,)).fetchall()
        return [self.get(row[0]) for row in ids]

    def review(self, assessment_id: str, candidate_id: str, reviewer: str, decision: str,
               rationale: str, concept_id: str | None = None) -> dict:
        if decision not in ("ACCEPT_CANDIDATE", "REJECT_CANDIDATE", "REQUEST_EVIDENCE"):
            raise StoreError("Invalid review decision")
        if not all(isinstance(s, str) and 1 <= len(s.strip()) <= 256 for s in (candidate_id, reviewer, rationale)):
            raise StoreError("Invalid candidate, reviewer, or rationale")
        assessment = self.get(assessment_id)
        candidate = next((c for c in assessment["candidates"] if c["candidate_id"] == candidate_id), None)
        if candidate is None:
            raise StoreError("Candidate not in the immutable assessment snapshot")
        if decision == "ACCEPT_CANDIDATE":
            from .knowledge import BY_ID
            if concept_id not in BY_ID:
                raise StoreError("Accept requires a controlled concept_id")
            try:
                assert_consistent_for_review(assessment, candidate, concept_id)
            except AssuranceError as exc:
                raise StoreError(str(exc)) from exc
        elif concept_id is not None:
            raise StoreError("Only an ACCEPT_CANDIDATE decision can name a concept")
        record = {"assessment_id": assessment_id, "snapshot_sha256": assessment["snapshot_sha256"],
                  "candidate_id": candidate_id, "candidate_text": candidate["text"],
                  "reviewer": reviewer, "decision": decision, "concept_id": concept_id,
                  "rationale": rationale, "authority_status": "UNVERIFIED_DEMO_REVIEWER_IDENTITY",
                  "automatically_promoted_to_physical_truth": False,
                  "created_at": datetime.now(timezone.utc).isoformat()}
        with self.db:
            self.db.execute("INSERT INTO candidate_review(assessment_id,candidate_id,reviewer,decision,concept_id,rationale,created_at) VALUES(?,?,?,?,?,?,?)",
                            (assessment_id, candidate_id, reviewer, decision, concept_id, rationale, record["created_at"]))
        return record

    def reviews(self, assessment_id: str) -> list[dict]:
        self.get(assessment_id)
        rows = self.db.execute("SELECT candidate_id,reviewer,decision,concept_id,rationale,created_at FROM candidate_review WHERE assessment_id=? ORDER BY id", (assessment_id,)).fetchall()
        return [{"candidate_id": c, "reviewer": r, "decision": d, "concept_id": k,
                 "rationale": n, "created_at": t, "authority_status": "UNVERIFIED_DEMO_REVIEWER_IDENTITY"}
                for c, r, d, k, n, t in rows]
