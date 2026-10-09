from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from typing import Any, Iterable


GENESIS_HMAC = "0" * 64


def stable_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def event_hmac(
    secret: bytes,
    *,
    stream_id: str,
    epoch: int,
    sequence: int,
    previous_hmac: str,
    event: dict[str, Any],
) -> str:
    if len(secret) < 32:
        raise ValueError("audit HMAC secret must contain at least 32 bytes")
    envelope = {
        "stream_id": stream_id,
        "epoch": epoch,
        "sequence": sequence,
        "previous_hmac": previous_hmac,
        "event": event,
    }
    return hmac.new(secret, stable_bytes(envelope), hashlib.sha256).hexdigest()


@dataclass(frozen=True)
class AuditVerification:
    valid: bool
    verified_events: int
    failure_sequence: int | None = None
    reason: str | None = None


def verify_chain(secret: bytes, stream_id: str, epoch: int, events: Iterable[dict[str, Any]]) -> AuditVerification:
    expected_previous = GENESIS_HMAC
    expected_sequence = 1
    count = 0
    for row in events:
        sequence = int(row["sequence"])
        if sequence != expected_sequence:
            return AuditVerification(False, count, sequence, "sequence gap or reorder")
        if not hmac.compare_digest(str(row["previous_hmac"]), expected_previous):
            return AuditVerification(False, count, sequence, "previous HMAC mismatch")
        payload = dict(row["event"])
        expected = event_hmac(
            secret,
            stream_id=stream_id,
            epoch=epoch,
            sequence=sequence,
            previous_hmac=expected_previous,
            event=payload,
        )
        if not hmac.compare_digest(str(row["event_hmac"]), expected):
            return AuditVerification(False, count, sequence, "event HMAC mismatch")
        expected_previous = expected
        expected_sequence += 1
        count += 1
    return AuditVerification(True, count)
