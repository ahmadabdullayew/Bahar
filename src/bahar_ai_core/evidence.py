"""Assertion *support* logic, not a laboratory, authentication or truth engine."""
from __future__ import annotations
from collections import defaultdict
from hashlib import sha256
import json

VALID_POLARITIES = {"support", "refute"}


def validate_assertions(assertions: list[dict] | tuple[dict, ...]) -> list[dict]:
    if not isinstance(assertions, (list, tuple)) or len(assertions) > 500:
        raise ValueError("evidence_assertions must be a collection of at most 500 records")
    result = []
    seen = set()
    for a in assertions:
        if not isinstance(a, dict):
            raise ValueError("Evidence assertion must be an object")
        if set(a) - {"proposition", "scope", "polarity", "evidence_id", "qualified"}:
            raise ValueError("Unsupported evidence assertion fields")
        key, scope, polarity, ref = (a.get(k) for k in ("proposition", "scope", "polarity", "evidence_id"))
        if not all(isinstance(v, str) and 0 < len(v.strip()) <= 256 for v in (key, scope, ref)):
            raise ValueError("Exact proposition, scope and evidence_id are mandatory")
        if polarity not in VALID_POLARITIES or type(a.get("qualified", False)) is not bool:
            raise ValueError("Invalid evidence polarity or qualified indicator")
        identity = (key, scope, polarity, ref)
        if identity in seen:
            raise ValueError("Duplicate evidence assertion")
        seen.add(identity)
        # Legacy qualified=True is USER ASSERTED, not cryptographic or domain expert verification.
        result.append({"proposition": key, "scope": scope, "polarity": polarity,
                       "evidence_id": ref, "qualification_origin": "USER_DECLARED" if a.get("qualified") else "UNREVIEWED"})
    return result


def summarize(assertions: list[dict] | tuple[dict, ...]) -> dict[str, dict]:
    records = validate_assertions(assertions)
    buckets: dict[tuple[str, str], dict[str, list[str]]] = defaultdict(lambda: {"positive": [], "negative": []})
    for r in records:
        if r["qualification_origin"] != "USER_DECLARED":
            continue
        target = "positive" if r["polarity"] == "support" else "negative"
        buckets[(r["proposition"], r["scope"])][target].append(r["evidence_id"])
    result = {}
    for (key, scope), pair in sorted(buckets.items()):
        pos, neg = bool(pair["positive"]), bool(pair["negative"])
        state = {(False, False): "UNKNOWN", (True, False): "SUPPORTED_POSITIVE",
                 (False, True): "SUPPORTED_NEGATIVE", (True, True): "CONFLICTED_EVIDENCE"}[(pos, neg)]
        result[f"{scope}::{key}"] = {
            "state": state, "positive_refs": sorted(pair["positive"]), "negative_refs": sorted(pair["negative"]),
            "qualification_origin": "USER_DECLARED_NOT_INDEPENDENTLY_VERIFIED",
            "physical_truth_established": False,
        }
    return result


def evidence_digest(assertions: list[dict] | tuple[dict, ...]) -> str:
    records = validate_assertions(assertions)
    return sha256(json.dumps(sorted(records, key=lambda r: (r["scope"], r["proposition"], r["evidence_id"], r["polarity"])),
                             sort_keys=True, separators=(",", ":")).encode()).hexdigest()
