from __future__ import annotations

from typing import Any, Iterable

from .models import EvidencePair


QUALIFICATION_DIMENSIONS = (
    "source_identity_verified",
    "integrity_verified",
    "relevant",
    "applicable",
    "substantively_qualified",
)


def scopes_compatible(left: dict[str, Any], right: dict[str, Any]) -> bool:
    """Compare only declared scope keys; incompatible lots must not conflict."""
    shared = set(left) & set(right)
    return all(left[key] == right[key] for key in shared)


def qualified(assertion: dict[str, Any]) -> bool:
    return all(assertion.get(dimension) is True for dimension in QUALIFICATION_DIMENSIONS)


def support_for(
    assertions: Iterable[dict[str, Any]],
    proposition: str,
    scope: dict[str, Any],
) -> tuple[EvidencePair, list[dict[str, Any]]]:
    matched: list[dict[str, Any]] = []
    positive = False
    negative = False
    for assertion in assertions:
        if assertion.get("proposition") != proposition:
            continue
        assertion_scope = dict(assertion.get("scope", {}))
        if not scopes_compatible(assertion_scope, scope):
            continue
        if assertion.get('polarity') == 'negative':
            # Negative claims NEVER generalize from a generic material or an
            # unspecified lot to a more specific supplier/material/lot query.
            # Generic knowledge is not proof of material-specific absence.
            if any(assertion_scope.get(key) != scope.get(key) for key in
                   ('material_id', 'supplier_id', 'material_lot_id', 'specification_version')):
                continue
            if not all(assertion_scope.get(key) for key in
                       ('material_id', 'supplier_id', 'material_lot_id', 'specification_version')):
                continue
        matched.append(assertion)
        if not qualified(assertion):
            continue
        polarity = assertion.get("polarity")
        positive = positive or polarity == "positive"
        negative = negative or polarity == "negative"
    return EvidencePair(positive=positive, negative=negative), matched


def verify_evidence(assertions: Iterable[dict[str, Any]]) -> list[str]:
    errors: list[str] = []
    seen_ids: set[str] = set()
    for index, assertion in enumerate(assertions):
        assertion_id = str(assertion.get("id", ""))
        if not assertion_id:
            errors.append(f"evidence[{index}] has no id")
        elif assertion_id in seen_ids:
            errors.append(f"duplicate evidence id: {assertion_id}")
        seen_ids.add(assertion_id)
        if assertion.get("polarity") not in {"positive", "negative", "qualifying"}:
            errors.append(f"evidence[{index}] has invalid polarity")
        if not assertion.get("source_id"):
            errors.append(f"evidence[{index}] has no source_id")
        if not assertion.get("proposition"):
            errors.append(f"evidence[{index}] has no proposition")
    return errors

