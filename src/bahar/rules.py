from __future__ import annotations

from datetime import date, datetime
from typing import Any

from .models import AuthorityKind


class RuleError(ValueError):
    pass


def parse_date(value: str | None) -> date | None:
    if value is None:
        return None
    return date.fromisoformat(value)


def _event_date(context: dict[str, Any], event: str) -> date | None:
    times = context.get("relevant_times", {})
    value = times.get(event)
    if not value:
        return None
    # Preserve date boundary rather than converting through the host timezone.
    return parse_date(str(value)[:10])


def validate_rule(rule: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    for field in (
        "id",
        "version",
        "jurisdiction",
        "authority_kind",
        "source_id",
        "source_url",
        "provision",
        "effective_from",
        "obligation_id",
        "relevant_event",
    ):
        if not rule.get(field):
            errors.append(f"rule {rule.get('id', '<unknown>')} missing {field}")
    try:
        AuthorityKind(str(rule.get("authority_kind")))
    except ValueError:
        errors.append(f"rule {rule.get('id', '<unknown>')} has invalid authority_kind")
    if rule.get("status") != "approved":
        errors.append(f"rule {rule.get('id', '<unknown>')} is not approved")
    if not rule.get("interpretation_approved_by"):
        errors.append(f"rule {rule.get('id', '<unknown>')} lacks approved interpretation authority")
    return errors


def is_applicable(rule: dict[str, Any], context: dict[str, Any]) -> bool:
    if rule.get("status") != "approved":
        return False
    if rule.get("jurisdiction") != context.get("jurisdiction"):
        return False
    event = str(rule.get("relevant_event", "market"))
    relevant = _event_date(context, event)
    if relevant is None:
        return False
    start = parse_date(rule.get("effective_from"))
    end = parse_date(rule.get("effective_to"))
    if start and relevant < start:
        return False
    if end and relevant > end:
        return False
    return True


def select_rules(
    rules: list[dict[str, Any]], context: dict[str, Any]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    errors = [error for rule in rules for error in validate_rule(rule)]
    applicable = [rule for rule in rules if is_applicable(rule, context)]
    conflicts: list[dict[str, Any]] = []
    by_obligation: dict[str, list[dict[str, Any]]] = {}
    for rule in applicable:
        by_obligation.setdefault(str(rule["obligation_id"]), []).append(rule)
    for obligation_id, group in by_obligation.items():
        signatures = {
            (
                tuple(sorted(rule.get("allergens", []))),
                bool(rule.get("separate_statement_required", False)),
                bool(rule.get("visual_emphasis_required", False)),
            )
            for rule in group
        }
        if len(signatures) > 1:
            # Untrusted assessment context has no authority to resolve law.
            # A registered, membership-approved precedence policy is applied
            # *before* this pure selector by GovernedWorkflow.
            conflicts.append(
                {
                    "obligation_id": obligation_id,
                    "rule_ids": sorted(str(rule["id"]) for rule in group),
                }
            )
    return applicable, conflicts, errors


def binding_rules(rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    binding = {AuthorityKind.BINDING_LAW.value, AuthorityKind.INCORPORATED_STANDARD.value}
    return [rule for rule in rules if rule.get("authority_kind") in binding]


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")
