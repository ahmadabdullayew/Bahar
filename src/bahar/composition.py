from __future__ import annotations

from decimal import Decimal, InvalidOperation
from typing import Any

from .knowledge import IngredientResolution, resolve_ingredient


class CompositionError(ValueError):
    pass


UNIT_DIMENSIONS = {
    "kg": ("mass", Decimal("1000")),
    "g": ("mass", Decimal("1")),
    "mg": ("mass", Decimal("0.001")),
    "l": ("volume", Decimal("1000")),
    "ml": ("volume", Decimal("1")),
}


def convert_quantity(value: str | int | float, source: str, target: str) -> Decimal:
    if source not in UNIT_DIMENSIONS or target not in UNIT_DIMENSIONS:
        raise CompositionError("unknown quantity unit")
    source_dimension, source_factor = UNIT_DIMENSIONS[source]
    target_dimension, target_factor = UNIT_DIMENSIONS[target]
    if source_dimension != target_dimension:
        raise CompositionError("incompatible quantity conversion")
    try:
        amount = Decimal(str(value))
    except InvalidOperation as exc:
        raise CompositionError("invalid quantity") from exc
    if not amount.is_finite() or amount < 0:
        raise CompositionError("quantity must be finite and non-negative")
    return amount * source_factor / target_factor


def resolve_formulation(
    root: dict[str, Any],
    formulations: dict[str, dict[str, Any]] | None = None,
) -> tuple[list[IngredientResolution], list[str]]:
    """Resolve nested formulation versions and reject cycles or floating references."""
    formulations = formulations or {}
    resolved: list[IngredientResolution] = []
    issues: list[str] = []

    def visit(formulation: dict[str, Any], stack: tuple[str, ...]) -> None:
        identity = f"{formulation.get('id')}@{formulation.get('version')}"
        if identity in stack:
            raise CompositionError(f"cyclic formulation reference: {' -> '.join(stack + (identity,))}")
        for ingredient in formulation.get("ingredients", []):
            try:
                quantity = ingredient.get("quantity")
                if quantity is not None:
                    convert_quantity(quantity["value"], quantity["unit"], quantity["unit"])
            except (KeyError, TypeError, CompositionError) as exc:
                issues.append(f"{ingredient.get('id', '<unknown>')}: {exc}")
            resolved.append(resolve_ingredient(ingredient))
        for component in formulation.get("subrecipes", []):
            component_id = component.get("formulation_id")
            component_version = component.get("version")
            if not component_id or not component_version:
                issues.append("subrecipe reference lacks an exact id and version")
                continue
            key = f"{component_id}@{component_version}"
            target = formulations.get(key)
            if target is None:
                issues.append(f"unavailable subrecipe: {key}")
                continue
            visit(target, stack + (identity,))

    visit(root, ())
    return resolved, issues

