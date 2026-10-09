from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from datetime import date, datetime
from decimal import Decimal
from typing import Any, Iterable

from sqlalchemy import text

from .assessment import digest
from .audit import stable_bytes
from .persistence import PostgresBaharStore
from .store import StoreError
from .authorization import authorize_operational_action


class OperationsError(StoreError):
    pass


def _json(value: Any) -> str:
    return stable_bytes(value).decode("utf-8")


def _normalise(value: Any) -> Any:
    if isinstance(value, (uuid.UUID, date, datetime, Decimal)):
        return str(value)
    if isinstance(value, dict):
        return {str(key): _normalise(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_normalise(item) for item in value]
    return value


def _record(row: Any) -> dict[str, Any]:
    return _normalise(dict(row))


def _uuid(value: Any, field: str) -> str:
    try:
        return str(uuid.UUID(str(value)))
    except (ValueError, TypeError, AttributeError) as exc:
        raise OperationsError(f"{field} must be a UUID") from exc


def _required(payload: dict[str, Any], *names: str) -> None:
    missing = [name for name in names if payload.get(name) in (None, "")]
    if missing:
        raise OperationsError("missing required fields: " + ", ".join(missing))


@dataclass(frozen=True)
class Resolution:
    state: str
    input_composition: list[dict[str, Any]]
    finished_product_composition: list[dict[str, Any]] | dict[str, Any] | None
    unresolved_claims: list[dict[str, Any]]
    visited_versions: list[str]


class OperationsService:
    """Tenant-bound operational workflows.

    All facts that can affect an assessment are inserted as immutable records.
    Corrections and assessments add records; they never rewrite historical facts.
    """

    def __init__(self, store: PostgresBaharStore):
        self.store = store
        self.organization_id = str(store.context.organization_id)
        self.principal_id = str(store.context.principal_id)

    # Every material mutation invalidates *all* active assurances when graph
    # completeness has not been independently certified. This is deliberately
    # conservative. The source mutation, release transitions and audit events
    # all commit or roll back in the SAME PostgreSQL transaction.
    MATERIAL_ACTIONS = frozenset({
        "material_specification_registered", "material_receipt_registered",
        "origin_finding_recorded", "supplier_correction_recorded",
        "formulation_version_registered", "label_text_registered",
        "artwork_registered", "artwork_assessed", "manufacturing_batch_recorded",
        "physical_package_inspected", "cleaning_event_recorded",
        "cross_contact_assessed", "packaging_lot_registered",
    })

    def _audit(self, connection: Any, action: str, target_type: str, target_id: str,
               detail: dict[str, Any], reason: str = "recorded") -> dict[str, Any]:
        # Fail closed: every recorded business mutation must have a verified
        # membership-backed action role, within the same transaction.
        authorize_operational_action(self.store, connection, action)
        impact = self.store.suspend_active_releases_in_transaction(
            connection, change_key=f"{target_type}:{target_id}",
            reason=f"Material change {action} requires assessment continuity review",
        ) if action in self.MATERIAL_ACTIONS else {
            'dependency_knowledge': 'not_assessed', 'impact_completeness': 'not_assessed',
            'suspended_release_ids': []}
        self.store._audit(
            connection,
            action=action,
            target_type=target_type,
            target_id=target_id,
            target_revision=None,
            outcome="success",
            reason=reason,
            operation_id=f"{action}:{target_id}:{uuid.uuid4()}",
            detail={**detail, "impact_control": impact},
        )
        return impact

    def ensure_local_reference_data(self) -> dict[str, Any]:
        facility_id = str(uuid.uuid5(self.store.context.organization_id, "facility:LOCAL"))
        units = (
            ("kg", "mass", "1000"), ("g", "mass", "1"), ("mg", "mass", "0.001"),
            ("l", "volume", "1000"), ("ml", "volume", "1"),
            ("ea", "count", "1"), ("pct", "dimensionless", "0.01"),
        )
        with self.store.transaction() as connection:
            connection.execute(text("""
                INSERT INTO facilities (organization_id, facility_id, code, name, state)
                VALUES (:org, :id, 'LOCAL', 'Local qualification facility', 'active')
                ON CONFLICT (organization_id, code) DO NOTHING
            """), {"org": self.organization_id, "id": facility_id})
            for code, dimension, factor in units:
                connection.execute(text("""
                    INSERT INTO units (organization_id, unit_code, dimension, factor_to_base, approved_by)
                    VALUES (:org, :code, :dimension, :factor, :principal)
                    ON CONFLICT (organization_id, unit_code) DO NOTHING
                """), {"org": self.organization_id, "code": code, "dimension": dimension,
                        "factor": factor, "principal": self.principal_id})
        return {"facility_id": facility_id, "unit_codes": [item[0] for item in units]}

    def dashboard(self) -> dict[str, Any]:
        counts: dict[str, int] = {}
        tables = {
            "suppliers": "suppliers", "materials": "purchased_materials",
            "supplier_lots": "supplier_lots", "receipts": "material_receipts",
            "formulations": "formulations", "artworks": "artwork_versions",
            "batches": "manufacturing_batches", "inspections": "physical_package_inspections",
            "cross_contact_assessments": "cross_contact_assessments",
        }
        with self.store.transaction() as connection:
            for key, table in tables.items():
                counts[key] = int(connection.execute(
                    text(f"SELECT count(*) FROM {table} WHERE organization_id = :org"),
                    {"org": self.organization_id},
                ).scalar_one())
            recent = connection.execute(text("""
                SELECT action, target_type, target_id, outcome, created_at
                FROM audit_events WHERE organization_id = :org
                ORDER BY epoch DESC, sequence DESC LIMIT 12
            """), {"org": self.organization_id}).mappings().all()
        return {"counts": counts, "recent_audit_events": [_record(row) for row in recent]}

    def list_records(self, resource: str) -> list[dict[str, Any]]:
        """Compatibility method: returns the initial page only."""
        return self.list_records_page(resource, limit=200)["records"]

    def list_records_page(self, resource: str, *, limit: int = 40,
                          offset: int = 0, search: str = "") -> dict[str, Any]:
        if not (1 <= limit <= 200) or offset < 0 or offset > 1_000_000:
            raise OperationsError("invalid pagination range")
        if len(search) > 160:
            raise OperationsError("search query is too long")
        queries = {
            "suppliers": "SELECT supplier_id, supplier_code, legal_name, status, created_at FROM suppliers",
            "materials": "SELECT material_id, material_code, name, material_kind, status, created_at FROM purchased_materials",
            "supplier-identifiers": "SELECT supplier_id, material_id, supplier_identifier, valid_from, valid_until, created_at FROM supplier_material_identifiers",
            "specifications": "SELECT specification_id, supplier_id, material_id, specification_code, specification_version, valid_from, valid_until, retracted_at, declared_origin, accepted_origin, created_at FROM material_specifications",
            "lots": "SELECT supplier_lot_id, supplier_id, material_id, lot_code, manufactured_on, expires_on, created_at FROM supplier_lots",
            "receipts": "SELECT receipt_id, receipt_code, supplier_lot_id, received_at, quantity, unit_code, facility_id, bound_specification_id, specification_binding_reason, created_at FROM material_receipts",
            "formulations": "SELECT formulation_id, formulation_code, name, current_version, state, created_at FROM formulations",
            "labels": "SELECT label_text_id, label_code, version, language_tag, ingredient_declaration, allergen_statement, text_sha256, created_at FROM label_text_versions",
            "artworks": "SELECT artwork_id, artwork_code, version, label_text_id, artifact_id, artifact_version, package_size, language_tags, status, created_at FROM artwork_versions",
            "batches": "SELECT batch_id, batch_code, facility_id, line_id, formulation_id, formulation_version, started_at, completed_at, actual_material_record_state, state, created_at FROM manufacturing_batches",
            "equipment": "SELECT equipment_id, line_id, equipment_code, name, shared, allergen_retention_features, created_at FROM equipment",
            "inspections": "SELECT inspection_id, sample_code, batch_id, artwork_match_state, ocr_state, legibility_state, emphasis_state, conclusion_scope, result, created_at FROM physical_package_inspections",
            "cross-contact": "SELECT cross_contact_assessment_id, batch_id, previous_batch_id, line_id, recipe_origin_allergens, unintended_hazards, state, evidence_sha256, created_at FROM cross_contact_assessments",
            "facilities": "SELECT facility_id, code, name, state, created_at FROM facilities",
            "lines": "SELECT line_id, facility_id, line_code, name, created_at FROM production_lines",
            "packaging-lots": "SELECT packaging_lot_id, lot_code, artwork_id, received_at, created_at FROM packaging_lots",
            "printers": "SELECT printer_specification_id, specification_code, created_at FROM printer_specifications",
            "camera-qualifications": "SELECT camera_qualification_id, camera_identifier, valid_from, valid_until, created_at FROM camera_qualifications",
            "sampling-plans": "SELECT sampling_plan_id, plan_code, plan_version, inference_scope, sample_size, created_at FROM sampling_plans",
            "cleaning-events": "SELECT cleaning_event_id, line_id, procedure_version, verification_state, completed_at, created_at FROM cleaning_events",
        }
        if resource not in queries:
            raise OperationsError("unknown resource")
        # Whitelisted base queries, parameterized tenant scope and search, bounded pages.
        # The outer query searches display fields only within the organization's records.
        query = f"""SELECT * FROM ({queries[resource]} WHERE organization_id = :org) AS scoped
            WHERE CAST(row_to_json(scoped) AS TEXT) ILIKE :pattern ESCAPE '\\'
            ORDER BY created_at DESC LIMIT :fetch_limit OFFSET :offset"""
        escaped = search.strip().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        with self.store.transaction() as connection:
            rows = connection.execute(text(query), {
                "org": self.organization_id, "pattern": f"%{escaped}%",
                "fetch_limit": limit + 1, "offset": offset,
            }).mappings().all()
        return {"records": [_record(row) for row in rows[:limit]],
                "has_more": len(rows) > limit, "limit": limit, "offset": offset}

    def create_supplier(self, payload: dict[str, Any]) -> dict[str, Any]:
        _required(payload, "supplier_code", "legal_name")
        supplier_id = str(uuid.uuid4())
        with self.store.transaction() as connection:
            row = connection.execute(text("""
                INSERT INTO suppliers (organization_id, supplier_id, supplier_code, legal_name, status)
                VALUES (:org, :id, :code, :name, 'active')
                RETURNING supplier_id, supplier_code, legal_name, status, created_at
            """), {"org": self.organization_id, "id": supplier_id,
                    "code": str(payload["supplier_code"]).strip(),
                    "name": str(payload["legal_name"]).strip()}).mappings().one()
            self._audit(connection, "supplier_registered", "supplier", supplier_id, _record(row))
        return _record(row)

    def create_material(self, payload: dict[str, Any]) -> dict[str, Any]:
        _required(payload, "material_code", "name", "material_kind")
        if payload["material_kind"] not in {"ingredient", "processing_aid", "packaging", "rework_carrier"}:
            raise OperationsError("invalid material_kind")
        material_id = str(uuid.uuid4())
        with self.store.transaction() as connection:
            row = connection.execute(text("""
                INSERT INTO purchased_materials
                  (organization_id, material_id, material_code, name, material_kind, status)
                VALUES (:org, :id, :code, :name, :kind, 'active')
                RETURNING material_id, material_code, name, material_kind, status, created_at
            """), {"org": self.organization_id, "id": material_id,
                    "code": str(payload["material_code"]).strip(), "name": str(payload["name"]).strip(),
                    "kind": payload["material_kind"]}).mappings().one()
            self._audit(connection, "material_registered", "material", material_id, _record(row))
        return _record(row)

    def create_supplier_identifier(self, payload: dict[str, Any]) -> dict[str, Any]:
        _required(payload, "supplier_id", "material_id", "supplier_identifier", "valid_from")
        with self.store.transaction() as connection:
            row = connection.execute(text("""
                INSERT INTO supplier_material_identifiers (
                  organization_id, supplier_id, material_id, supplier_identifier, valid_from, valid_until
                ) VALUES (:org, :supplier, :material, :identifier, :valid_from, :valid_until)
                RETURNING supplier_id, material_id, supplier_identifier, valid_from, valid_until, created_at
            """), {"org": self.organization_id,
                    "supplier": _uuid(payload["supplier_id"], "supplier_id"),
                    "material": _uuid(payload["material_id"], "material_id"),
                    "identifier": str(payload["supplier_identifier"]).strip(),
                    "valid_from": payload["valid_from"], "valid_until": payload.get("valid_until") or None,
                    }).mappings().one()
            target_id = f"{row['supplier_id']}:{row['supplier_identifier']}:{row['valid_from']}"
            self._audit(connection, "supplier_material_identifier_registered",
                        "supplier_material_identifier", target_id, _record(row))
        return _record(row)

    def create_specification(self, payload: dict[str, Any]) -> dict[str, Any]:
        _required(payload, "supplier_id", "material_id", "specification_code",
                  "specification_version", "valid_from")
        specification_id = str(uuid.uuid4())
        params = {
            "org": self.organization_id, "id": specification_id,
            "supplier": _uuid(payload["supplier_id"], "supplier_id"),
            "material": _uuid(payload["material_id"], "material_id"),
            "code": str(payload["specification_code"]).strip(),
            "version": str(payload["specification_version"]).strip(),
            "valid_from": payload["valid_from"], "valid_until": payload.get("valid_until") or None,
            "declared_origin": _json(payload.get("declared_origin", {})),
            "accepted_origin": _json(payload["accepted_origin"]) if payload.get("accepted_origin") is not None else None,
            "replaces": _uuid(payload["replaces_specification_id"], "replaces_specification_id")
            if payload.get("replaces_specification_id") else None,
        }
        with self.store.transaction() as connection:
            row = connection.execute(text("""
                INSERT INTO material_specifications (
                  organization_id, specification_id, supplier_id, material_id,
                  specification_code, specification_version, valid_from, valid_until,
                  declared_origin, accepted_origin, replaces_specification_id
                ) VALUES (
                  :org, :id, :supplier, :material, :code, :version, :valid_from, :valid_until,
                  CAST(:declared_origin AS jsonb), CAST(:accepted_origin AS jsonb), :replaces
                ) RETURNING specification_id, supplier_id, material_id, specification_code,
                  specification_version, valid_from, valid_until, declared_origin, accepted_origin, created_at
            """), params).mappings().one()
            self._audit(connection, "material_specification_registered", "material_specification",
                        specification_id, _record(row))
        return _record(row)

    def create_lot(self, payload: dict[str, Any]) -> dict[str, Any]:
        _required(payload, "supplier_id", "material_id", "lot_code")
        lot_id = str(uuid.uuid4())
        with self.store.transaction() as connection:
            row = connection.execute(text("""
                INSERT INTO supplier_lots (
                  organization_id, supplier_lot_id, supplier_id, material_id, lot_code,
                  manufactured_on, expires_on
                ) VALUES (:org, :id, :supplier, :material, :code, :manufactured, :expires)
                RETURNING supplier_lot_id, supplier_id, material_id, lot_code,
                  manufactured_on, expires_on, created_at
            """), {"org": self.organization_id, "id": lot_id,
                    "supplier": _uuid(payload["supplier_id"], "supplier_id"),
                    "material": _uuid(payload["material_id"], "material_id"),
                    "code": str(payload["lot_code"]).strip(),
                    "manufactured": payload.get("manufactured_on") or None,
                    "expires": payload.get("expires_on") or None}).mappings().one()
            self._audit(connection, "supplier_lot_registered", "supplier_lot", lot_id, _record(row))
        return _record(row)

    def create_receipt(self, payload: dict[str, Any]) -> dict[str, Any]:
        _required(payload, "receipt_code", "supplier_lot_id", "received_at", "quantity", "unit_code")
        receipt_id = str(uuid.uuid4())
        spec_id = _uuid(payload["bound_specification_id"], "bound_specification_id") \
            if payload.get("bound_specification_id") else None
        if spec_id and not payload.get("specification_binding_reason"):
            raise OperationsError("specification_binding_reason is required for a bound historical specification")
        with self.store.transaction() as connection:
            if spec_id:
                valid = connection.execute(text("""
                    SELECT 1 FROM material_specifications s
                    JOIN supplier_lots l ON l.organization_id=s.organization_id
                      AND l.supplier_id=s.supplier_id AND l.material_id=s.material_id
                    WHERE s.organization_id=:org AND s.specification_id=:spec
                      AND l.supplier_lot_id=:lot
                """), {"org": self.organization_id, "spec": spec_id,
                        "lot": _uuid(payload["supplier_lot_id"], "supplier_lot_id")}).scalar_one_or_none()
                if not valid:
                    raise OperationsError("specification does not belong to this supplier/material lot")
            row = connection.execute(text("""
                INSERT INTO material_receipts (
                  organization_id, receipt_id, receipt_code, supplier_lot_id, received_at,
                  quantity, unit_code, facility_id, bound_specification_id, specification_binding_reason
                ) VALUES (:org, :id, :code, :lot, :received, :quantity, :unit, :facility, :spec, :reason)
                RETURNING receipt_id, receipt_code, supplier_lot_id, received_at, quantity, unit_code,
                  facility_id, bound_specification_id, specification_binding_reason, created_at
            """), {"org": self.organization_id, "id": receipt_id,
                    "code": str(payload["receipt_code"]).strip(),
                    "lot": _uuid(payload["supplier_lot_id"], "supplier_lot_id"),
                    "received": payload["received_at"], "quantity": str(payload["quantity"]),
                    "unit": str(payload["unit_code"]),
                    "facility": _uuid(payload["facility_id"], "facility_id") if payload.get("facility_id") else None,
                    "spec": spec_id, "reason": payload.get("specification_binding_reason") or None,
                    }).mappings().one()
            self._audit(connection, "material_receipt_registered", "material_receipt", receipt_id, _record(row))
        return _record(row)

    def add_origin_finding(self, payload: dict[str, Any]) -> dict[str, Any]:
        _required(payload, "supplier_lot_id", "finding_kind", "origin", "finding_state", "observed_at")
        if payload["finding_kind"] not in {"supplier_declared", "independently_verified", "laboratory_finding"}:
            raise OperationsError("invalid finding_kind")
        if payload["finding_state"] not in {"unknown", "supported_positive", "supported_negative", "conflicted"}:
            raise OperationsError("invalid finding_state")
        finding_id = str(uuid.uuid4())
        with self.store.transaction() as connection:
            row = connection.execute(text("""
                INSERT INTO material_origin_findings (
                  organization_id, origin_finding_id, supplier_lot_id, finding_kind, origin,
                  finding_state, observed_at, approved_by
                ) VALUES (:org, :id, :lot, :kind, CAST(:origin AS jsonb), :state, :observed, :approved)
                RETURNING origin_finding_id, supplier_lot_id, finding_kind, origin,
                  finding_state, observed_at, approved_by, created_at
            """), {"org": self.organization_id, "id": finding_id,
                    "lot": _uuid(payload["supplier_lot_id"], "supplier_lot_id"),
                    "kind": payload["finding_kind"], "origin": _json(payload["origin"]),
                    "state": payload["finding_state"], "observed": payload["observed_at"],
                    "approved": self.principal_id if payload.get("approved", False) else None,
                    }).mappings().one()
            self._audit(connection, "origin_finding_recorded", "origin_finding", finding_id, _record(row))
        return _record(row)

    def create_supplier_correction(self, payload: dict[str, Any]) -> dict[str, Any]:
        _required(payload, "specification_id", "correction_kind", "correction", "effective_at")
        if payload["correction_kind"] not in {"clarification", "replacement", "retraction"}:
            raise OperationsError("invalid correction_kind")
        correction_id = str(uuid.uuid4())
        specification_id = _uuid(payload["specification_id"], "specification_id")
        with self.store.transaction(serializable=True) as connection:
            row = connection.execute(text("""
                INSERT INTO supplier_corrections (
                  organization_id, correction_id, specification_id, correction_kind,
                  correction, effective_at, created_by
                ) VALUES (:org, :id, :spec, :kind, CAST(:correction AS jsonb), :effective, :principal)
                RETURNING correction_id, specification_id, correction_kind, correction,
                  effective_at, created_by, created_at
            """), {"org": self.organization_id, "id": correction_id, "spec": specification_id,
                    "kind": payload["correction_kind"], "correction": _json(payload["correction"]),
                    "effective": payload["effective_at"], "principal": self.principal_id}).mappings().one()
            affected = connection.execute(text("""
                SELECT r.receipt_id, r.receipt_code, r.supplier_lot_id, r.received_at,
                       r.bound_specification_id, r.specification_binding_reason
                FROM material_receipts r
                WHERE r.organization_id=:org AND r.bound_specification_id=:spec
                ORDER BY r.received_at, r.receipt_id
            """), {"org": self.organization_id, "spec": specification_id}).mappings().all()
            detail = {"correction": _record(row), "affected_receipt_ids": [str(r["receipt_id"]) for r in affected],
                      "history_rewritten": False}
            impact = self._audit(connection, "supplier_correction_recorded", "supplier_correction",
                                 correction_id, detail)
        return {**_record(row), "affected_receipts": [_record(r) for r in affected],
                "history_rewritten": False, "impact_control": impact}

    def create_formulation(self, payload: dict[str, Any]) -> dict[str, Any]:
        _required(payload, "formulation_code", "name")
        formulation_id = str(uuid.uuid4())
        with self.store.transaction() as connection:
            row = connection.execute(text("""
                INSERT INTO formulations (organization_id, formulation_id, formulation_code, name)
                VALUES (:org, :id, :code, :name)
                RETURNING formulation_id, formulation_code, name, current_version, state, created_at
            """), {"org": self.organization_id, "id": formulation_id,
                    "code": str(payload["formulation_code"]).strip(),
                    "name": str(payload["name"]).strip()}).mappings().one()
            self._audit(connection, "formulation_registered", "formulation", formulation_id, _record(row))
        return _record(row)

    def _unit(self, connection: Any, unit_code: str) -> tuple[str, Decimal]:
        row = connection.execute(text("""
            SELECT dimension, factor_to_base FROM units
            WHERE organization_id=:org AND unit_code=:unit
        """), {"org": self.organization_id, "unit": unit_code}).mappings().one_or_none()
        if not row:
            raise OperationsError(f"unknown unit: {unit_code}")
        return str(row["dimension"]), Decimal(row["factor_to_base"])

    def _assert_no_cycle(self, connection: Any, formulation_id: str,
                         children: list[tuple[str, int]]) -> None:
        target = str(formulation_id)

        def visit(node: str, version: int, path: set[tuple[str, int]]) -> None:
            key = (node, version)
            if key in path or node == target:
                raise OperationsError("formulation cycle detected")
            rows = connection.execute(text("""
                SELECT child_formulation_id, child_formulation_version
                FROM formulation_components
                WHERE organization_id=:org AND formulation_id=:id AND formulation_version=:version
                  AND component_role='subrecipe'
            """), {"org": self.organization_id, "id": node, "version": version}).all()
            for child, child_version in rows:
                visit(str(child), int(child_version), path | {key})

        for child_id, child_version in children:
            visit(child_id, child_version, set())

    def add_formulation_version(self, payload: dict[str, Any]) -> dict[str, Any]:
        _required(payload, "formulation_id", "declared_yield", "yield_unit", "reason", "components")
        if not isinstance(payload["components"], list) or not payload["components"]:
            raise OperationsError("components must be a non-empty array")
        formulation_id = _uuid(payload["formulation_id"], "formulation_id")

        def operation() -> dict[str, Any]:
            with self.store.transaction(serializable=True) as connection:
                formulation = connection.execute(text("""
                    SELECT current_version FROM formulations
                    WHERE organization_id=:org AND formulation_id=:id FOR UPDATE
                """), {"org": self.organization_id, "id": formulation_id}).mappings().one_or_none()
                if formulation is None:
                    raise OperationsError("formulation not found")
                version = int(formulation["current_version"]) + 1
                yield_dimension, _ = self._unit(connection, str(payload["yield_unit"]))
                children: list[tuple[str, int]] = []
                for component in payload["components"]:
                    _required(component, "role", "quantity", "unit_code")
                    dimension, _ = self._unit(connection, str(component["unit_code"]))
                    if dimension != yield_dimension:
                        raise OperationsError(
                            f"incompatible unit dimension {dimension}; formulation yield uses {yield_dimension}"
                        )
                    role = component["role"]
                    if role == "subrecipe":
                        _required(component, "child_formulation_id", "child_formulation_version")
                        child = _uuid(component["child_formulation_id"], "child_formulation_id")
                        child_version = int(component["child_formulation_version"])
                        exists = connection.execute(text("""
                            SELECT 1 FROM formulation_versions WHERE organization_id=:org
                              AND formulation_id=:id AND version=:version
                        """), {"org": self.organization_id, "id": child,
                                "version": child_version}).scalar_one_or_none()
                        if not exists:
                            raise OperationsError("exact subrecipe version does not exist")
                        children.append((child, child_version))
                    elif role not in {"ingredient", "processing_aid", "rework"}:
                        raise OperationsError("invalid component role")
                    elif not component.get("material_id"):
                        raise OperationsError("material_id is required for material components")
                self._assert_no_cycle(connection, formulation_id, children)
                connection.execute(text("""
                    INSERT INTO formulation_versions (
                      organization_id, formulation_id, version, declared_yield, yield_unit,
                      finished_product_composition, transformation, reason, created_by
                    ) VALUES (:org, :id, :version, :yield, :unit, CAST(:finished AS jsonb),
                      CAST(:transformation AS jsonb), :reason, :principal)
                """), {"org": self.organization_id, "id": formulation_id, "version": version,
                        "yield": str(payload["declared_yield"]), "unit": str(payload["yield_unit"]),
                        "finished": _json(payload["finished_product_composition"])
                        if payload.get("finished_product_composition") is not None else None,
                        "transformation": _json(payload.get("transformation", {})),
                        "reason": str(payload["reason"]), "principal": self.principal_id})
                for sequence, component in enumerate(payload["components"], start=1):
                    role = component["role"]
                    connection.execute(text("""
                        INSERT INTO formulation_components (
                          organization_id, formulation_id, formulation_version, sequence,
                          component_role, material_id, child_formulation_id, child_formulation_version,
                          quantity, unit_code, retained_fraction, removal_claim
                        ) VALUES (:org, :id, :version, :sequence, :role, :material, :child,
                          :child_version, :quantity, :unit, :retained, CAST(:claim AS jsonb))
                    """), {"org": self.organization_id, "id": formulation_id, "version": version,
                            "sequence": sequence, "role": role,
                            "material": _uuid(component["material_id"], "material_id")
                            if role != "subrecipe" else None,
                            "child": _uuid(component["child_formulation_id"], "child_formulation_id")
                            if role == "subrecipe" else None,
                            "child_version": int(component["child_formulation_version"])
                            if role == "subrecipe" else None,
                            "quantity": str(component["quantity"]), "unit": str(component["unit_code"]),
                            "retained": component.get("retained_fraction"),
                            "claim": _json(component["removal_claim"])
                            if component.get("removal_claim") is not None else None})
                connection.execute(text("""
                    UPDATE formulations SET current_version=:version
                    WHERE organization_id=:org AND formulation_id=:id AND current_version=:previous
                """), {"org": self.organization_id, "id": formulation_id,
                        "version": version, "previous": version - 1})
                resolution = self._resolve(connection, formulation_id, version, set())
                detail = {"formulation_id": formulation_id, "version": version,
                          "resolution": resolution.__dict__}
                self._audit(connection, "formulation_version_registered", "formulation",
                            formulation_id, detail)
                return detail

        return self.store.retry_serializable(operation)

    def _resolve(self, connection: Any, formulation_id: str, version: int,
                 path: set[tuple[str, int]]) -> Resolution:
        key = (formulation_id, version)
        if key in path:
            raise OperationsError("formulation cycle detected during resolution")
        header = connection.execute(text("""
            SELECT declared_yield, yield_unit, finished_product_composition FROM formulation_versions
            WHERE organization_id=:org AND formulation_id=:id AND version=:version
        """), {"org": self.organization_id, "id": formulation_id,
                "version": version}).mappings().one_or_none()
        if header is None:
            raise OperationsError("formulation version not found")
        rows = connection.execute(text("""
            SELECT component_role, material_id, child_formulation_id, child_formulation_version,
                   quantity, unit_code, retained_fraction, removal_claim, sequence
            FROM formulation_components WHERE organization_id=:org AND formulation_id=:id
              AND formulation_version=:version ORDER BY sequence
        """), {"org": self.organization_id, "id": formulation_id,
                "version": version}).mappings().all()
        inputs: list[dict[str, Any]] = []
        unresolved: list[dict[str, Any]] = []
        visited = [f"{formulation_id}:{version}"]
        for row in rows:
            _, factor = self._unit(connection, str(row["unit_code"]))
            quantity_base = Decimal(row["quantity"]) * factor
            if row["component_role"] == "subrecipe":
                child = self._resolve(connection, str(row["child_formulation_id"]),
                                      int(row["child_formulation_version"]), path | {key})
                child_header = connection.execute(text("""
                    SELECT declared_yield, yield_unit FROM formulation_versions
                    WHERE organization_id=:org AND formulation_id=:id AND version=:version
                """), {"org": self.organization_id, "id": str(row["child_formulation_id"]),
                        "version": int(row["child_formulation_version"])}).mappings().one()
                _, child_yield_factor = self._unit(connection, str(child_header["yield_unit"]))
                child_yield_base = Decimal(child_header["declared_yield"]) * child_yield_factor
                scale = quantity_base / child_yield_base
                for item in child.input_composition:
                    scaled = dict(item)
                    scaled["input_quantity_base"] = str(Decimal(item["input_quantity_base"]) * scale)
                    scaled["finished_quantity_base"] = str(Decimal(item["finished_quantity_base"]) * scale)
                    scaled["via_subrecipe"] = f"{row['child_formulation_id']}:{row['child_formulation_version']}"
                    scaled["subrecipe_scale"] = str(scale)
                    inputs.append(scaled)
                unresolved.extend(child.unresolved_claims)
                visited.extend(child.visited_versions)
            else:
                retained = Decimal(row["retained_fraction"]) if row["retained_fraction"] is not None else Decimal("1")
                item = {"material_id": str(row["material_id"]), "role": row["component_role"],
                        "input_quantity_base": str(quantity_base),
                        "finished_quantity_base": str(quantity_base * retained),
                        "unit_dimension_base": self._unit(connection, str(row["unit_code"]))[0]}
                inputs.append(item)
                claim = row["removal_claim"]
                if claim and not (isinstance(claim, dict) and claim.get("qualified_evidence_id")
                                  and claim.get("approved") is True):
                    unresolved.append({"material_id": str(row["material_id"]),
                                       "claim": claim, "reason": "qualified approved evidence is absent"})
        return Resolution(
            state="indeterminate" if unresolved else "resolved",
            input_composition=inputs,
            finished_product_composition=header["finished_product_composition"],
            unresolved_claims=unresolved,
            visited_versions=sorted(set(visited)),
        )

    def resolve_formulation(self, formulation_id: str, version: int) -> dict[str, Any]:
        with self.store.transaction() as connection:
            resolution = self._resolve(connection, _uuid(formulation_id, "formulation_id"), int(version), set())
        return resolution.__dict__

    def create_label_text(self, payload: dict[str, Any]) -> dict[str, Any]:
        _required(payload, "label_code", "version", "language_tag", "ingredient_declaration", "full_text")
        label_id = str(uuid.uuid4())
        full_text = str(payload["full_text"])
        from hashlib import sha256
        text_sha256 = sha256(full_text.encode("utf-8")).hexdigest()
        with self.store.transaction() as connection:
            row = connection.execute(text("""
                INSERT INTO label_text_versions (
                  organization_id, label_text_id, label_code, version, language_tag,
                  ingredient_declaration, allergen_statement, full_text, text_sha256, created_by
                ) VALUES (:org, :id, :code, :version, :language, :ingredients, :allergens,
                  :full_text, :sha256, :principal)
                RETURNING label_text_id, label_code, version, language_tag, ingredient_declaration,
                  allergen_statement, text_sha256, created_at
            """), {"org": self.organization_id, "id": label_id,
                    "code": str(payload["label_code"]).strip(), "version": int(payload["version"]),
                    "language": str(payload["language_tag"]),
                    "ingredients": str(payload["ingredient_declaration"]),
                    "allergens": payload.get("allergen_statement") or None, "full_text": full_text,
                    "sha256": text_sha256, "principal": self.principal_id}).mappings().one()
            self._audit(connection, "label_text_registered", "label_text", label_id, _record(row))
        return _record(row)

    def create_printer_specification(self, payload: dict[str, Any]) -> dict[str, Any]:
        _required(payload, "specification_code")
        specification_id = str(uuid.uuid4())
        with self.store.transaction() as connection:
            row = connection.execute(text("""
                INSERT INTO printer_specifications (
                  organization_id, printer_specification_id, specification_code,
                  min_x_height_mm, min_contrast_ratio, resolution_dpi, rules
                ) VALUES (:org, :id, :code, :height, :contrast, :dpi, CAST(:rules AS jsonb))
                RETURNING printer_specification_id, specification_code, min_x_height_mm,
                  min_contrast_ratio, resolution_dpi, rules, created_at
            """), {"org": self.organization_id, "id": specification_id,
                    "code": str(payload["specification_code"]), "height": payload.get("min_x_height_mm"),
                    "contrast": payload.get("min_contrast_ratio"), "dpi": payload.get("resolution_dpi"),
                    "rules": _json(payload.get("rules", {}))}).mappings().one()
            self._audit(connection, "printer_specification_registered", "printer_specification",
                        specification_id, _record(row))
        return _record(row)

    def create_artwork(self, payload: dict[str, Any]) -> dict[str, Any]:
        _required(payload, "artwork_code", "version", "label_text_id", "artifact_id",
                  "artifact_version", "package_size", "language_tags")
        if not isinstance(payload["language_tags"], list) or not payload["language_tags"]:
            raise OperationsError("language_tags must be a non-empty array")
        artwork_id = str(uuid.uuid4())
        with self.store.transaction() as connection:
            row = connection.execute(text("""
                INSERT INTO artwork_versions (
                  organization_id, artwork_id, artwork_code, version, label_text_id,
                  artifact_id, artifact_version, package_size, language_tags,
                  printer_specification_id, width_mm, height_mm
                ) VALUES (:org, :id, :code, :version, :label, :artifact, :artifact_version,
                  :package_size, :languages, :printer, :width, :height)
                RETURNING artwork_id, artwork_code, version, label_text_id, artifact_id,
                  artifact_version, package_size, language_tags, status, created_at
            """), {"org": self.organization_id, "id": artwork_id,
                    "code": str(payload["artwork_code"]), "version": int(payload["version"]),
                    "label": _uuid(payload["label_text_id"], "label_text_id"),
                    "artifact": _uuid(payload["artifact_id"], "artifact_id"),
                    "artifact_version": int(payload["artifact_version"]),
                    "package_size": str(payload["package_size"]),
                    "languages": list(map(str, payload["language_tags"])),
                    "printer": _uuid(payload["printer_specification_id"], "printer_specification_id")
                    if payload.get("printer_specification_id") else None,
                    "width": payload.get("width_mm"), "height": payload.get("height_mm")}).mappings().one()
            self._audit(connection, "artwork_registered", "artwork", artwork_id, _record(row))
        return _record(row)

    def assess_artwork(self, payload: dict[str, Any]) -> dict[str, Any]:
        _required(payload, "artwork_id", "regions")
        if not isinstance(payload["regions"], list):
            raise OperationsError("regions must be an array")
        artwork_id = _uuid(payload["artwork_id"], "artwork_id")
        assessment_id = str(uuid.uuid4())
        with self.store.transaction() as connection:
            artwork = connection.execute(text("""
                SELECT a.label_text_id, a.printer_specification_id,
                       l.ingredient_declaration, l.allergen_statement,
                       p.min_x_height_mm, p.min_contrast_ratio
                FROM artwork_versions a
                JOIN label_text_versions l ON l.organization_id=a.organization_id
                  AND l.label_text_id=a.label_text_id
                LEFT JOIN printer_specifications p ON p.organization_id=a.organization_id
                  AND p.printer_specification_id=a.printer_specification_id
                WHERE a.organization_id=:org AND a.artwork_id=:id
            """), {"org": self.organization_id, "id": artwork_id}).mappings().one_or_none()
            if artwork is None:
                raise OperationsError("artwork not found")
            for region in payload["regions"]:
                _required(region, "region_kind", "extracted_text", "polygon")
                connection.execute(text("""
                    INSERT INTO artwork_regions (
                      organization_id, artwork_id, region_kind, extracted_text, polygon,
                      x_height_mm, contrast_ratio, emphasis, placement, confidence
                    ) VALUES (:org, :artwork, :kind, :text, CAST(:polygon AS jsonb),
                      :height, :contrast, CAST(:emphasis AS jsonb), CAST(:placement AS jsonb), :confidence)
                """), {"org": self.organization_id, "artwork": artwork_id,
                        "kind": region["region_kind"], "text": str(region["extracted_text"]),
                        "polygon": _json(region["polygon"]), "height": region.get("x_height_mm"),
                        "contrast": region.get("contrast_ratio"),
                        "emphasis": _json(region.get("emphasis", {})),
                        "placement": _json(region.get("placement", {})),
                        "confidence": region.get("confidence")})
            ingredients = " ".join(str(r["extracted_text"]) for r in payload["regions"]
                                   if r.get("region_kind") == "ingredient_declaration").strip()
            allergens = " ".join(str(r["extracted_text"]) for r in payload["regions"]
                                  if r.get("region_kind") == "allergen_statement").strip()
            expected_allergens = str(artwork["allergen_statement"] or "").strip()
            text_match = "pass" if (ingredients == str(artwork["ingredient_declaration"]).strip()
                                    and allergens == expected_allergens) else "fail"
            heights = [Decimal(str(r["x_height_mm"])) for r in payload["regions"]
                       if r.get("x_height_mm") is not None]
            contrasts = [Decimal(str(r["contrast_ratio"])) for r in payload["regions"]
                         if r.get("contrast_ratio") is not None]
            legibility = "indeterminate" if artwork["min_x_height_mm"] is None or not heights else (
                "pass" if min(heights) >= Decimal(artwork["min_x_height_mm"]) else "fail")
            contrast = "indeterminate" if artwork["min_contrast_ratio"] is None or not contrasts else (
                "pass" if min(contrasts) >= Decimal(artwork["min_contrast_ratio"]) else "fail")
            emphasis_regions = [r for r in payload["regions"] if r.get("region_kind") == "allergen_statement"]
            emphasis = "indeterminate" if not emphasis_regions else (
                "pass" if all(bool(r.get("emphasis", {}).get("distinguishable")) for r in emphasis_regions)
                else "fail")
            placement = "indeterminate" if not payload["regions"] else (
                "pass" if all(r.get("placement", {}).get("within_safe_area") is True for r in payload["regions"])
                else "fail")
            terminology = payload.get("terminology_state", "indeterminate")
            result = {"text_match_state": text_match, "terminology_state": terminology,
                      "emphasis_state": emphasis, "placement_state": placement,
                      "contrast_state": contrast, "legibility_state": legibility,
                      "text_record_pass_does_not_override_artwork": True,
                      "artwork_artifact_bound": True}
            connection.execute(text("""
                INSERT INTO artwork_assessments (
                  organization_id, artwork_assessment_id, artwork_id, terminology_state,
                  text_match_state, emphasis_state, placement_state, contrast_state,
                  legibility_state, result
                ) VALUES (:org, :id, :artwork, :terminology, :text_match, :emphasis,
                  :placement, :contrast, :legibility, CAST(:result AS jsonb))
            """), {"org": self.organization_id, "id": assessment_id, "artwork": artwork_id,
                    "terminology": terminology, "text_match": text_match, "emphasis": emphasis,
                    "placement": placement, "contrast": contrast, "legibility": legibility,
                    "result": _json(result)})
            self._audit(connection, "artwork_assessed", "artwork_assessment", assessment_id, result)
        return {"artwork_assessment_id": assessment_id, **result}

    def create_line(self, payload: dict[str, Any]) -> dict[str, Any]:
        _required(payload, "facility_id", "line_code", "name")
        line_id = str(uuid.uuid4())
        with self.store.transaction() as connection:
            row = connection.execute(text("""
                INSERT INTO production_lines (organization_id, line_id, facility_id, line_code, name)
                VALUES (:org, :id, :facility, :code, :name)
                RETURNING line_id, facility_id, line_code, name, created_at
            """), {"org": self.organization_id, "id": line_id,
                    "facility": _uuid(payload["facility_id"], "facility_id"),
                    "code": str(payload["line_code"]), "name": str(payload["name"])}).mappings().one()
            self._audit(connection, "production_line_registered", "production_line", line_id, _record(row))
        return _record(row)

    def create_equipment(self, payload: dict[str, Any]) -> dict[str, Any]:
        _required(payload, "line_id", "equipment_code", "name")
        equipment_id = str(uuid.uuid4())
        with self.store.transaction() as connection:
            row = connection.execute(text("""
                INSERT INTO equipment (
                  organization_id, equipment_id, line_id, equipment_code, name,
                  shared, allergen_retention_features
                ) VALUES (:org, :id, :line, :code, :name, :shared, CAST(:features AS jsonb))
                RETURNING equipment_id, line_id, equipment_code, name, shared,
                  allergen_retention_features, created_at
            """), {"org": self.organization_id, "id": equipment_id,
                    "line": _uuid(payload["line_id"], "line_id"),
                    "code": str(payload["equipment_code"]), "name": str(payload["name"]),
                    "shared": bool(payload.get("shared", False)),
                    "features": _json(payload.get("allergen_retention_features", {}))}).mappings().one()
            self._audit(connection, "equipment_registered", "equipment", equipment_id, _record(row))
        return _record(row)

    def create_packaging_lot(self, payload: dict[str, Any]) -> dict[str, Any]:
        _required(payload, "lot_code", "artwork_id")
        lot_id = str(uuid.uuid4())
        with self.store.transaction() as connection:
            row = connection.execute(text("""
                INSERT INTO packaging_lots (organization_id, packaging_lot_id, lot_code, artwork_id, received_at)
                VALUES (:org, :id, :code, :artwork, :received)
                RETURNING packaging_lot_id, lot_code, artwork_id, received_at, created_at
            """), {"org": self.organization_id, "id": lot_id, "code": str(payload["lot_code"]),
                    "artwork": _uuid(payload["artwork_id"], "artwork_id"),
                    "received": payload.get("received_at") or None}).mappings().one()
            self._audit(connection, "packaging_lot_registered", "packaging_lot", lot_id, _record(row))
        return _record(row)

    def create_batch(self, payload: dict[str, Any]) -> dict[str, Any]:
        _required(payload, "batch_code", "facility_id", "line_id", "formulation_id",
                  "formulation_version", "started_at", "actual_material_record_state")
        if payload["actual_material_record_state"] not in {"complete", "partial", "missing"}:
            raise OperationsError("invalid actual_material_record_state")
        batch_id = str(uuid.uuid4())
        with self.store.transaction() as connection:
            row = connection.execute(text("""
                INSERT INTO manufacturing_batches (
                  organization_id, batch_id, batch_code, facility_id, line_id,
                  formulation_id, formulation_version, started_at, completed_at,
                  actual_material_record_state, state
                ) VALUES (:org, :id, :code, :facility, :line, :formulation, :version,
                  :started, :completed, :actual_state, :state)
                RETURNING batch_id, batch_code, facility_id, line_id, formulation_id,
                  formulation_version, started_at, completed_at, actual_material_record_state, state, created_at
            """), {"org": self.organization_id, "id": batch_id, "code": str(payload["batch_code"]),
                    "facility": _uuid(payload["facility_id"], "facility_id"),
                    "line": _uuid(payload["line_id"], "line_id"),
                    "formulation": _uuid(payload["formulation_id"], "formulation_id"),
                    "version": int(payload["formulation_version"]), "started": payload["started_at"],
                    "completed": payload.get("completed_at") or None,
                    "actual_state": payload["actual_material_record_state"],
                    "state": payload.get("state", "planned")}).mappings().one()
            for item in payload.get("materials", []):
                _required(item, "material_id", "quantity", "unit_code", "consumption_kind")
                connection.execute(text("""
                    INSERT INTO batch_material_consumptions (
                      organization_id, batch_id, material_id, supplier_lot_id, receipt_id,
                      quantity, unit_code, consumption_kind
                    ) VALUES (:org, :batch, :material, :lot, :receipt, :quantity, :unit, :kind)
                """), {"org": self.organization_id, "batch": batch_id,
                        "material": _uuid(item["material_id"], "material_id"),
                        "lot": _uuid(item["supplier_lot_id"], "supplier_lot_id") if item.get("supplier_lot_id") else None,
                        "receipt": _uuid(item["receipt_id"], "receipt_id") if item.get("receipt_id") else None,
                        "quantity": str(item["quantity"]), "unit": str(item["unit_code"]),
                        "kind": item["consumption_kind"]})
            for item in payload.get("packaging", []):
                _required(item, "packaging_lot_id", "usage_state")
                connection.execute(text("""
                    INSERT INTO batch_packaging_usage
                      (organization_id, batch_id, packaging_lot_id, usage_state)
                    VALUES (:org, :batch, :lot, :state)
                """), {"org": self.organization_id, "batch": batch_id,
                        "lot": _uuid(item["packaging_lot_id"], "packaging_lot_id"),
                        "state": item["usage_state"]})
            reconciliation = self._reconcile_batch(connection, batch_id)
            self._audit(connection, "manufacturing_batch_recorded", "manufacturing_batch",
                        batch_id, {"batch": _record(row), "reconciliation": reconciliation})
        return {**_record(row), "reconciliation": reconciliation}

    def _reconcile_batch(self, connection: Any, batch_id: str) -> dict[str, Any]:
        batch = connection.execute(text("""
            SELECT actual_material_record_state FROM manufacturing_batches
            WHERE organization_id=:org AND batch_id=:id
        """), {"org": self.organization_id, "id": batch_id}).mappings().one()
        materials = connection.execute(text("""
            SELECT material_id, consumption_kind, quantity, unit_code FROM batch_material_consumptions
            WHERE organization_id=:org AND batch_id=:id
        """), {"org": self.organization_id, "id": batch_id}).mappings().all()
        planned = {str(r["material_id"]) for r in materials if r["consumption_kind"] == "planned"}
        actual = {str(r["material_id"]) for r in materials if r["consumption_kind"] in {"actual", "rework"}}
        packaging = connection.execute(text("""
            SELECT p.usage_state, l.artwork_id, p.packaging_lot_id
            FROM batch_packaging_usage p JOIN packaging_lots l
              ON l.organization_id=p.organization_id AND l.packaging_lot_id=p.packaging_lot_id
            WHERE p.organization_id=:org AND p.batch_id=:id
        """), {"org": self.organization_id, "id": batch_id}).mappings().all()
        planned_art = {str(r["artwork_id"]) for r in packaging if r["usage_state"] == "planned"}
        actual_art = {str(r["artwork_id"]) for r in packaging if r["usage_state"] == "actual"}
        missing = str(batch["actual_material_record_state"]) != "complete"
        substitutions = sorted(actual - planned) if not missing else []
        omissions = sorted(planned - actual) if not missing else []
        packaging_mismatch = bool(actual_art and planned_art and actual_art != planned_art)
        state = "indeterminate" if missing else (
            "failed" if substitutions or omissions or packaging_mismatch else "matched")
        return {"state": state, "formula_approval_is_not_batch_proof": True,
                "substituted_material_ids": substitutions, "missing_material_ids": omissions,
                "packaging_mismatch": packaging_mismatch,
                "planned_artwork_ids": sorted(planned_art), "actual_artwork_ids": sorted(actual_art)}

    def reconcile_batch(self, batch_id: str) -> dict[str, Any]:
        with self.store.transaction() as connection:
            return self._reconcile_batch(connection, _uuid(batch_id, "batch_id"))

    def create_camera_qualification(self, payload: dict[str, Any]) -> dict[str, Any]:
        _required(payload, "camera_identifier", "workflow_version", "valid_from", "valid_until")
        qualification_id = str(uuid.uuid4())
        with self.store.transaction() as connection:
            row = connection.execute(text("""
                INSERT INTO camera_qualifications (
                  organization_id, camera_qualification_id, camera_identifier, workflow_version,
                  valid_from, valid_until, approved_by
                ) VALUES (:org, :id, :camera, :workflow, :from, :until, :principal)
                RETURNING camera_qualification_id, camera_identifier, workflow_version,
                  valid_from, valid_until, approved_by, created_at
            """), {"org": self.organization_id, "id": qualification_id,
                    "camera": str(payload["camera_identifier"]), "workflow": str(payload["workflow_version"]),
                    "from": payload["valid_from"], "until": payload["valid_until"],
                    "principal": self.principal_id}).mappings().one()
            self._audit(connection, "camera_qualification_registered", "camera_qualification",
                        qualification_id, _record(row))
        return _record(row)

    def create_sampling_plan(self, payload: dict[str, Any]) -> dict[str, Any]:
        _required(payload, "plan_code", "plan_version", "sample_size", "inference_scope", "acceptance_policy")
        if payload["inference_scope"] not in {"sample_only", "batch"}:
            raise OperationsError("invalid inference_scope")
        if payload["inference_scope"] == "batch" and not payload.get("approved", False):
            raise OperationsError("batch inference requires explicit approval")
        plan_id = str(uuid.uuid4())
        with self.store.transaction() as connection:
            row = connection.execute(text("""
                INSERT INTO sampling_plans (
                  organization_id, sampling_plan_id, plan_code, plan_version,
                  sample_size, inference_scope, acceptance_policy, approved_by
                ) VALUES (:org, :id, :code, :version, :size, :scope,
                  CAST(:policy AS jsonb), :approved)
                RETURNING sampling_plan_id, plan_code, plan_version, sample_size,
                  inference_scope, acceptance_policy, approved_by, created_at
            """), {"org": self.organization_id, "id": plan_id, "code": str(payload["plan_code"]),
                    "version": int(payload["plan_version"]), "size": int(payload["sample_size"]),
                    "scope": payload["inference_scope"], "policy": _json(payload["acceptance_policy"]),
                    "approved": self.principal_id if payload.get("approved", False) else None}).mappings().one()
            self._audit(connection, "sampling_plan_registered", "sampling_plan", plan_id, _record(row))
        return _record(row)

    def create_inspection(self, payload: dict[str, Any]) -> dict[str, Any]:
        required = ("sample_code", "batch_id", "packaging_lot_id", "camera_qualification_id",
                    "sampling_plan_id", "source_artifact_id", "source_artifact_version", "line_id",
                    "captured_at", "product_identity_state", "package_identity_state",
                    "artwork_match_state", "ocr_state", "legibility_state", "emphasis_state", "result")
        _required(payload, *required)
        inspection_id = str(uuid.uuid4())
        with self.store.transaction() as connection:
            plan = connection.execute(text("""
                SELECT inference_scope FROM sampling_plans
                WHERE organization_id=:org AND sampling_plan_id=:id
            """), {"org": self.organization_id,
                    "id": _uuid(payload["sampling_plan_id"], "sampling_plan_id")}).scalar_one_or_none()
            if plan is None:
                raise OperationsError("sampling plan not found")
            requested_scope = payload.get("conclusion_scope", "sample_only")
            if requested_scope == "batch" and plan != "batch":
                raise OperationsError("inspection conclusion cannot exceed sampling-plan scope")
            camera_valid = connection.execute(text("""
                SELECT 1 FROM camera_qualifications WHERE organization_id=:org
                  AND camera_qualification_id=:id AND :captured >= valid_from AND :captured <= valid_until
            """), {"org": self.organization_id,
                    "id": _uuid(payload["camera_qualification_id"], "camera_qualification_id"),
                    "captured": payload["captured_at"]}).scalar_one_or_none()
            if not camera_valid:
                raise OperationsError("camera qualification is not valid at capture time")
            row = connection.execute(text("""
                INSERT INTO physical_package_inspections (
                  organization_id, inspection_id, sample_code, batch_id, packaging_lot_id,
                  camera_qualification_id, sampling_plan_id, source_artifact_id,
                  source_artifact_version, line_id, captured_at, product_identity_state,
                  package_identity_state, artwork_match_state, ocr_state, legibility_state,
                  emphasis_state, result, conclusion_scope
                ) VALUES (:org, :id, :sample, :batch, :packaging, :camera, :plan, :artifact,
                  :artifact_version, :line, :captured, :product_state, :package_state,
                  :artwork_state, :ocr_state, :legibility, :emphasis, CAST(:result AS jsonb), :scope)
                RETURNING inspection_id, sample_code, batch_id, artwork_match_state, ocr_state,
                  legibility_state, emphasis_state, conclusion_scope, result, created_at
            """), {"org": self.organization_id, "id": inspection_id,
                    "sample": str(payload["sample_code"]), "batch": _uuid(payload["batch_id"], "batch_id"),
                    "packaging": _uuid(payload["packaging_lot_id"], "packaging_lot_id"),
                    "camera": _uuid(payload["camera_qualification_id"], "camera_qualification_id"),
                    "plan": _uuid(payload["sampling_plan_id"], "sampling_plan_id"),
                    "artifact": _uuid(payload["source_artifact_id"], "source_artifact_id"),
                    "artifact_version": int(payload["source_artifact_version"]),
                    "line": _uuid(payload["line_id"], "line_id"), "captured": payload["captured_at"],
                    "product_state": payload["product_identity_state"],
                    "package_state": payload["package_identity_state"],
                    "artwork_state": payload["artwork_match_state"], "ocr_state": payload["ocr_state"],
                    "legibility": payload["legibility_state"], "emphasis": payload["emphasis_state"],
                    "result": _json(payload["result"]), "scope": requested_scope}).mappings().one()
            self._audit(connection, "physical_package_inspected", "physical_package_inspection",
                        inspection_id, _record(row))
        return _record(row)

    def create_cleaning_event(self, payload: dict[str, Any]) -> dict[str, Any]:
        _required(payload, "line_id", "equipment_ids", "procedure_version", "started_at",
                  "completed_at", "verification_state", "verification_evidence")
        if payload["verification_state"] not in {"passed", "failed", "indeterminate"}:
            raise OperationsError("invalid verification_state")
        event_id = str(uuid.uuid4())
        equipment_ids = [_uuid(value, "equipment_id") for value in payload["equipment_ids"]]
        with self.store.transaction() as connection:
            row = connection.execute(text("""
                INSERT INTO cleaning_events (
                  organization_id, cleaning_event_id, line_id, equipment_ids, procedure_version,
                  started_at, completed_at, verification_state, verification_evidence
                ) VALUES (:org, :id, :line, :equipment, :procedure, :started, :completed,
                  :state, CAST(:evidence AS jsonb))
                RETURNING cleaning_event_id, line_id, equipment_ids, procedure_version,
                  started_at, completed_at, verification_state, verification_evidence, created_at
            """), {"org": self.organization_id, "id": event_id,
                    "line": _uuid(payload["line_id"], "line_id"), "equipment": equipment_ids,
                    "procedure": str(payload["procedure_version"]), "started": payload["started_at"],
                    "completed": payload["completed_at"], "state": payload["verification_state"],
                    "evidence": _json(payload["verification_evidence"])}).mappings().one()
            self._audit(connection, "cleaning_event_recorded", "cleaning_event", event_id, _record(row))
        return _record(row)

    def create_cross_contact_assessment(self, payload: dict[str, Any]) -> dict[str, Any]:
        _required(payload, "batch_id", "line_id", "recipe_origin_allergens",
                  "unintended_hazards", "controls")
        assessment_id = str(uuid.uuid4())
        with self.store.transaction() as connection:
            snapshot: dict[str, Any] = {
                "batch_id": _uuid(payload["batch_id"], "batch_id"),
                "previous_batch_id": _uuid(payload["previous_batch_id"], "previous_batch_id")
                if payload.get("previous_batch_id") else None,
                "line_id": _uuid(payload["line_id"], "line_id"),
                "recipe_origin_allergens": sorted(set(map(str, payload["recipe_origin_allergens"]))),
                "unintended_hazards": sorted(set(map(str, payload["unintended_hazards"]))),
                "controls": payload["controls"],
            }
            cleaning_id = _uuid(payload["cleaning_event_id"], "cleaning_event_id") \
                if payload.get("cleaning_event_id") else None
            cleaning = None
            if cleaning_id:
                cleaning_row = connection.execute(text("""
                    SELECT cleaning_event_id, line_id, equipment_ids, procedure_version,
                           started_at, completed_at, verification_state, verification_evidence
                    FROM cleaning_events WHERE organization_id=:org AND cleaning_event_id=:id
                """), {"org": self.organization_id, "id": cleaning_id}).mappings().one_or_none()
                if cleaning_row is None:
                    raise OperationsError("cleaning event not found")
                cleaning = _record(cleaning_row)
                if str(cleaning_row["line_id"]) != snapshot["line_id"]:
                    raise OperationsError("cleaning event belongs to another line")
            snapshot["cleaning_event"] = cleaning
            evidence_sha256 = digest(snapshot)
            if snapshot["unintended_hazards"] and not cleaning:
                state = "indeterminate"
            elif cleaning and cleaning["verification_state"] == "failed":
                state = "failed"
            elif cleaning and cleaning["verification_state"] == "indeterminate":
                state = "indeterminate"
            elif snapshot["unintended_hazards"] and not payload["controls"]:
                state = "indeterminate"
            else:
                state = "supported"
            row = connection.execute(text("""
                INSERT INTO cross_contact_assessments (
                  organization_id, cross_contact_assessment_id, batch_id, previous_batch_id,
                  line_id, cleaning_event_id, recipe_origin_allergens, unintended_hazards,
                  controls, evidence_snapshot, evidence_sha256, state
                ) VALUES (:org, :id, :batch, :previous, :line, :cleaning, :recipe, :hazards,
                  CAST(:controls AS jsonb), CAST(:snapshot AS jsonb), :sha256, :state)
                RETURNING cross_contact_assessment_id, batch_id, previous_batch_id, line_id,
                  recipe_origin_allergens, unintended_hazards, state, evidence_sha256, created_at
            """), {"org": self.organization_id, "id": assessment_id,
                    "batch": snapshot["batch_id"], "previous": snapshot["previous_batch_id"],
                    "line": snapshot["line_id"], "cleaning": cleaning_id,
                    "recipe": snapshot["recipe_origin_allergens"], "hazards": snapshot["unintended_hazards"],
                    "controls": _json(payload["controls"]), "snapshot": _json(snapshot),
                    "sha256": evidence_sha256, "state": state}).mappings().one()
            self._audit(connection, "cross_contact_assessed", "cross_contact_assessment",
                        assessment_id, {"record": _record(row), "evidence_snapshot": snapshot})
        return {**_record(row), "evidence_snapshot": snapshot,
                "recipe_and_unintended_allergens_separated": True}

