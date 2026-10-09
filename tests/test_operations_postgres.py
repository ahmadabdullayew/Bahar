from __future__ import annotations

import os
import uuid
from decimal import Decimal

import pytest
from sqlalchemy import text

from bahar.operations import OperationsError, OperationsService
from bahar.persistence import PostgresBaharStore, TenantContext


DATABASE_URL = os.environ.get("BAHAR_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not DATABASE_URL, reason="BAHAR_TEST_DATABASE_URL is not configured")
ORG_ID = uuid.UUID("00000000-0000-4000-8000-000000000001")
PRINCIPAL_ID = uuid.UUID("00000000-0000-4000-8000-000000000001")


@pytest.fixture
def operations() -> OperationsService:
    store = PostgresBaharStore(
        str(DATABASE_URL), TenantContext(ORG_ID, PRINCIPAL_ID, "operations-integration-test"),
        b"integration-test-audit-key-material-32-bytes",
    )
    service = OperationsService(store)
    service.ensure_local_reference_data()
    try:
        yield service
    finally:
        store.close()


def unique(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


def material(operations: OperationsService, name: str = "Test material") -> dict[str, object]:
    return operations.create_material({
        "material_code": unique("MAT"), "name": name, "material_kind": "ingredient",
    })


def formulation_version(operations: OperationsService, material_id: str) -> tuple[dict[str, object], dict[str, object]]:
    formulation = operations.create_formulation({"formulation_code": unique("FORM"), "name": "Test formula"})
    version = operations.add_formulation_version({
        "formulation_id": formulation["formulation_id"], "declared_yield": 10,
        "yield_unit": "kg", "reason": "test fixture",
        "components": [{"role": "ingredient", "material_id": material_id,
                        "quantity": 10, "unit_code": "kg"}],
    })
    return formulation, version


def line(operations: OperationsService) -> dict[str, object]:
    facility_id = str(uuid.uuid5(ORG_ID, "facility:LOCAL"))
    return operations.create_line({
        "facility_id": facility_id, "line_code": unique("LINE"), "name": "Test line",
    })


def seed_artifact(operations: OperationsService) -> tuple[str, int]:
    artifact_id = str(uuid.uuid4())
    object_key = unique("test-artifact")
    with operations.store.transaction() as connection:
        connection.execute(text("""
            INSERT INTO artifacts (
              organization_id, artifact_id, artifact_type, document_identity,
              declared_version, document_scope, state, current_version, created_by
            ) VALUES (:org, :id, 'test_fixture', :identity, '1', '{}'::jsonb,
              'active', 1, :principal)
        """), {"org": operations.organization_id, "id": artifact_id,
                "identity": object_key, "principal": operations.principal_id})
        connection.execute(text("""
            INSERT INTO artifact_versions (
              organization_id, artifact_id, version, storage_class, bucket_name,
              object_key, provider_version_id, byte_length, sha256, claimed_media_type,
              detected_media_type, encryption_method, encryption_key_id,
              retention_class, signature_state, custody_state
            ) VALUES (:org, :id, 1, 'governed', 'integration-test', :key, :provider,
              0, :sha, 'image/png', 'image/png', 'test-only', 'test-only',
              'regulatory-evidence', 'not_evaluated', 'governed_available')
        """), {"org": operations.organization_id, "id": artifact_id, "key": object_key,
                "provider": str(uuid.uuid4()), "sha": "0" * 64})
    return artifact_id, 1


def test_supplier_correction_finds_receipt_without_rewriting_history(operations: OperationsService) -> None:
    supplier = operations.create_supplier({"supplier_code": unique("SUP"), "legal_name": "Supplier"})
    purchased = material(operations)
    operations.create_supplier_identifier({
        "supplier_id": supplier["supplier_id"], "material_id": purchased["material_id"],
        "supplier_identifier": unique("SKU"), "valid_from": "2026-01-01",
    })
    specification = operations.create_specification({
        "supplier_id": supplier["supplier_id"], "material_id": purchased["material_id"],
        "specification_code": unique("SPEC"), "specification_version": "1",
        "valid_from": "2026-01-01", "declared_origin": {"country": "AZ"},
    })
    lot = operations.create_lot({
        "supplier_id": supplier["supplier_id"], "material_id": purchased["material_id"],
        "lot_code": unique("LOT"),
    })
    receipt = operations.create_receipt({
        "receipt_code": unique("RCV"), "supplier_lot_id": lot["supplier_lot_id"],
        "received_at": "2026-10-09T08:00:00Z", "quantity": 20, "unit_code": "kg",
        "bound_specification_id": specification["specification_id"],
        "specification_binding_reason": "effective specification verified at receipt",
    })
    correction = operations.create_supplier_correction({
        "specification_id": specification["specification_id"], "correction_kind": "clarification",
        "correction": {"origin": "clarified"}, "effective_at": "2026-10-09T09:00:00Z",
    })
    assert correction["history_rewritten"] is False
    assert [item["receipt_id"] for item in correction["affected_receipts"]] == [receipt["receipt_id"]]
    stored = next(item for item in operations.list_records("receipts") if item["receipt_id"] == receipt["receipt_id"])
    assert stored["bound_specification_id"] == specification["specification_id"]


def test_nested_formulations_scale_and_reject_cycles_and_incompatible_units(
    operations: OperationsService,
) -> None:
    first = material(operations, "First")
    second = material(operations, "Second")
    child, _ = formulation_version(operations, str(first["material_id"]))
    parent = operations.create_formulation({"formulation_code": unique("PARENT"), "name": "Parent"})
    resolved = operations.add_formulation_version({
        "formulation_id": parent["formulation_id"], "declared_yield": 20,
        "yield_unit": "kg", "reason": "nested fixture", "components": [
            {"role": "subrecipe", "child_formulation_id": child["formulation_id"],
             "child_formulation_version": 1, "quantity": 5, "unit_code": "kg"},
            {"role": "ingredient", "material_id": second["material_id"],
             "quantity": 15, "unit_code": "kg"},
        ],
    })
    assert Decimal(resolved["resolution"]["input_composition"][0]["input_quantity_base"]) == 5000
    with pytest.raises(OperationsError, match="cycle"):
        operations.add_formulation_version({
            "formulation_id": child["formulation_id"], "declared_yield": 10,
            "yield_unit": "kg", "reason": "cycle", "components": [{
                "role": "subrecipe", "child_formulation_id": parent["formulation_id"],
                "child_formulation_version": 1, "quantity": 10, "unit_code": "kg",
            }],
        })
    with pytest.raises(OperationsError, match="incompatible"):
        operations.add_formulation_version({
            "formulation_id": parent["formulation_id"], "declared_yield": 1,
            "yield_unit": "kg", "reason": "bad dimension", "components": [{
                "role": "ingredient", "material_id": first["material_id"],
                "quantity": 1, "unit_code": "l",
            }],
        })


def test_artwork_text_and_rendered_properties_are_independent(operations: OperationsService) -> None:
    artifact_id, artifact_version = seed_artifact(operations)
    label = operations.create_label_text({
        "label_code": unique("LABEL"), "version": 1, "language_tag": "az",
        "ingredient_declaration": "Tərkibi: küncüt", "allergen_statement": "Allergen: küncüt",
        "full_text": "Tərkibi: küncüt. Allergen: küncüt",
    })
    printer = operations.create_printer_specification({
        "specification_code": unique("PRINT"), "min_x_height_mm": 1.2,
        "min_contrast_ratio": 4.5, "resolution_dpi": 300,
    })
    artwork = operations.create_artwork({
        "artwork_code": unique("ART"), "version": 1, "label_text_id": label["label_text_id"],
        "artifact_id": artifact_id, "artifact_version": artifact_version,
        "package_size": "500 g", "language_tags": ["az"],
        "printer_specification_id": printer["printer_specification_id"],
    })
    assessment = operations.assess_artwork({
        "artwork_id": artwork["artwork_id"], "terminology_state": "pass", "regions": [
            {"region_kind": "ingredient_declaration", "extracted_text": "Tərkibi: küncüt",
             "polygon": [[0, 0], [1, 0], [1, 1]], "x_height_mm": 0.8,
             "contrast_ratio": 3, "placement": {"within_safe_area": True}, "confidence": 0.99},
            {"region_kind": "allergen_statement", "extracted_text": "Allergen: küncüt",
             "polygon": [[0, 2], [1, 2], [1, 3]], "x_height_mm": 0.8,
             "contrast_ratio": 3, "placement": {"within_safe_area": True},
             "emphasis": {"distinguishable": False}, "confidence": 0.99},
        ],
    })
    assert assessment["text_match_state"] == "pass"
    assert assessment["legibility_state"] == "fail"
    assert assessment["contrast_state"] == "fail"
    assert assessment["emphasis_state"] == "fail"
    assert assessment["text_record_pass_does_not_override_artwork"] is True


def test_batch_substitution_and_cross_contact_snapshot(operations: OperationsService) -> None:
    planned = material(operations, "Planned")
    substitute = material(operations, "Substitute")
    formulation, _ = formulation_version(operations, str(planned["material_id"]))
    production_line = line(operations)
    batch = operations.create_batch({
        "batch_code": unique("BATCH"), "facility_id": str(uuid.uuid5(ORG_ID, "facility:LOCAL")),
        "line_id": production_line["line_id"], "formulation_id": formulation["formulation_id"],
        "formulation_version": 1, "started_at": "2026-10-09T08:00:00Z",
        "actual_material_record_state": "complete", "state": "completed", "materials": [
            {"material_id": planned["material_id"], "quantity": 10,
             "unit_code": "kg", "consumption_kind": "planned"},
            {"material_id": substitute["material_id"], "quantity": 10,
             "unit_code": "kg", "consumption_kind": "actual"},
        ],
    })
    assert batch["reconciliation"]["state"] == "failed"
    assert batch["reconciliation"]["formula_approval_is_not_batch_proof"] is True
    cleaning = operations.create_cleaning_event({
        "line_id": production_line["line_id"], "equipment_ids": [],
        "procedure_version": "CLEAN-1", "started_at": "2026-10-09T06:00:00Z",
        "completed_at": "2026-10-09T07:00:00Z", "verification_state": "passed",
        "verification_evidence": {"method": "validated swab", "record": unique("SWAB")},
    })
    cross_contact = operations.create_cross_contact_assessment({
        "batch_id": batch["batch_id"], "line_id": production_line["line_id"],
        "cleaning_event_id": cleaning["cleaning_event_id"],
        "recipe_origin_allergens": ["wheat"], "unintended_hazards": ["sesame"],
        "controls": {"verified_cleaning": True},
    })
    assert cross_contact["state"] == "supported"
    assert cross_contact["recipe_and_unintended_allergens_separated"] is True
    assert cross_contact["evidence_sha256"]


def test_physical_inspection_cannot_exceed_sampling_scope(operations: OperationsService) -> None:
    artifact_id, artifact_version = seed_artifact(operations)
    purchased = material(operations, "Package inspection material")
    formulation, _ = formulation_version(operations, str(purchased["material_id"]))
    production_line = line(operations)
    label = operations.create_label_text({
        "label_code": unique("LABEL"), "version": 1, "language_tag": "az",
        "ingredient_declaration": "Tərkibi: buğda", "allergen_statement": "Allergen: buğda",
        "full_text": "Tərkibi: buğda. Allergen: buğda",
    })
    artwork = operations.create_artwork({
        "artwork_code": unique("ART"), "version": 1, "label_text_id": label["label_text_id"],
        "artifact_id": artifact_id, "artifact_version": artifact_version,
        "package_size": "500 g", "language_tags": ["az"],
    })
    packaging = operations.create_packaging_lot({
        "lot_code": unique("PKG"), "artwork_id": artwork["artwork_id"],
        "received_at": "2026-10-09T07:00:00Z",
    })
    batch = operations.create_batch({
        "batch_code": unique("INSPECT"), "facility_id": str(uuid.uuid5(ORG_ID, "facility:LOCAL")),
        "line_id": production_line["line_id"], "formulation_id": formulation["formulation_id"],
        "formulation_version": 1, "started_at": "2026-10-09T08:00:00Z",
        "actual_material_record_state": "complete", "state": "completed",
        "materials": [], "packaging": [
            {"packaging_lot_id": packaging["packaging_lot_id"], "usage_state": "planned"},
            {"packaging_lot_id": packaging["packaging_lot_id"], "usage_state": "actual"},
        ],
    })
    camera = operations.create_camera_qualification({
        "camera_identifier": unique("CAM"), "workflow_version": "1",
        "valid_from": "2026-01-01T00:00:00Z", "valid_until": "2027-01-01T00:00:00Z",
    })
    plan = operations.create_sampling_plan({
        "plan_code": unique("PLAN"), "plan_version": 1, "sample_size": 3,
        "inference_scope": "sample_only", "acceptance_policy": {"defects_allowed": 0},
    })
    payload = {
        "sample_code": unique("SAMPLE"), "batch_id": batch["batch_id"],
        "packaging_lot_id": packaging["packaging_lot_id"],
        "camera_qualification_id": camera["camera_qualification_id"],
        "sampling_plan_id": plan["sampling_plan_id"], "source_artifact_id": artifact_id,
        "source_artifact_version": artifact_version, "line_id": production_line["line_id"],
        "captured_at": "2026-10-09T10:00:00Z", "product_identity_state": "matched",
        "package_identity_state": "matched", "artwork_match_state": "matched",
        "ocr_state": "passed", "legibility_state": "passed", "emphasis_state": "passed",
        "result": {"observed_artwork_id": artwork["artwork_id"]},
    }
    with pytest.raises(OperationsError, match="cannot exceed"):
        operations.create_inspection({**payload, "conclusion_scope": "batch"})
    inspection = operations.create_inspection({**payload, "conclusion_scope": "sample_only"})
    assert inspection["conclusion_scope"] == "sample_only"

