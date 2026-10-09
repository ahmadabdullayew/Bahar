"""F46 mandatory deny-by-default action/role matrix.

No role, actor or tenant selection may be taken from HTTP request bodies.
Production callers must first construct a per-user verified TenantContext;
this module verifies DB memberships, not an upstream identity proof.
"""
from __future__ import annotations
from typing import Any
from .persistence import PostgresBaharStore
from .store import StoreError

OPERATION_ACTION_ROLES = {
    'supplier_registered':'analyst','material_registered':'analyst',
    'supplier_material_identifier_registered':'analyst',
    'material_specification_registered':'analyst','supplier_lot_registered':'analyst',
    'material_receipt_registered':'analyst','origin_finding_recorded':'reviewer',
    'supplier_correction_recorded':'reviewer','formulation_registered':'analyst',
    'formulation_version_registered':'analyst','label_text_registered':'analyst',
    'printer_specification_registered':'analyst','artwork_registered':'analyst',
    'artwork_assessed':'reviewer','production_line_registered':'analyst',
    'equipment_registered':'analyst','packaging_lot_registered':'analyst',
    'manufacturing_batch_recorded':'analyst','camera_qualification_registered':'reviewer',
    'sampling_plan_registered':'reviewer','physical_package_inspected':'reviewer',
    'cleaning_event_recorded':'reviewer','cross_contact_assessed':'reviewer',
}


def authorize_operational_action(store: Any, connection: Any, action: str) -> str:
    if action not in OPERATION_ACTION_ROLES:
        raise StoreError(f'undefined operational action denied: {action}')
    if isinstance(store,PostgresBaharStore):
        store._require_role(connection,OPERATION_ACTION_ROLES[action])
        return str(store.context.principal_id)
    return 'LOCAL_DEMONSTRATION_ONLY'
