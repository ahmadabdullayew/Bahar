"""Supplier lots, formulations, artwork, package inspection, batches, and cross-contact."""

from __future__ import annotations

from alembic import op


revision = "0002_supply_chain_operations"
down_revision = "0001_production_foundation"
branch_labels = None
depends_on = None


DDL = r"""
CREATE TABLE suppliers (
  organization_id uuid NOT NULL REFERENCES organizations(organization_id),
  supplier_id uuid NOT NULL DEFAULT gen_random_uuid(),
  supplier_code text NOT NULL,
  legal_name text NOT NULL,
  status lifecycle_state NOT NULL DEFAULT 'active',
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (organization_id, supplier_id),
  UNIQUE (organization_id, supplier_code)
);

CREATE TABLE purchased_materials (
  organization_id uuid NOT NULL REFERENCES organizations(organization_id),
  material_id uuid NOT NULL DEFAULT gen_random_uuid(),
  material_code text NOT NULL,
  name text NOT NULL,
  material_kind text NOT NULL CHECK (material_kind IN ('ingredient','processing_aid','packaging','rework_carrier')),
  status lifecycle_state NOT NULL DEFAULT 'active',
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (organization_id, material_id),
  UNIQUE (organization_id, material_code)
);

CREATE TABLE supplier_material_identifiers (
  organization_id uuid NOT NULL,
  supplier_id uuid NOT NULL,
  material_id uuid NOT NULL,
  supplier_identifier text NOT NULL,
  valid_from date NOT NULL,
  valid_until date,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (organization_id, supplier_id, supplier_identifier, valid_from),
  FOREIGN KEY (organization_id, supplier_id) REFERENCES suppliers(organization_id, supplier_id),
  FOREIGN KEY (organization_id, material_id) REFERENCES purchased_materials(organization_id, material_id),
  CHECK (valid_until IS NULL OR valid_until > valid_from)
);

CREATE TABLE material_specifications (
  organization_id uuid NOT NULL,
  specification_id uuid NOT NULL DEFAULT gen_random_uuid(),
  supplier_id uuid NOT NULL,
  material_id uuid NOT NULL,
  specification_code text NOT NULL,
  specification_version text NOT NULL,
  valid_from date NOT NULL,
  valid_until date,
  retracted_at timestamptz,
  retraction_reason text,
  declared_origin jsonb NOT NULL DEFAULT '{}'::jsonb,
  accepted_origin jsonb,
  source_artifact_id uuid,
  source_artifact_version bigint,
  replaces_specification_id uuid,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (organization_id, specification_id),
  UNIQUE (organization_id, supplier_id, specification_code, specification_version),
  FOREIGN KEY (organization_id, supplier_id) REFERENCES suppliers(organization_id, supplier_id),
  FOREIGN KEY (organization_id, material_id) REFERENCES purchased_materials(organization_id, material_id),
  FOREIGN KEY (organization_id, source_artifact_id, source_artifact_version)
    REFERENCES artifact_versions(organization_id, artifact_id, version),
  FOREIGN KEY (organization_id, replaces_specification_id)
    REFERENCES material_specifications(organization_id, specification_id),
  CHECK (valid_until IS NULL OR valid_until > valid_from),
  CHECK ((retracted_at IS NULL) = (retraction_reason IS NULL))
);

CREATE TABLE supplier_lots (
  organization_id uuid NOT NULL,
  supplier_lot_id uuid NOT NULL DEFAULT gen_random_uuid(),
  supplier_id uuid NOT NULL,
  material_id uuid NOT NULL,
  lot_code text NOT NULL,
  manufactured_on date,
  expires_on date,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (organization_id, supplier_lot_id),
  UNIQUE (organization_id, supplier_id, material_id, lot_code),
  FOREIGN KEY (organization_id, supplier_id) REFERENCES suppliers(organization_id, supplier_id),
  FOREIGN KEY (organization_id, material_id) REFERENCES purchased_materials(organization_id, material_id),
  CHECK (expires_on IS NULL OR manufactured_on IS NULL OR expires_on > manufactured_on)
);

CREATE TABLE material_receipts (
  organization_id uuid NOT NULL,
  receipt_id uuid NOT NULL DEFAULT gen_random_uuid(),
  receipt_code text NOT NULL,
  supplier_lot_id uuid NOT NULL,
  received_at timestamptz NOT NULL,
  quantity numeric(20,8) NOT NULL CHECK (quantity > 0),
  unit_code text NOT NULL,
  facility_id uuid,
  bound_specification_id uuid,
  specification_binding_reason text,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (organization_id, receipt_id),
  UNIQUE (organization_id, receipt_code),
  FOREIGN KEY (organization_id, supplier_lot_id) REFERENCES supplier_lots(organization_id, supplier_lot_id),
  FOREIGN KEY (organization_id, facility_id) REFERENCES facilities(organization_id, facility_id),
  FOREIGN KEY (organization_id, bound_specification_id)
    REFERENCES material_specifications(organization_id, specification_id),
  CHECK ((bound_specification_id IS NULL) = (specification_binding_reason IS NULL))
);

CREATE TABLE material_origin_findings (
  organization_id uuid NOT NULL,
  origin_finding_id uuid NOT NULL DEFAULT gen_random_uuid(),
  supplier_lot_id uuid NOT NULL,
  finding_kind text NOT NULL CHECK (finding_kind IN ('supplier_declared','independently_verified','laboratory_finding')),
  origin jsonb NOT NULL,
  finding_state knowledge_state NOT NULL,
  source_artifact_id uuid,
  source_artifact_version bigint,
  observed_at timestamptz NOT NULL,
  approved_by uuid REFERENCES principals(principal_id),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (organization_id, origin_finding_id),
  FOREIGN KEY (organization_id, supplier_lot_id) REFERENCES supplier_lots(organization_id, supplier_lot_id),
  FOREIGN KEY (organization_id, source_artifact_id, source_artifact_version)
    REFERENCES artifact_versions(organization_id, artifact_id, version)
);

CREATE TABLE supplier_corrections (
  organization_id uuid NOT NULL,
  correction_id uuid NOT NULL DEFAULT gen_random_uuid(),
  specification_id uuid NOT NULL,
  correction_kind text NOT NULL CHECK (correction_kind IN ('clarification','replacement','retraction')),
  correction jsonb NOT NULL,
  source_artifact_id uuid,
  source_artifact_version bigint,
  effective_at timestamptz NOT NULL,
  created_by uuid NOT NULL REFERENCES principals(principal_id),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (organization_id, correction_id),
  FOREIGN KEY (organization_id, specification_id)
    REFERENCES material_specifications(organization_id, specification_id),
  FOREIGN KEY (organization_id, source_artifact_id, source_artifact_version)
    REFERENCES artifact_versions(organization_id, artifact_id, version)
);

CREATE TABLE units (
  organization_id uuid NOT NULL REFERENCES organizations(organization_id),
  unit_code text NOT NULL,
  dimension text NOT NULL CHECK (dimension IN ('mass','volume','count','dimensionless')),
  factor_to_base numeric(30,12) NOT NULL CHECK (factor_to_base > 0),
  approved_by uuid REFERENCES principals(principal_id),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (organization_id, unit_code)
);

CREATE TABLE formulations (
  organization_id uuid NOT NULL REFERENCES organizations(organization_id),
  formulation_id uuid NOT NULL DEFAULT gen_random_uuid(),
  formulation_code text NOT NULL,
  name text NOT NULL,
  current_version bigint NOT NULL DEFAULT 0,
  state lifecycle_state NOT NULL DEFAULT 'draft',
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (organization_id, formulation_id),
  UNIQUE (organization_id, formulation_code)
);

CREATE TABLE formulation_versions (
  organization_id uuid NOT NULL,
  formulation_id uuid NOT NULL,
  version bigint NOT NULL CHECK (version > 0),
  declared_yield numeric(20,8) NOT NULL CHECK (declared_yield > 0),
  yield_unit text NOT NULL,
  finished_product_composition jsonb,
  transformation jsonb NOT NULL DEFAULT '{}'::jsonb,
  reason text NOT NULL,
  created_by uuid NOT NULL REFERENCES principals(principal_id),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (organization_id, formulation_id, version),
  FOREIGN KEY (organization_id, formulation_id) REFERENCES formulations(organization_id, formulation_id),
  FOREIGN KEY (organization_id, yield_unit) REFERENCES units(organization_id, unit_code)
);

CREATE TABLE formulation_components (
  organization_id uuid NOT NULL,
  formulation_id uuid NOT NULL,
  formulation_version bigint NOT NULL,
  component_id uuid NOT NULL DEFAULT gen_random_uuid(),
  sequence integer NOT NULL CHECK (sequence > 0),
  component_role text NOT NULL CHECK (component_role IN ('ingredient','subrecipe','processing_aid','rework')),
  material_id uuid,
  child_formulation_id uuid,
  child_formulation_version bigint,
  quantity numeric(20,8) NOT NULL CHECK (quantity >= 0),
  unit_code text NOT NULL,
  retained_fraction numeric(12,9),
  removal_claim jsonb,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (organization_id, formulation_id, formulation_version, component_id),
  UNIQUE (organization_id, formulation_id, formulation_version, sequence),
  FOREIGN KEY (organization_id, formulation_id, formulation_version)
    REFERENCES formulation_versions(organization_id, formulation_id, version),
  FOREIGN KEY (organization_id, material_id) REFERENCES purchased_materials(organization_id, material_id),
  FOREIGN KEY (organization_id, child_formulation_id, child_formulation_version)
    REFERENCES formulation_versions(organization_id, formulation_id, version),
  FOREIGN KEY (organization_id, unit_code) REFERENCES units(organization_id, unit_code),
  CHECK (
    (component_role IN ('ingredient','processing_aid','rework') AND material_id IS NOT NULL
      AND child_formulation_id IS NULL AND child_formulation_version IS NULL)
    OR
    (component_role = 'subrecipe' AND material_id IS NULL
      AND child_formulation_id IS NOT NULL AND child_formulation_version IS NOT NULL)
  ),
  CHECK (retained_fraction IS NULL OR (retained_fraction >= 0 AND retained_fraction <= 1))
);

CREATE TABLE label_text_versions (
  organization_id uuid NOT NULL REFERENCES organizations(organization_id),
  label_text_id uuid NOT NULL DEFAULT gen_random_uuid(),
  label_code text NOT NULL,
  version bigint NOT NULL CHECK (version > 0),
  language_tag text NOT NULL,
  ingredient_declaration text NOT NULL,
  allergen_statement text,
  full_text text NOT NULL,
  text_sha256 char(64) NOT NULL,
  created_by uuid REFERENCES principals(principal_id),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (organization_id, label_text_id),
  UNIQUE (organization_id, label_code, version, language_tag)
);

CREATE TABLE printer_specifications (
  organization_id uuid NOT NULL REFERENCES organizations(organization_id),
  printer_specification_id uuid NOT NULL DEFAULT gen_random_uuid(),
  specification_code text NOT NULL,
  min_x_height_mm numeric(10,4),
  min_contrast_ratio numeric(10,4),
  resolution_dpi integer CHECK (resolution_dpi IS NULL OR resolution_dpi > 0),
  rules jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (organization_id, printer_specification_id),
  UNIQUE (organization_id, specification_code)
);

CREATE TABLE artwork_versions (
  organization_id uuid NOT NULL REFERENCES organizations(organization_id),
  artwork_id uuid NOT NULL DEFAULT gen_random_uuid(),
  artwork_code text NOT NULL,
  version bigint NOT NULL CHECK (version > 0),
  label_text_id uuid NOT NULL,
  artifact_id uuid NOT NULL,
  artifact_version bigint NOT NULL,
  package_size text NOT NULL,
  language_tags text[] NOT NULL,
  printer_specification_id uuid,
  width_mm numeric(12,4),
  height_mm numeric(12,4),
  status lifecycle_state NOT NULL DEFAULT 'draft',
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (organization_id, artwork_id),
  UNIQUE (organization_id, artwork_code, version),
  FOREIGN KEY (organization_id, label_text_id) REFERENCES label_text_versions(organization_id, label_text_id),
  FOREIGN KEY (organization_id, artifact_id, artifact_version)
    REFERENCES artifact_versions(organization_id, artifact_id, version),
  FOREIGN KEY (organization_id, printer_specification_id)
    REFERENCES printer_specifications(organization_id, printer_specification_id)
);

CREATE TABLE artwork_regions (
  organization_id uuid NOT NULL,
  artwork_id uuid NOT NULL,
  region_id uuid NOT NULL DEFAULT gen_random_uuid(),
  region_kind text NOT NULL CHECK (region_kind IN ('ingredient_declaration','allergen_statement','product_identity','mandatory_text','other')),
  extracted_text text NOT NULL,
  polygon jsonb NOT NULL,
  x_height_mm numeric(12,5),
  contrast_ratio numeric(12,5),
  emphasis jsonb NOT NULL DEFAULT '{}'::jsonb,
  placement jsonb NOT NULL DEFAULT '{}'::jsonb,
  confidence numeric(6,5),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (organization_id, artwork_id, region_id),
  FOREIGN KEY (organization_id, artwork_id) REFERENCES artwork_versions(organization_id, artwork_id)
);

CREATE TABLE artwork_assessments (
  organization_id uuid NOT NULL,
  artwork_assessment_id uuid NOT NULL DEFAULT gen_random_uuid(),
  artwork_id uuid NOT NULL,
  terminology_state text NOT NULL,
  text_match_state text NOT NULL,
  emphasis_state text NOT NULL,
  placement_state text NOT NULL,
  contrast_state text NOT NULL,
  legibility_state text NOT NULL,
  result jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (organization_id, artwork_assessment_id),
  FOREIGN KEY (organization_id, artwork_id) REFERENCES artwork_versions(organization_id, artwork_id)
);

CREATE TABLE production_lines (
  organization_id uuid NOT NULL,
  line_id uuid NOT NULL DEFAULT gen_random_uuid(),
  facility_id uuid NOT NULL,
  line_code text NOT NULL,
  name text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (organization_id, line_id),
  UNIQUE (organization_id, facility_id, line_code),
  FOREIGN KEY (organization_id, facility_id) REFERENCES facilities(organization_id, facility_id)
);

CREATE TABLE equipment (
  organization_id uuid NOT NULL,
  equipment_id uuid NOT NULL DEFAULT gen_random_uuid(),
  line_id uuid NOT NULL,
  equipment_code text NOT NULL,
  name text NOT NULL,
  shared boolean NOT NULL DEFAULT false,
  allergen_retention_features jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (organization_id, equipment_id),
  UNIQUE (organization_id, line_id, equipment_code),
  FOREIGN KEY (organization_id, line_id) REFERENCES production_lines(organization_id, line_id)
);

CREATE TABLE packaging_lots (
  organization_id uuid NOT NULL,
  packaging_lot_id uuid NOT NULL DEFAULT gen_random_uuid(),
  lot_code text NOT NULL,
  artwork_id uuid NOT NULL,
  received_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (organization_id, packaging_lot_id),
  UNIQUE (organization_id, lot_code),
  FOREIGN KEY (organization_id, artwork_id) REFERENCES artwork_versions(organization_id, artwork_id)
);

CREATE TABLE manufacturing_batches (
  organization_id uuid NOT NULL,
  batch_id uuid NOT NULL DEFAULT gen_random_uuid(),
  batch_code text NOT NULL,
  facility_id uuid NOT NULL,
  line_id uuid NOT NULL,
  formulation_id uuid NOT NULL,
  formulation_version bigint NOT NULL,
  started_at timestamptz NOT NULL,
  completed_at timestamptz,
  actual_material_record_state text NOT NULL CHECK (actual_material_record_state IN ('complete','partial','missing')),
  state text NOT NULL CHECK (state IN ('planned','running','completed','held','released','cancelled')),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (organization_id, batch_id),
  UNIQUE (organization_id, batch_code),
  FOREIGN KEY (organization_id, facility_id) REFERENCES facilities(organization_id, facility_id),
  FOREIGN KEY (organization_id, line_id) REFERENCES production_lines(organization_id, line_id),
  FOREIGN KEY (organization_id, formulation_id, formulation_version)
    REFERENCES formulation_versions(organization_id, formulation_id, version),
  CHECK (completed_at IS NULL OR completed_at >= started_at)
);

CREATE TABLE batch_material_consumptions (
  organization_id uuid NOT NULL,
  batch_id uuid NOT NULL,
  consumption_id uuid NOT NULL DEFAULT gen_random_uuid(),
  material_id uuid NOT NULL,
  supplier_lot_id uuid,
  receipt_id uuid,
  quantity numeric(20,8) NOT NULL CHECK (quantity >= 0),
  unit_code text NOT NULL,
  consumption_kind text NOT NULL CHECK (consumption_kind IN ('planned','actual','rework')),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (organization_id, batch_id, consumption_id),
  FOREIGN KEY (organization_id, batch_id) REFERENCES manufacturing_batches(organization_id, batch_id),
  FOREIGN KEY (organization_id, material_id) REFERENCES purchased_materials(organization_id, material_id),
  FOREIGN KEY (organization_id, supplier_lot_id) REFERENCES supplier_lots(organization_id, supplier_lot_id),
  FOREIGN KEY (organization_id, receipt_id) REFERENCES material_receipts(organization_id, receipt_id),
  FOREIGN KEY (organization_id, unit_code) REFERENCES units(organization_id, unit_code)
);

CREATE TABLE batch_packaging_usage (
  organization_id uuid NOT NULL,
  batch_id uuid NOT NULL,
  packaging_lot_id uuid NOT NULL,
  usage_state text NOT NULL CHECK (usage_state IN ('planned','actual')),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (organization_id, batch_id, packaging_lot_id, usage_state),
  FOREIGN KEY (organization_id, batch_id) REFERENCES manufacturing_batches(organization_id, batch_id),
  FOREIGN KEY (organization_id, packaging_lot_id) REFERENCES packaging_lots(organization_id, packaging_lot_id)
);

CREATE TABLE batch_deviations (
  organization_id uuid NOT NULL,
  batch_id uuid NOT NULL,
  deviation_id uuid NOT NULL DEFAULT gen_random_uuid(),
  deviation_kind text NOT NULL,
  severity text NOT NULL CHECK (severity IN ('information','review','blocking')),
  detail jsonb NOT NULL,
  detected_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (organization_id, batch_id, deviation_id),
  FOREIGN KEY (organization_id, batch_id) REFERENCES manufacturing_batches(organization_id, batch_id)
);

CREATE TABLE camera_qualifications (
  organization_id uuid NOT NULL REFERENCES organizations(organization_id),
  camera_qualification_id uuid NOT NULL DEFAULT gen_random_uuid(),
  camera_identifier text NOT NULL,
  workflow_version text NOT NULL,
  calibration_artifact_id uuid,
  calibration_artifact_version bigint,
  valid_from timestamptz NOT NULL,
  valid_until timestamptz NOT NULL,
  approved_by uuid NOT NULL REFERENCES principals(principal_id),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (organization_id, camera_qualification_id),
  FOREIGN KEY (organization_id, calibration_artifact_id, calibration_artifact_version)
    REFERENCES artifact_versions(organization_id, artifact_id, version),
  CHECK (valid_until > valid_from)
);

CREATE TABLE sampling_plans (
  organization_id uuid NOT NULL REFERENCES organizations(organization_id),
  sampling_plan_id uuid NOT NULL DEFAULT gen_random_uuid(),
  plan_code text NOT NULL,
  plan_version bigint NOT NULL,
  sample_size integer NOT NULL CHECK (sample_size > 0),
  inference_scope text NOT NULL CHECK (inference_scope IN ('sample_only','batch')),
  acceptance_policy jsonb NOT NULL,
  approved_by uuid REFERENCES principals(principal_id),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (organization_id, sampling_plan_id),
  UNIQUE (organization_id, plan_code, plan_version),
  CHECK (inference_scope = 'sample_only' OR approved_by IS NOT NULL)
);

CREATE TABLE physical_package_inspections (
  organization_id uuid NOT NULL,
  inspection_id uuid NOT NULL DEFAULT gen_random_uuid(),
  sample_code text NOT NULL,
  batch_id uuid NOT NULL,
  packaging_lot_id uuid NOT NULL,
  camera_qualification_id uuid NOT NULL,
  sampling_plan_id uuid NOT NULL,
  source_artifact_id uuid NOT NULL,
  source_artifact_version bigint NOT NULL,
  line_id uuid NOT NULL,
  captured_at timestamptz NOT NULL,
  product_identity_state text NOT NULL,
  package_identity_state text NOT NULL,
  artwork_match_state text NOT NULL,
  ocr_state text NOT NULL,
  legibility_state text NOT NULL,
  emphasis_state text NOT NULL,
  result jsonb NOT NULL,
  conclusion_scope text NOT NULL CHECK (conclusion_scope IN ('sample_only','batch')),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (organization_id, inspection_id),
  UNIQUE (organization_id, sample_code),
  FOREIGN KEY (organization_id, batch_id) REFERENCES manufacturing_batches(organization_id, batch_id),
  FOREIGN KEY (organization_id, packaging_lot_id) REFERENCES packaging_lots(organization_id, packaging_lot_id),
  FOREIGN KEY (organization_id, camera_qualification_id)
    REFERENCES camera_qualifications(organization_id, camera_qualification_id),
  FOREIGN KEY (organization_id, sampling_plan_id) REFERENCES sampling_plans(organization_id, sampling_plan_id),
  FOREIGN KEY (organization_id, source_artifact_id, source_artifact_version)
    REFERENCES artifact_versions(organization_id, artifact_id, version),
  FOREIGN KEY (organization_id, line_id) REFERENCES production_lines(organization_id, line_id)
);

CREATE TABLE cleaning_events (
  organization_id uuid NOT NULL REFERENCES organizations(organization_id),
  cleaning_event_id uuid NOT NULL DEFAULT gen_random_uuid(),
  line_id uuid NOT NULL,
  equipment_ids uuid[] NOT NULL,
  procedure_version text NOT NULL,
  started_at timestamptz NOT NULL,
  completed_at timestamptz NOT NULL,
  verification_state text NOT NULL CHECK (verification_state IN ('passed','failed','indeterminate')),
  verification_evidence jsonb NOT NULL,
  source_artifact_id uuid,
  source_artifact_version bigint,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (organization_id, cleaning_event_id),
  FOREIGN KEY (organization_id, line_id) REFERENCES production_lines(organization_id, line_id),
  FOREIGN KEY (organization_id, source_artifact_id, source_artifact_version)
    REFERENCES artifact_versions(organization_id, artifact_id, version),
  CHECK (completed_at >= started_at)
);

CREATE TABLE cross_contact_assessments (
  organization_id uuid NOT NULL,
  cross_contact_assessment_id uuid NOT NULL DEFAULT gen_random_uuid(),
  batch_id uuid NOT NULL,
  previous_batch_id uuid,
  line_id uuid NOT NULL,
  cleaning_event_id uuid,
  recipe_origin_allergens text[] NOT NULL,
  unintended_hazards text[] NOT NULL,
  controls jsonb NOT NULL,
  evidence_snapshot jsonb NOT NULL,
  evidence_sha256 char(64) NOT NULL,
  state text NOT NULL CHECK (state IN ('supported','indeterminate','conflicted','failed')),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (organization_id, cross_contact_assessment_id),
  FOREIGN KEY (organization_id, batch_id) REFERENCES manufacturing_batches(organization_id, batch_id),
  FOREIGN KEY (organization_id, previous_batch_id) REFERENCES manufacturing_batches(organization_id, batch_id),
  FOREIGN KEY (organization_id, line_id) REFERENCES production_lines(organization_id, line_id),
  FOREIGN KEY (organization_id, cleaning_event_id) REFERENCES cleaning_events(organization_id, cleaning_event_id)
);

CREATE INDEX receipt_by_specification ON material_receipts (organization_id, bound_specification_id);
CREATE INDEX receipt_by_supplier_lot ON material_receipts (organization_id, supplier_lot_id);
CREATE INDEX formulation_component_children ON formulation_components
  (organization_id, child_formulation_id, child_formulation_version);
CREATE INDEX batch_by_line_time ON manufacturing_batches (organization_id, line_id, started_at);

CREATE TRIGGER material_specifications_immutable BEFORE UPDATE OR DELETE ON material_specifications
FOR EACH ROW EXECUTE FUNCTION reject_immutable_mutation();
CREATE TRIGGER supplier_lots_immutable BEFORE UPDATE OR DELETE ON supplier_lots
FOR EACH ROW EXECUTE FUNCTION reject_immutable_mutation();
CREATE TRIGGER material_receipts_immutable BEFORE UPDATE OR DELETE ON material_receipts
FOR EACH ROW EXECUTE FUNCTION reject_immutable_mutation();
CREATE TRIGGER material_origin_findings_immutable BEFORE UPDATE OR DELETE ON material_origin_findings
FOR EACH ROW EXECUTE FUNCTION reject_immutable_mutation();
CREATE TRIGGER supplier_corrections_immutable BEFORE UPDATE OR DELETE ON supplier_corrections
FOR EACH ROW EXECUTE FUNCTION reject_immutable_mutation();
CREATE TRIGGER formulation_versions_immutable BEFORE UPDATE OR DELETE ON formulation_versions
FOR EACH ROW EXECUTE FUNCTION reject_immutable_mutation();
CREATE TRIGGER formulation_components_immutable BEFORE UPDATE OR DELETE ON formulation_components
FOR EACH ROW EXECUTE FUNCTION reject_immutable_mutation();
CREATE TRIGGER label_text_versions_immutable BEFORE UPDATE OR DELETE ON label_text_versions
FOR EACH ROW EXECUTE FUNCTION reject_immutable_mutation();
CREATE TRIGGER artwork_versions_immutable BEFORE UPDATE OR DELETE ON artwork_versions
FOR EACH ROW EXECUTE FUNCTION reject_immutable_mutation();
CREATE TRIGGER artwork_regions_immutable BEFORE UPDATE OR DELETE ON artwork_regions
FOR EACH ROW EXECUTE FUNCTION reject_immutable_mutation();
CREATE TRIGGER manufacturing_batches_immutable BEFORE UPDATE OR DELETE ON manufacturing_batches
FOR EACH ROW EXECUTE FUNCTION reject_immutable_mutation();
CREATE TRIGGER physical_package_inspections_immutable BEFORE UPDATE OR DELETE ON physical_package_inspections
FOR EACH ROW EXECUTE FUNCTION reject_immutable_mutation();
CREATE TRIGGER cleaning_events_immutable BEFORE UPDATE OR DELETE ON cleaning_events
FOR EACH ROW EXECUTE FUNCTION reject_immutable_mutation();
CREATE TRIGGER cross_contact_assessments_immutable BEFORE UPDATE OR DELETE ON cross_contact_assessments
FOR EACH ROW EXECUTE FUNCTION reject_immutable_mutation();

DO $$
DECLARE table_name text;
BEGIN
  FOREACH table_name IN ARRAY ARRAY[
    'suppliers','purchased_materials','supplier_material_identifiers','material_specifications',
    'supplier_lots','material_receipts','material_origin_findings','supplier_corrections','units',
    'formulations','formulation_versions','formulation_components','label_text_versions',
    'printer_specifications','artwork_versions','artwork_regions','artwork_assessments',
    'production_lines','equipment','packaging_lots','manufacturing_batches',
    'batch_material_consumptions','batch_packaging_usage','batch_deviations',
    'camera_qualifications','sampling_plans','physical_package_inspections',
    'cleaning_events','cross_contact_assessments'
  ]
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', table_name);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', table_name);
    EXECUTE format(
      'CREATE POLICY tenant_isolation ON %I USING (organization_id = current_organization_id()) WITH CHECK (organization_id = current_organization_id())',
      table_name
    );
  END LOOP;
END $$;

REVOKE UPDATE, DELETE, TRUNCATE ON material_specifications, supplier_lots, material_receipts,
  material_origin_findings, supplier_corrections, formulation_versions, formulation_components,
  label_text_versions, artwork_versions, artwork_regions, manufacturing_batches,
  physical_package_inspections, cleaning_events, cross_contact_assessments FROM bahar_app;
"""


def upgrade() -> None:
    op.execute(DDL)


def downgrade() -> None:
    for table in (
        "cross_contact_assessments", "cleaning_events", "physical_package_inspections",
        "sampling_plans", "camera_qualifications", "batch_deviations", "batch_packaging_usage",
        "batch_material_consumptions", "manufacturing_batches", "packaging_lots", "equipment",
        "production_lines", "artwork_assessments", "artwork_regions", "artwork_versions",
        "printer_specifications", "label_text_versions", "formulation_components",
        "formulation_versions", "formulations", "units", "supplier_corrections",
        "material_origin_findings", "material_receipts", "supplier_lots",
        "material_specifications", "supplier_material_identifiers", "purchased_materials", "suppliers",
    ):
        op.execute(f"DROP TABLE IF EXISTS {table} CASCADE")
