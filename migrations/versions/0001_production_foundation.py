"""Production persistence, evidence custody, extraction, knowledge, and audit foundation."""

from __future__ import annotations

from alembic import op


revision = "0001_production_foundation"
down_revision = None
branch_labels = None
depends_on = None


DDL = r"""
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TYPE lifecycle_state AS ENUM ('draft','active','superseded','suspended','withdrawn');
CREATE TYPE ingestion_state AS ENUM (
  'received','original_preserved','type_verified','malware_scan_passed',
  'structure_validated','extraction_ready','extracted','reviewed','accepted',
  'quarantined','rejected','failed_internal'
);
CREATE TYPE decision_state AS ENUM ('proposed','under_review','accepted','corrected','rejected','superseded');
CREATE TYPE knowledge_state AS ENUM ('unknown','supported_positive','supported_negative','conflicted');

CREATE TABLE organizations (
  organization_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  slug text NOT NULL UNIQUE,
  name text NOT NULL,
  state lifecycle_state NOT NULL DEFAULT 'active',
  created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE facilities (
  facility_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(organization_id),
  code text NOT NULL,
  name text NOT NULL,
  state lifecycle_state NOT NULL DEFAULT 'active',
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (organization_id, code),
  UNIQUE (organization_id, facility_id)
);

CREATE TABLE principals (
  principal_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  issuer text NOT NULL,
  subject text NOT NULL,
  display_name text,
  state lifecycle_state NOT NULL DEFAULT 'active',
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (issuer, subject)
);

CREATE TABLE memberships (
  membership_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(organization_id),
  principal_id uuid NOT NULL REFERENCES principals(principal_id),
  facility_id uuid,
  role_name text NOT NULL CHECK (role_name IN (
    'analyst','reviewer','regulatory_approver','release_authority',
    'incident_manager','auditor','tenant_administrator','platform_administrator','emergency_operator'
  )),
  valid_from timestamptz NOT NULL DEFAULT clock_timestamp(),
  valid_until timestamptz,
  appointment_artifact_id uuid,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  FOREIGN KEY (organization_id, facility_id) REFERENCES facilities(organization_id, facility_id),
  CHECK (valid_until IS NULL OR valid_until > valid_from)
);
CREATE UNIQUE INDEX memberships_scope_unique ON memberships (
  organization_id, principal_id, COALESCE(facility_id, '00000000-0000-0000-0000-000000000000'::uuid), role_name
);

CREATE TABLE governed_entities (
  organization_id uuid NOT NULL REFERENCES organizations(organization_id),
  entity_id uuid NOT NULL DEFAULT gen_random_uuid(),
  external_key text NOT NULL,
  entity_type text NOT NULL,
  current_revision bigint NOT NULL DEFAULT 0 CHECK (current_revision >= 0),
  state lifecycle_state NOT NULL DEFAULT 'draft',
  created_by uuid REFERENCES principals(principal_id),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (organization_id, entity_id),
  UNIQUE (organization_id, entity_type, external_key)
);

CREATE TABLE entity_revisions (
  organization_id uuid NOT NULL,
  entity_id uuid NOT NULL,
  revision bigint NOT NULL CHECK (revision > 0),
  predecessor_revision bigint,
  body jsonb NOT NULL,
  body_sha256 char(64) NOT NULL CHECK (body_sha256 ~ '^[0-9a-f]{64}$'),
  reason text NOT NULL,
  author_id uuid REFERENCES principals(principal_id),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (organization_id, entity_id, revision),
  FOREIGN KEY (organization_id, entity_id) REFERENCES governed_entities(organization_id, entity_id),
  CHECK (predecessor_revision IS NULL OR predecessor_revision = revision - 1)
);

CREATE TABLE dependency_revisions (
  organization_id uuid NOT NULL REFERENCES organizations(organization_id),
  dependency_id uuid NOT NULL DEFAULT gen_random_uuid(),
  revision bigint NOT NULL CHECK (revision > 0),
  upstream_type text NOT NULL,
  upstream_id uuid NOT NULL,
  downstream_type text NOT NULL,
  downstream_id uuid NOT NULL,
  relation text NOT NULL,
  completeness text NOT NULL CHECK (completeness IN ('complete','partial','unknown')),
  state lifecycle_state NOT NULL DEFAULT 'active',
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (organization_id, dependency_id, revision)
);

CREATE TABLE requirement_catalogs (
  organization_id uuid NOT NULL REFERENCES organizations(organization_id),
  catalog_id uuid NOT NULL DEFAULT gen_random_uuid(),
  slug text NOT NULL,
  catalog_version text NOT NULL,
  source_sha256 char(64) NOT NULL,
  state lifecycle_state NOT NULL DEFAULT 'draft',
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (organization_id, catalog_id),
  UNIQUE (organization_id, slug, catalog_version)
);

CREATE TABLE requirements (
  organization_id uuid NOT NULL,
  catalog_id uuid NOT NULL,
  requirement_id text NOT NULL CHECK (requirement_id ~ '^LG-[A-Z]{3}-[0-9]{3}$'),
  current_revision bigint NOT NULL DEFAULT 0,
  status text NOT NULL CHECK (status IN ('proposed','reviewed','approved','implemented','verified','excluded','superseded')),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (organization_id, catalog_id, requirement_id),
  FOREIGN KEY (organization_id, catalog_id) REFERENCES requirement_catalogs(organization_id, catalog_id)
);

CREATE TABLE requirement_revisions (
  organization_id uuid NOT NULL,
  catalog_id uuid NOT NULL,
  requirement_id text NOT NULL,
  revision bigint NOT NULL CHECK (revision > 0),
  description text NOT NULL,
  origin text NOT NULL,
  rationale text NOT NULL,
  authority text NOT NULL,
  priority text NOT NULL,
  applicability jsonb NOT NULL,
  dependencies text[] NOT NULL DEFAULT '{}',
  acceptance_predicate text,
  verification_method text,
  implementation_components text[] NOT NULL DEFAULT '{}',
  test_references text[] NOT NULL DEFAULT '{}',
  evidence_references text[] NOT NULL DEFAULT '{}',
  exclusion_reason text,
  source_locator text NOT NULL,
  source_sha256 char(64) NOT NULL,
  created_by uuid REFERENCES principals(principal_id),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (organization_id, catalog_id, requirement_id, revision),
  FOREIGN KEY (organization_id, catalog_id, requirement_id)
    REFERENCES requirements(organization_id, catalog_id, requirement_id)
);

CREATE TABLE requirement_conflicts (
  organization_id uuid NOT NULL,
  catalog_id uuid NOT NULL,
  conflict_id uuid NOT NULL DEFAULT gen_random_uuid(),
  left_requirement_id text NOT NULL,
  right_requirement_id text NOT NULL,
  conflict_kind text NOT NULL,
  analysis text NOT NULL,
  resolution text,
  resolved_by uuid REFERENCES principals(principal_id),
  resolved_at timestamptz,
  PRIMARY KEY (organization_id, catalog_id, conflict_id),
  FOREIGN KEY (organization_id, catalog_id, left_requirement_id)
    REFERENCES requirements(organization_id, catalog_id, requirement_id),
  FOREIGN KEY (organization_id, catalog_id, right_requirement_id)
    REFERENCES requirements(organization_id, catalog_id, requirement_id),
  CHECK (left_requirement_id <> right_requirement_id)
);

CREATE TABLE retention_policies (
  organization_id uuid NOT NULL REFERENCES organizations(organization_id),
  retention_class text NOT NULL,
  duration_days integer,
  immutable boolean NOT NULL DEFAULT false,
  description text NOT NULL,
  approved_by uuid REFERENCES principals(principal_id),
  approved_at timestamptz,
  PRIMARY KEY (organization_id, retention_class),
  CHECK (duration_days IS NULL OR duration_days > 0)
);

CREATE TABLE artifacts (
  organization_id uuid NOT NULL REFERENCES organizations(organization_id),
  artifact_id uuid NOT NULL DEFAULT gen_random_uuid(),
  artifact_type text NOT NULL,
  document_identity text,
  declared_version text,
  document_scope jsonb NOT NULL DEFAULT '{}'::jsonb,
  supplier_id uuid,
  supplier_identifier text,
  state lifecycle_state NOT NULL DEFAULT 'draft',
  current_version bigint NOT NULL DEFAULT 0 CHECK (current_version >= 0),
  created_by uuid REFERENCES principals(principal_id),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (organization_id, artifact_id)
);

CREATE TABLE document_applicable_lots (
  organization_id uuid NOT NULL,
  artifact_id uuid NOT NULL,
  lot_identifier text NOT NULL,
  declared_scope jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (organization_id, artifact_id, lot_identifier),
  FOREIGN KEY (organization_id, artifact_id) REFERENCES artifacts(organization_id, artifact_id)
);

CREATE TABLE artifact_versions (
  organization_id uuid NOT NULL,
  artifact_id uuid NOT NULL,
  version bigint NOT NULL CHECK (version > 0),
  storage_class text NOT NULL CHECK (storage_class IN ('quarantine','governed','derived','export','audit','backup')),
  bucket_name text NOT NULL,
  object_key text NOT NULL,
  provider_version_id text,
  byte_length bigint NOT NULL CHECK (byte_length >= 0),
  sha256 char(64) NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
  claimed_media_type text,
  detected_media_type text NOT NULL,
  encryption_method text NOT NULL,
  encryption_key_id text NOT NULL,
  retention_class text NOT NULL,
  retain_until timestamptz,
  legal_hold boolean NOT NULL DEFAULT false,
  valid_from date,
  valid_until date,
  signature_state text NOT NULL DEFAULT 'not_evaluated',
  custody_state text NOT NULL CHECK (custody_state IN ('preserved_quarantined','governed_available','missing','digest_mismatch','rejected')),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (organization_id, artifact_id, version),
  FOREIGN KEY (organization_id, artifact_id) REFERENCES artifacts(organization_id, artifact_id),
  FOREIGN KEY (organization_id, retention_class) REFERENCES retention_policies(organization_id, retention_class),
  UNIQUE (organization_id, bucket_name, object_key, provider_version_id)
);

CREATE TABLE artifact_lot_links (
  organization_id uuid NOT NULL,
  artifact_id uuid NOT NULL,
  artifact_version bigint NOT NULL,
  material_id uuid NOT NULL,
  lot_identifier text NOT NULL,
  applicability_state text NOT NULL CHECK (applicability_state IN ('declared','verified','rejected','unknown')),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (organization_id, artifact_id, artifact_version, material_id, lot_identifier),
  FOREIGN KEY (organization_id, artifact_id, artifact_version)
    REFERENCES artifact_versions(organization_id, artifact_id, version)
);

CREATE TABLE ingestion_requests (
  organization_id uuid NOT NULL REFERENCES organizations(organization_id),
  ingestion_id uuid NOT NULL DEFAULT gen_random_uuid(),
  artifact_id uuid NOT NULL,
  artifact_version bigint NOT NULL,
  state ingestion_state NOT NULL DEFAULT 'received',
  claimed_filename text NOT NULL,
  claimed_media_type text,
  detected_media_type text,
  failure_code text,
  submitted_by uuid REFERENCES principals(principal_id),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (organization_id, ingestion_id),
  FOREIGN KEY (organization_id, artifact_id, artifact_version)
    REFERENCES artifact_versions(organization_id, artifact_id, version)
);

CREATE TABLE ingestion_attempts (
  organization_id uuid NOT NULL,
  ingestion_id uuid NOT NULL,
  attempt bigint NOT NULL CHECK (attempt > 0),
  stage text NOT NULL,
  tool_name text NOT NULL,
  tool_version text NOT NULL,
  result_state text NOT NULL,
  details jsonb NOT NULL DEFAULT '{}'::jsonb,
  started_at timestamptz NOT NULL,
  completed_at timestamptz,
  PRIMARY KEY (organization_id, ingestion_id, attempt),
  FOREIGN KEY (organization_id, ingestion_id) REFERENCES ingestion_requests(organization_id, ingestion_id)
);

CREATE TABLE extraction_runs (
  organization_id uuid NOT NULL REFERENCES organizations(organization_id),
  extraction_id uuid NOT NULL DEFAULT gen_random_uuid(),
  artifact_id uuid NOT NULL,
  artifact_version bigint NOT NULL,
  method text NOT NULL CHECK (method IN ('structured_api','spreadsheet','native_pdf','ocr','human_transcription')),
  engine_name text NOT NULL,
  engine_version text NOT NULL,
  language_profile text,
  configuration jsonb NOT NULL,
  state text NOT NULL CHECK (state IN ('running','completed','partial','failed','quarantined')),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  completed_at timestamptz,
  PRIMARY KEY (organization_id, extraction_id),
  FOREIGN KEY (organization_id, artifact_id, artifact_version)
    REFERENCES artifact_versions(organization_id, artifact_id, version)
);

CREATE TABLE extracted_regions (
  organization_id uuid NOT NULL,
  extraction_id uuid NOT NULL,
  region_id uuid NOT NULL DEFAULT gen_random_uuid(),
  page_number integer NOT NULL CHECK (page_number > 0),
  region_type text NOT NULL,
  source_text text NOT NULL,
  normalized_polygon jsonb NOT NULL,
  pixel_polygon jsonb,
  confidence numeric(6,5),
  unresolved boolean NOT NULL DEFAULT false,
  style jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (organization_id, extraction_id, region_id),
  FOREIGN KEY (organization_id, extraction_id) REFERENCES extraction_runs(organization_id, extraction_id),
  CHECK (confidence IS NULL OR (confidence >= 0 AND confidence <= 1))
);

CREATE TABLE extraction_corrections (
  organization_id uuid NOT NULL,
  correction_id uuid NOT NULL DEFAULT gen_random_uuid(),
  extraction_id uuid NOT NULL,
  region_id uuid NOT NULL,
  corrected_text text,
  corrected_polygon jsonb,
  reason text NOT NULL,
  corrected_by uuid NOT NULL REFERENCES principals(principal_id),
  review_state decision_state NOT NULL DEFAULT 'proposed',
  supersedes_correction_id uuid,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (organization_id, correction_id),
  FOREIGN KEY (organization_id, extraction_id, region_id)
    REFERENCES extracted_regions(organization_id, extraction_id, region_id),
  FOREIGN KEY (organization_id, supersedes_correction_id)
    REFERENCES extraction_corrections(organization_id, correction_id)
);

CREATE TABLE ai_runs (
  organization_id uuid NOT NULL REFERENCES organizations(organization_id),
  ai_run_id uuid NOT NULL DEFAULT gen_random_uuid(),
  provider_id text NOT NULL,
  model_id text NOT NULL,
  model_version text NOT NULL,
  prompt_id text NOT NULL,
  prompt_version text NOT NULL,
  prompt_sha256 char(64) NOT NULL,
  schema_id text NOT NULL,
  schema_version text NOT NULL,
  schema_sha256 char(64) NOT NULL,
  safety_policy_version text NOT NULL,
  temperature numeric,
  seed bigint,
  input_manifest jsonb NOT NULL,
  output_sha256 char(64),
  state text NOT NULL CHECK (state IN ('running','completed','timeout','provider_unavailable','schema_rejected','quarantined','failed')),
  started_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  completed_at timestamptz,
  PRIMARY KEY (organization_id, ai_run_id)
);

CREATE TABLE interpretations (
  organization_id uuid NOT NULL,
  interpretation_id uuid NOT NULL DEFAULT gen_random_uuid(),
  revision bigint NOT NULL CHECK (revision > 0),
  ai_run_id uuid,
  extraction_id uuid,
  region_ids uuid[] NOT NULL DEFAULT '{}',
  proposition jsonb NOT NULL,
  state decision_state NOT NULL DEFAULT 'proposed',
  reviewer_id uuid REFERENCES principals(principal_id),
  decision_reason text,
  supersedes_revision bigint,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (organization_id, interpretation_id, revision),
  FOREIGN KEY (organization_id, ai_run_id) REFERENCES ai_runs(organization_id, ai_run_id),
  FOREIGN KEY (organization_id, extraction_id) REFERENCES extraction_runs(organization_id, extraction_id)
);

CREATE TABLE ingredient_concepts (
  organization_id uuid NOT NULL REFERENCES organizations(organization_id),
  concept_id uuid NOT NULL DEFAULT gen_random_uuid(),
  concept_kind text NOT NULL CHECK (concept_kind IN (
    'ingredient','commercial_material','biological_source','chemical_substance',
    'additive','allergen_class','functional_class','process','laboratory_analyte','legal_category'
  )),
  public_identifier text,
  state lifecycle_state NOT NULL DEFAULT 'draft',
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (organization_id, concept_id),
  UNIQUE (organization_id, public_identifier)
);

CREATE TABLE ingredient_names (
  organization_id uuid NOT NULL,
  name_id uuid NOT NULL DEFAULT gen_random_uuid(),
  concept_id uuid NOT NULL,
  lexical_value text NOT NULL,
  language_tag text NOT NULL,
  script_tag text,
  label_kind text NOT NULL CHECK (label_kind IN ('preferred','alternative','hidden','transliteration')),
  search_value text NOT NULL,
  source_artifact_id uuid,
  approval_state decision_state NOT NULL DEFAULT 'proposed',
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (organization_id, name_id),
  FOREIGN KEY (organization_id, concept_id) REFERENCES ingredient_concepts(organization_id, concept_id)
);
CREATE UNIQUE INDEX one_preferred_name_per_language
  ON ingredient_names (organization_id, concept_id, language_tag)
  WHERE label_kind = 'preferred' AND approval_state = 'accepted';

CREATE TABLE knowledge_assertions (
  organization_id uuid NOT NULL REFERENCES organizations(organization_id),
  assertion_id uuid NOT NULL DEFAULT gen_random_uuid(),
  revision bigint NOT NULL CHECK (revision > 0),
  subject_id uuid NOT NULL,
  predicate text NOT NULL,
  object_id uuid NOT NULL,
  polarity text NOT NULL CHECK (polarity IN ('positive','negative')),
  evidence_state knowledge_state NOT NULL DEFAULT 'unknown',
  scope_kind text NOT NULL CHECK (scope_kind IN ('general','supplier','material','lot','product','jurisdiction')),
  scope jsonb NOT NULL DEFAULT '{}'::jsonb,
  source_artifact_id uuid,
  source_artifact_version bigint,
  valid_from timestamptz,
  valid_until timestamptz,
  approval_state decision_state NOT NULL DEFAULT 'proposed',
  approved_by uuid REFERENCES principals(principal_id),
  supersedes_revision bigint,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (organization_id, assertion_id, revision),
  FOREIGN KEY (organization_id, subject_id) REFERENCES ingredient_concepts(organization_id, concept_id),
  FOREIGN KEY (organization_id, object_id) REFERENCES ingredient_concepts(organization_id, concept_id),
  FOREIGN KEY (organization_id, source_artifact_id, source_artifact_version)
    REFERENCES artifact_versions(organization_id, artifact_id, version),
  CHECK (valid_until IS NULL OR valid_from IS NULL OR valid_until > valid_from)
);

CREATE TABLE assessments (
  organization_id uuid NOT NULL REFERENCES organizations(organization_id),
  assessment_id uuid NOT NULL,
  external_key text NOT NULL,
  manifest_sha256 char(64) NOT NULL,
  input_sha256 char(64) NOT NULL,
  result jsonb NOT NULL,
  execution_state text NOT NULL,
  technical_readiness text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (organization_id, assessment_id),
  UNIQUE (organization_id, external_key),
  UNIQUE (organization_id, manifest_sha256)
);

CREATE TABLE releases (
  organization_id uuid NOT NULL REFERENCES organizations(organization_id),
  release_id uuid NOT NULL DEFAULT gen_random_uuid(),
  external_key text NOT NULL,
  assessment_id uuid NOT NULL,
  state text NOT NULL CHECK (state IN ('approved','suspended','withdrawn')),
  revision bigint NOT NULL CHECK (revision > 0),
  scope_sha256 char(64) NOT NULL,
  configuration_sha256 char(64) NOT NULL,
  evidence_snapshot_sha256 char(64) NOT NULL,
  authority_id uuid NOT NULL REFERENCES principals(principal_id),
  reason text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (organization_id, release_id),
  UNIQUE (organization_id, external_key),
  FOREIGN KEY (organization_id, assessment_id) REFERENCES assessments(organization_id, assessment_id)
);

CREATE TABLE release_revisions (
  organization_id uuid NOT NULL,
  release_id uuid NOT NULL,
  revision bigint NOT NULL CHECK (revision > 0),
  state text NOT NULL CHECK (state IN ('approved','suspended','withdrawn')),
  authority_id uuid NOT NULL REFERENCES principals(principal_id),
  reason text NOT NULL,
  predecessor_revision bigint,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (organization_id, release_id, revision),
  FOREIGN KEY (organization_id, release_id) REFERENCES releases(organization_id, release_id),
  CHECK (predecessor_revision IS NULL OR predecessor_revision = revision - 1)
);

CREATE TABLE idempotency_records (
  organization_id uuid NOT NULL REFERENCES organizations(organization_id),
  principal_id uuid NOT NULL REFERENCES principals(principal_id),
  operation_type text NOT NULL,
  idempotency_key text NOT NULL,
  request_sha256 char(64) NOT NULL,
  state text NOT NULL CHECK (state IN ('started','completed','failed')),
  response jsonb,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  completed_at timestamptz,
  PRIMARY KEY (organization_id, principal_id, operation_type, idempotency_key)
);

CREATE TABLE transaction_outbox (
  organization_id uuid NOT NULL REFERENCES organizations(organization_id),
  outbox_id uuid NOT NULL DEFAULT gen_random_uuid(),
  topic text NOT NULL,
  aggregate_type text NOT NULL,
  aggregate_id uuid NOT NULL,
  aggregate_revision bigint,
  payload jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  published_at timestamptz,
  attempt_count integer NOT NULL DEFAULT 0,
  PRIMARY KEY (organization_id, outbox_id)
);

CREATE TABLE audit_streams (
  organization_id uuid NOT NULL REFERENCES organizations(organization_id),
  stream_id uuid NOT NULL DEFAULT gen_random_uuid(),
  epoch integer NOT NULL DEFAULT 1 CHECK (epoch > 0),
  next_sequence bigint NOT NULL DEFAULT 1 CHECK (next_sequence > 0),
  head_hmac char(64) NOT NULL DEFAULT repeat('0', 64),
  key_id text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (organization_id, stream_id),
  UNIQUE (organization_id, epoch)
);

CREATE TABLE audit_events (
  organization_id uuid NOT NULL,
  stream_id uuid NOT NULL,
  epoch integer NOT NULL,
  sequence bigint NOT NULL CHECK (sequence > 0),
  event_id uuid NOT NULL DEFAULT gen_random_uuid(),
  actor_id uuid REFERENCES principals(principal_id),
  service_identity text,
  action text NOT NULL,
  target_type text NOT NULL,
  target_id text NOT NULL,
  target_revision bigint,
  outcome text NOT NULL,
  reason text,
  operation_id text NOT NULL,
  idempotency_key text,
  detail jsonb NOT NULL,
  previous_hmac char(64) NOT NULL,
  event_hmac char(64) NOT NULL,
  key_id text NOT NULL,
  database_transaction_id bigint NOT NULL DEFAULT txid_current(),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (organization_id, stream_id, epoch, sequence),
  UNIQUE (organization_id, event_id),
  FOREIGN KEY (organization_id, stream_id) REFERENCES audit_streams(organization_id, stream_id)
);

CREATE TABLE audit_checkpoints (
  organization_id uuid NOT NULL,
  stream_id uuid NOT NULL,
  epoch integer NOT NULL,
  last_sequence bigint NOT NULL,
  last_hmac char(64) NOT NULL,
  signature_algorithm text NOT NULL,
  signing_key_id text NOT NULL,
  signature text NOT NULL,
  object_bucket text NOT NULL,
  object_key text NOT NULL,
  provider_version_id text,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (organization_id, stream_id, epoch, last_sequence),
  FOREIGN KEY (organization_id, stream_id) REFERENCES audit_streams(organization_id, stream_id)
);

CREATE OR REPLACE FUNCTION reject_immutable_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'immutable records cannot be updated or deleted';
END;
$$;

CREATE TRIGGER entity_revisions_immutable BEFORE UPDATE OR DELETE ON entity_revisions
FOR EACH ROW EXECUTE FUNCTION reject_immutable_mutation();
CREATE TRIGGER artifact_versions_immutable BEFORE UPDATE OR DELETE ON artifact_versions
FOR EACH ROW EXECUTE FUNCTION reject_immutable_mutation();
CREATE TRIGGER extracted_regions_immutable BEFORE UPDATE OR DELETE ON extracted_regions
FOR EACH ROW EXECUTE FUNCTION reject_immutable_mutation();
CREATE TRIGGER audit_events_immutable BEFORE UPDATE OR DELETE ON audit_events
FOR EACH ROW EXECUTE FUNCTION reject_immutable_mutation();
CREATE TRIGGER release_revisions_immutable BEFORE UPDATE OR DELETE ON release_revisions
FOR EACH ROW EXECUTE FUNCTION reject_immutable_mutation();
CREATE TRIGGER requirement_revisions_immutable BEFORE UPDATE OR DELETE ON requirement_revisions
FOR EACH ROW EXECUTE FUNCTION reject_immutable_mutation();

CREATE OR REPLACE FUNCTION current_organization_id() RETURNS uuid
LANGUAGE sql STABLE PARALLEL SAFE AS $$
  SELECT NULLIF(current_setting('app.organization_id', true), '')::uuid
$$;

CREATE OR REPLACE FUNCTION current_principal_id() RETURNS uuid
LANGUAGE sql STABLE PARALLEL SAFE AS $$
  SELECT NULLIF(current_setting('app.principal_id', true), '')::uuid
$$;

ALTER TABLE principals ENABLE ROW LEVEL SECURITY;
ALTER TABLE principals FORCE ROW LEVEL SECURITY;
CREATE POLICY principal_membership_isolation ON principals
  USING (
    principal_id = current_principal_id()
    OR EXISTS (
      SELECT 1 FROM memberships m
      WHERE m.organization_id = current_organization_id()
        AND m.principal_id = principals.principal_id
    )
  );

ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE organizations FORCE ROW LEVEL SECURITY;
CREATE POLICY organization_isolation ON organizations
  USING (organization_id = current_organization_id())
  WITH CHECK (organization_id = current_organization_id());

DO $$
DECLARE table_name text;
BEGIN
  FOREACH table_name IN ARRAY ARRAY[
    'facilities','memberships','governed_entities','entity_revisions','dependency_revisions',
    'requirement_catalogs','requirements','requirement_revisions','requirement_conflicts',
    'retention_policies','artifacts','document_applicable_lots','artifact_versions','artifact_lot_links',
    'ingestion_requests','ingestion_attempts','extraction_runs','extracted_regions',
    'extraction_corrections','ai_runs','interpretations','ingredient_concepts',
    'ingredient_names','knowledge_assertions','assessments','releases','release_revisions','idempotency_records',
    'transaction_outbox','audit_streams','audit_events','audit_checkpoints'
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

GRANT USAGE ON SCHEMA public TO bahar_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO bahar_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO bahar_app;
REVOKE UPDATE, DELETE, TRUNCATE ON entity_revisions, artifact_versions, extracted_regions, audit_events, release_revisions, requirement_revisions FROM bahar_app;
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON organizations, principals FROM bahar_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO bahar_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO bahar_app;
"""


def upgrade() -> None:
    op.execute(DDL)


def downgrade() -> None:
    op.execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public;")
