"""Operational evidence events and scoped review decisions F39-F48.

Revision ID: 0003_operational_assurance
Revises: 0002_supply_chain_operations
"""
from alembic import op
revision = '0003_operational_assurance'
down_revision = '0002_supply_chain_operations'
branch_labels = None
depends_on = None


def upgrade():
    op.execute(r"""
    CREATE TABLE operational_assurance_events (
      organization_id uuid NOT NULL REFERENCES organizations(organization_id),
      record_key text NOT NULL CHECK (length(record_key) BETWEEN 1 AND 256),
      revision bigint NOT NULL CHECK (revision > 0),
      kind text NOT NULL CHECK (length(kind) BETWEEN 1 AND 100),
      body jsonb NOT NULL,
      body_sha256 char(64) NOT NULL CHECK (body_sha256 ~ '^[0-9a-f]{64}$'),
      actor_id uuid NOT NULL REFERENCES principals(principal_id),
      operation_id text NOT NULL,
      created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
      PRIMARY KEY (organization_id, record_key, revision),
      UNIQUE (organization_id, operation_id)
    );
    CREATE INDEX operational_assurance_by_kind ON operational_assurance_events
        (organization_id, kind, created_at);
    CREATE TRIGGER operational_assurance_immutable BEFORE UPDATE OR DELETE
        ON operational_assurance_events FOR EACH ROW EXECUTE FUNCTION reject_immutable_mutation();
    ALTER TABLE operational_assurance_events ENABLE ROW LEVEL SECURITY;
    ALTER TABLE operational_assurance_events FORCE ROW LEVEL SECURITY;
    CREATE POLICY tenant_isolation ON operational_assurance_events
        USING (organization_id = current_organization_id())
        WITH CHECK (organization_id = current_organization_id());
    REVOKE UPDATE, DELETE, TRUNCATE ON operational_assurance_events FROM bahar_app;
    """)


def downgrade():
    op.execute('DROP TABLE IF EXISTS operational_assurance_events CASCADE')
