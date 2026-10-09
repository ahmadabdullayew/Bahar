"""Read-only external-identity-to-membership lookup and reviewed decisions.

Provision principals and memberships using a separately authorized tenant-admin
process. Never let bearer claim contents or the client create memberships.
"""
from alembic import op
revision='0004_oidc_actor_lookup'
down_revision='0003_operational_assurance'
branch_labels=None
depends_on=None

DDL=r'''
CREATE OR REPLACE FUNCTION public.auth_actor_memberships(p_issuer text, p_subject text)
RETURNS TABLE (organization_id uuid, principal_id uuid, role_name text, facility_id uuid)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $body$
    SELECT m.organization_id, p.principal_id, m.role_name, m.facility_id
    FROM public.principals p
    INNER JOIN public.memberships m ON m.principal_id=p.principal_id
    INNER JOIN public.organizations o ON o.organization_id=m.organization_id
    LEFT JOIN public.facilities f ON f.facility_id=m.facility_id AND f.organization_id=m.organization_id
    WHERE p.issuer=p_issuer AND p.subject=p_subject
      AND p.state='active' AND o.state='active'
      AND (m.facility_id IS NULL OR f.state='active')
      AND m.valid_from <= clock_timestamp()
      AND (m.valid_until IS NULL OR m.valid_until>clock_timestamp())
$body$;
REVOKE ALL ON FUNCTION public.auth_actor_memberships(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.auth_actor_memberships(text,text) TO bahar_app;

CREATE TABLE public.review_assignments (
  organization_id uuid NOT NULL REFERENCES organizations(organization_id),
  assessment_key text NOT NULL, reviewer_id uuid NOT NULL REFERENCES principals(principal_id),
  assigned_by uuid NOT NULL REFERENCES principals(principal_id),
  assigned_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  assignment_reason text NOT NULL,
  PRIMARY KEY (organization_id, assessment_key)
);
CREATE TABLE public.review_decisions (
  organization_id uuid NOT NULL REFERENCES organizations(organization_id),
  decision_id uuid NOT NULL DEFAULT gen_random_uuid(),
  assessment_key text NOT NULL,
  reviewer_id uuid NOT NULL REFERENCES principals(principal_id),
  verdict text NOT NULL CHECK (verdict IN ('accepted_for_review','rejected','needs_changes')),
  reason text NOT NULL,
  assessment_digest text NOT NULL,
  decided_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (organization_id, decision_id),
  FOREIGN KEY (organization_id, assessment_key) REFERENCES review_assignments(organization_id,assessment_key)
);
CREATE TABLE public.regulatory_review_decisions (
  organization_id uuid NOT NULL REFERENCES organizations(organization_id),
  decision_id uuid NOT NULL DEFAULT gen_random_uuid(),
  assessment_key text NOT NULL,
  approver_id uuid NOT NULL REFERENCES principals(principal_id),
  verdict text NOT NULL CHECK (verdict IN ('approved_for_further_release_checks','rejected')),
  reason text NOT NULL,
  assessment_digest text NOT NULL,
  decided_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (organization_id, decision_id),
  FOREIGN KEY (organization_id, assessment_key) REFERENCES review_assignments(organization_id,assessment_key)
);
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['review_assignments','review_decisions','regulatory_review_decisions'] LOOP
    EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY',t);
    EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY',t);
    EXECUTE format('CREATE POLICY tenant_isolation ON public.%I USING (organization_id=public.current_organization_id()) WITH CHECK (organization_id=public.current_organization_id())',t);
    EXECUTE format('GRANT SELECT,INSERT ON public.%I TO bahar_app',t);
    EXECUTE format('REVOKE UPDATE,DELETE,TRUNCATE ON public.%I FROM bahar_app',t);
  END LOOP;
END $$;
'''

def upgrade():op.execute(DDL)
def downgrade():
    op.execute('DROP TABLE IF EXISTS regulatory_review_decisions,review_decisions,review_assignments; DROP FUNCTION IF EXISTS public.auth_actor_memberships(text,text);')
