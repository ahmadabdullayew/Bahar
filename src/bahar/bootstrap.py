from __future__ import annotations

import uuid

from sqlalchemy import create_engine, text


LOCAL_ORGANIZATION_ID = uuid.UUID("00000000-0000-4000-8000-000000000001")
LOCAL_PRINCIPAL_ID = uuid.UUID("00000000-0000-4000-8000-000000000001")


def bootstrap_local(database_admin_url: str) -> None:
    """Create the explicit local identity fixture; never called implicitly in production."""
    engine = create_engine(database_admin_url, pool_pre_ping=True)
    with engine.begin() as connection:
        connection.execute(
            text(
                """
                INSERT INTO organizations (organization_id, slug, name, state)
                VALUES (:organization_id, 'local-bahar', 'Local Bahar', 'active')
                ON CONFLICT (organization_id) DO NOTHING
                """
            ),
            {"organization_id": str(LOCAL_ORGANIZATION_ID)},
        )
        connection.execute(
            text(
                """
                INSERT INTO principals (principal_id, issuer, subject, display_name, state)
                VALUES (:principal_id, 'urn:bahar:local', 'local-release-authority',
                  'Local Release Authority', 'active')
                ON CONFLICT (principal_id) DO NOTHING
                """
            ),
            {"principal_id": str(LOCAL_PRINCIPAL_ID)},
        )
        for role in (
            "analyst", "reviewer", "regulatory_approver", "release_authority",
            "incident_manager", "auditor", "tenant_administrator",
        ):
            connection.execute(
                text(
                    """
                    INSERT INTO memberships (organization_id, principal_id, role_name)
                    VALUES (:organization_id, :principal_id, :role_name)
                    ON CONFLICT DO NOTHING
                    """
                ),
                {
                    "organization_id": str(LOCAL_ORGANIZATION_ID),
                    "principal_id": str(LOCAL_PRINCIPAL_ID), "role_name": role,
                },
            )
        for retention_class, duration_days, immutable, description in (
            ("regulatory-evidence", 3650, True, "Regulatory source and product evidence"),
            ("audit", None, True, "Audit checkpoints and validation reports"),
            ("transient-quarantine", 30, False, "Rejected and quarantined uploads"),
        ):
            connection.execute(
                text(
                    """
                    INSERT INTO retention_policies (
                      organization_id, retention_class, duration_days, immutable, description,
                      approved_by, approved_at
                    ) VALUES (
                      :organization_id, :retention_class, :duration_days, :immutable, :description,
                      :approved_by, clock_timestamp()
                    ) ON CONFLICT (organization_id, retention_class) DO NOTHING
                    """
                ),
                {
                    "organization_id": str(LOCAL_ORGANIZATION_ID), "retention_class": retention_class,
                    "duration_days": duration_days, "immutable": immutable, "description": description,
                    "approved_by": str(LOCAL_PRINCIPAL_ID),
                },
            )
    engine.dispose()
