from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sqlalchemy import text

from .audit import sha256_bytes, stable_bytes


REQUIREMENT_ID = re.compile(r"^LG-[A-Z]{3}-\d{3}$")
BULLET = re.compile(r"^- \*\*(LG-[A-Z]{3}-\d{3})(?: \[([^]]+)\])?\*\*\s+[—-]\s+(.+?)\s*$")
TABLE = re.compile(r"^\|\s*(LG-[A-Z]{3}-\d{3})\s*\|\s*(.+?)\s*\|\s*$")


class RequirementCatalogError(RuntimeError):
    pass


@dataclass(frozen=True)
class RequirementRecord:
    requirement_id: str
    description: str
    origin: str
    rationale: str
    authority: str
    priority: str
    applicability: dict[str, Any]
    dependencies: tuple[str, ...] = ()
    acceptance_predicate: str | None = None
    verification_method: str | None = None
    implementation_components: tuple[str, ...] = ()
    test_references: tuple[str, ...] = ()
    evidence_references: tuple[str, ...] = ()
    exclusion_reason: str | None = None
    source_locator: str = ""
    source_sha256: str = ""
    status: str = "proposed"
    revision: int = 1

    def validate(self) -> None:
        if not REQUIREMENT_ID.fullmatch(self.requirement_id):
            raise RequirementCatalogError(f"invalid requirement id: {self.requirement_id}")
        if not self.description.strip() or not self.origin.strip() or not self.authority.strip():
            raise RequirementCatalogError(f"{self.requirement_id}: description, origin, and authority are required")
        if self.status in {"approved", "implemented", "verified", "excluded"} and (
            (self.acceptance_predicate is None or self.verification_method is None)
            and self.exclusion_reason is None
        ):
            raise RequirementCatalogError(
                f"{self.requirement_id}: executable acceptance or an explicit exclusion is required"
            )
        if self.status == "verified" and not self.evidence_references:
            raise RequirementCatalogError(f"{self.requirement_id}: verified status requires evidence")
        for dependency in self.dependencies:
            if not REQUIREMENT_ID.fullmatch(dependency):
                raise RequirementCatalogError(f"{self.requirement_id}: invalid dependency {dependency}")


@dataclass
class RequirementCatalog:
    slug: str
    version: str
    records: dict[str, list[RequirementRecord]] = field(default_factory=dict)
    conflicts: list[dict[str, str]] = field(default_factory=list)

    def add(self, record: RequirementRecord) -> None:
        record.validate()
        revisions = self.records.setdefault(record.requirement_id, [])
        if revisions and record.revision != revisions[-1].revision + 1:
            raise RequirementCatalogError(f"{record.requirement_id}: revision is not sequential")
        if not revisions and record.revision != 1:
            raise RequirementCatalogError(f"{record.requirement_id}: first revision must be 1")
        revisions.append(record)

    def register_conflict(
        self, left: str, right: str, *, conflict_kind: str, analysis: str, resolution: str | None = None
    ) -> None:
        if left == right or left not in self.records or right not in self.records:
            raise RequirementCatalogError("conflict endpoints must be two distinct catalog requirements")
        self.conflicts.append({
            "left": left, "right": right, "kind": conflict_kind,
            "analysis": analysis, "resolution": resolution or "",
        })

    def coverage(self) -> dict[str, Any]:
        latest = [revisions[-1] for revisions in self.records.values()]
        accepted = [
            record for record in latest
            if (record.acceptance_predicate and record.verification_method) or record.exclusion_reason
        ]
        evidenced = [record for record in latest if record.status != "verified" or record.evidence_references]
        unresolved_conflicts = [item for item in self.conflicts if not item["resolution"]]
        return {
            "total": len(latest),
            "acceptance_or_exclusion_complete": len(accepted),
            "evidence_status_consistent": len(evidenced),
            "unresolved_conflicts": len(unresolved_conflicts),
            "complete": len(accepted) == len(latest) and len(evidenced) == len(latest) and not unresolved_conflicts,
        }


def parse_markdown_requirements(path: Path) -> dict[str, dict[str, str]]:
    raw = path.read_bytes()
    source_digest = sha256_bytes(raw)
    parsed: dict[str, dict[str, str]] = {}
    for line_number, line in enumerate(raw.decode("utf-8").splitlines(), 1):
        match = BULLET.match(line) or TABLE.match(line)
        if not match:
            continue
        requirement_id = match.group(1)
        if match.re is BULLET:
            priority = match.group(2) or "unassigned"
            description = match.group(3)
        else:
            priority = "unassigned"
            description = match.group(2)
            if description.casefold().startswith(("revised binding requirement", "requirement")):
                continue
        description = re.sub(r"\s+", " ", description).strip()
        current = parsed.get(requirement_id)
        if current and current["description"] != description:
            raise RequirementCatalogError(
                f"contradictory duplicate {requirement_id} at {path}:{line_number}"
            )
        parsed[requirement_id] = {
            "description": description,
            "priority": priority,
            "source_locator": f"{path}:{line_number}",
            "source_sha256": source_digest,
        }
    return parsed


def staged_catalog_from_markdown(path: Path, *, slug: str, version: str) -> RequirementCatalog:
    catalog = RequirementCatalog(slug, version)
    for requirement_id, value in sorted(parse_markdown_requirements(path).items()):
        catalog.add(RequirementRecord(
            requirement_id=requirement_id,
            description=value["description"],
            origin="requirements audit source document",
            rationale="pending approved traceability metadata",
            authority="unassigned",
            priority=value["priority"],
            applicability={"state": "pending_scope_decision"},
            source_locator=value["source_locator"],
            source_sha256=value["source_sha256"],
            status="proposed",
        ))
    return catalog


class PostgresRequirementRepository:
    def __init__(self, store: Any) -> None:
        self.store = store

    def save_catalog(self, catalog: RequirementCatalog) -> str:
        if not catalog.records:
            raise RequirementCatalogError("empty requirement catalogs are not accepted")
        source_digests = {revision.source_sha256 for revisions in catalog.records.values() for revision in revisions}
        catalog_digest = sha256_bytes(stable_bytes(sorted(source_digests)))
        catalog_id = str(__import__("uuid").uuid4())
        organization_id = str(self.store.context.organization_id)
        with self.store.transaction(serializable=True) as connection:
            connection.execute(
                text(
                    """
                    INSERT INTO requirement_catalogs (
                      organization_id, catalog_id, slug, catalog_version, source_sha256
                    ) VALUES (
                      :organization_id, :catalog_id, :slug, :catalog_version, :source_sha256
                    )
                    """
                ),
                {
                    "organization_id": organization_id, "catalog_id": catalog_id,
                    "slug": catalog.slug, "catalog_version": catalog.version,
                    "source_sha256": catalog_digest,
                },
            )
            for requirement_id, revisions in sorted(catalog.records.items()):
                current = revisions[-1]
                connection.execute(
                    text(
                        """
                        INSERT INTO requirements (
                          organization_id, catalog_id, requirement_id, current_revision, status
                        ) VALUES (
                          :organization_id, :catalog_id, :requirement_id, :current_revision, :status
                        )
                        """
                    ),
                    {
                        "organization_id": organization_id, "catalog_id": catalog_id,
                        "requirement_id": requirement_id, "current_revision": current.revision,
                        "status": current.status,
                    },
                )
                for revision in revisions:
                    connection.execute(
                        text(
                            """
                            INSERT INTO requirement_revisions (
                              organization_id, catalog_id, requirement_id, revision, description,
                              origin, rationale, authority, priority, applicability, dependencies,
                              acceptance_predicate, verification_method, implementation_components,
                              test_references, evidence_references, exclusion_reason, source_locator,
                              source_sha256, created_by
                            ) VALUES (
                              :organization_id, :catalog_id, :requirement_id, :revision, :description,
                              :origin, :rationale, :authority, :priority, CAST(:applicability AS jsonb),
                              :dependencies, :acceptance_predicate, :verification_method,
                              :implementation_components, :test_references, :evidence_references,
                              :exclusion_reason, :source_locator, :source_sha256, :created_by
                            )
                            """
                        ),
                        {
                            "organization_id": organization_id, "catalog_id": catalog_id,
                            "requirement_id": revision.requirement_id, "revision": revision.revision,
                            "description": revision.description, "origin": revision.origin,
                            "rationale": revision.rationale, "authority": revision.authority,
                            "priority": revision.priority,
                            "applicability": stable_bytes(revision.applicability).decode("utf-8"),
                            "dependencies": list(revision.dependencies),
                            "acceptance_predicate": revision.acceptance_predicate,
                            "verification_method": revision.verification_method,
                            "implementation_components": list(revision.implementation_components),
                            "test_references": list(revision.test_references),
                            "evidence_references": list(revision.evidence_references),
                            "exclusion_reason": revision.exclusion_reason,
                            "source_locator": revision.source_locator,
                            "source_sha256": revision.source_sha256,
                            "created_by": str(self.store.context.principal_id),
                        },
                    )
            for conflict in catalog.conflicts:
                connection.execute(
                    text(
                        """
                        INSERT INTO requirement_conflicts (
                          organization_id, catalog_id, left_requirement_id, right_requirement_id,
                          conflict_kind, analysis, resolution, resolved_by, resolved_at
                        ) VALUES (
                          :organization_id, :catalog_id, :left_requirement_id, :right_requirement_id,
                          :conflict_kind, :analysis, NULLIF(:resolution, ''),
                          CASE WHEN :resolution = '' THEN NULL ELSE :resolved_by END,
                          CASE WHEN :resolution = '' THEN NULL ELSE clock_timestamp() END
                        )
                        """
                    ),
                    {
                        "organization_id": organization_id, "catalog_id": catalog_id,
                        "left_requirement_id": conflict["left"],
                        "right_requirement_id": conflict["right"],
                        "conflict_kind": conflict["kind"], "analysis": conflict["analysis"],
                        "resolution": conflict["resolution"],
                        "resolved_by": str(self.store.context.principal_id),
                    },
                )
            self.store._audit(
                connection, action="requirement_catalog_imported", target_type="requirement_catalog",
                target_id=catalog_id, target_revision=1, outcome="success",
                reason="versioned requirement catalog import",
                operation_id=f"requirements:{catalog.slug}:{catalog.version}",
                detail={"requirements": len(catalog.records), "source_sha256": catalog_digest},
            )
        return catalog_id
