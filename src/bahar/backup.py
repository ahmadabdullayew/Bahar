from __future__ import annotations

import json
import shutil
import subprocess
import uuid
from pathlib import Path
from typing import Any

import psycopg
from psycopg import sql
from sqlalchemy.engine import make_url

from .audit import sha256_bytes, stable_bytes
from .object_store import S3ObjectStore, StoredObject


class BackupError(RuntimeError):
    pass


def _native_postgres_url(url: str, *, database: str | None = None) -> str:
    parsed = make_url(url)
    if not parsed.drivername.startswith("postgresql"):
        raise BackupError("backup requires PostgreSQL")
    parsed = parsed.set(drivername="postgresql")
    if database is not None:
        parsed = parsed.set(database=database)
    return parsed.render_as_string(hide_password=False)


def _required_program(name: str) -> str:
    program = shutil.which(name)
    if not program:
        raise BackupError(f"required PostgreSQL utility is unavailable: {name}")
    return program


def create_backup(database_admin_url: str, object_store: S3ObjectStore, output_directory: Path) -> Path:
    output_directory.mkdir(parents=True, exist_ok=False)
    database_dump = output_directory / "database.dump"
    command = [
        _required_program("pg_dump"), "--format=custom", "--no-owner", "--no-privileges",
        "--file", str(database_dump), _native_postgres_url(database_admin_url),
    ]
    completed = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, text=True)
    if completed.returncode != 0:
        raise BackupError("pg_dump failed: " + completed.stderr[-2000:])
    objects: list[dict[str, Any]] = []
    for storage_class, bucket in sorted(object_store.buckets.items()):
        paginator = object_store.client.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=bucket):
            for item in page.get("Versions", []):
                head = object_store.client.head_object(
                    Bucket=bucket, Key=item["Key"], VersionId=item["VersionId"]
                )
                metadata = head.get("Metadata", {})
                if not metadata.get("lg-sha256") or not metadata.get("lg-plain-length"):
                    raise BackupError(f"unmanaged object found in governed bucket: {bucket}/{item['Key']}")
                reference = StoredObject(
                    bucket, item["Key"], item["VersionId"], int(metadata["lg-plain-length"]),
                    metadata["lg-sha256"], metadata.get("lg-encryption", "unknown"),
                    object_store.kms_key_id, item["LastModified"].isoformat(),
                )
                object_store.read(reference)
                objects.append({
                    "storage_class": storage_class,
                    "bucket": bucket,
                    "key": item["Key"],
                    "version_id": item["VersionId"],
                    "byte_length": reference.byte_length,
                    "sha256": reference.sha256,
                    "encryption_method": reference.encryption_method,
                })
    manifest = {
        "format": "bahar-backup-manifest-v1",
        "database_dump": {"file": database_dump.name, "sha256": sha256_bytes(database_dump.read_bytes())},
        "objects": objects,
    }
    manifest["manifest_sha256"] = sha256_bytes(stable_bytes(manifest))
    manifest_path = output_directory / "manifest.json"
    manifest_path.write_bytes(stable_bytes(manifest))
    return manifest_path


def verify_backup(
    database_admin_url: str,
    object_store: S3ObjectStore,
    manifest_path: Path,
    *,
    exercise_restore: bool = False,
) -> dict[str, Any]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    claimed_manifest_digest = manifest.pop("manifest_sha256", None)
    if claimed_manifest_digest != sha256_bytes(stable_bytes(manifest)):
        raise BackupError("backup manifest digest mismatch")
    if manifest.get("format") != "bahar-backup-manifest-v1":
        raise BackupError("unsupported backup manifest format")
    dump_path = manifest_path.parent / manifest["database_dump"]["file"]
    if sha256_bytes(dump_path.read_bytes()) != manifest["database_dump"]["sha256"]:
        raise BackupError("database dump digest mismatch")
    listing = subprocess.run(
        [_required_program("pg_restore"), "--list", str(dump_path)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, text=True,
    )
    if listing.returncode != 0:
        raise BackupError("database archive validation failed: " + listing.stderr[-2000:])
    checked_objects = 0
    for item in manifest["objects"]:
        reference = StoredObject(
            item["bucket"], item["key"], item["version_id"], int(item["byte_length"]),
            item["sha256"], item["encryption_method"], object_store.kms_key_id, "",
        )
        object_store.read(reference)
        checked_objects += 1
    restore_report: dict[str, Any] | None = None
    if exercise_restore:
        restore_report = _exercise_database_restore(database_admin_url, dump_path)
    return {
        "valid": True,
        "database_archive_entries": len(listing.stdout.splitlines()),
        "verified_object_versions": checked_objects,
        "restore": restore_report,
    }


def _exercise_database_restore(database_admin_url: str, dump_path: Path) -> dict[str, Any]:
    database_name = "bahar_restore_test_" + uuid.uuid4().hex
    maintenance_url = _native_postgres_url(database_admin_url, database="postgres")
    with psycopg.connect(maintenance_url, autocommit=True) as connection:
        connection.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(database_name)))
    try:
        restore_url = _native_postgres_url(database_admin_url, database=database_name)
        restored = subprocess.run(
            [_required_program("pg_restore"), "--exit-on-error", "--no-owner", "--no-privileges",
             "--dbname", restore_url, str(dump_path)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, text=True,
        )
        if restored.returncode != 0:
            raise BackupError("restore exercise failed: " + restored.stderr[-2000:])
        with psycopg.connect(restore_url) as connection:
            organizations = connection.execute("SELECT count(*) FROM organizations").fetchone()[0]
            audit_events = connection.execute("SELECT count(*) FROM audit_events").fetchone()[0]
        return {"database": database_name, "organizations": organizations, "audit_events": audit_events}
    finally:
        with psycopg.connect(maintenance_url, autocommit=True) as connection:
            connection.execute(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = %s",
                (database_name,),
            )
            connection.execute(sql.SQL("DROP DATABASE IF EXISTS {}").format(sql.Identifier(database_name)))
