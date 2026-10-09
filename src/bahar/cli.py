from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any

from .api import serve
from .assessment import AssessmentEngine
from .resources import load_case, load_json
from .bootstrap import bootstrap_local
from .config import ProductionSettings
from .object_store import S3ObjectStore
from .backup import create_backup, verify_backup


def read_case(path: str) -> dict[str, Any]:
    case = json.loads(Path(path).read_text(encoding="utf-8"))
    if not case.get("rules"):
        case["rules"] = load_json("az_rules.json")
    return case


def main() -> None:
    parser = argparse.ArgumentParser(prog="bahar")
    commands = parser.add_subparsers(dest="command", required=True)
    demo = commands.add_parser("demo", help="run a bundled deterministic case")
    demo.add_argument("--case", choices=("unsafe", "ready"), default="unsafe")
    assess = commands.add_parser("assess", help="assess a JSON case")
    assess.add_argument("path")
    server = commands.add_parser("serve", help="start the local web application")
    server.add_argument("--host", default="127.0.0.1")
    server.add_argument("--port", default=8088, type=int)
    server.add_argument("--database", default="bahar.sqlite3")
    commands.add_parser("bootstrap-local", help="create the explicit local identity fixture")
    commands.add_parser("provision-objects", help="create and version configured object buckets")
    backup_command = commands.add_parser("backup", help="create a database and object inventory backup")
    backup_command.add_argument("output_directory")
    verify_command = commands.add_parser("verify-backup", help="verify backup digests and optionally restore")
    verify_command.add_argument("manifest")
    verify_command.add_argument("--exercise-restore", action="store_true")
    args = parser.parse_args()

    if args.command == "serve":
        serve(args.host, args.port, args.database)
        return
    if args.command == "bootstrap-local":
        database_admin_url = os.environ.get("BAHAR_DATABASE_ADMIN_URL")
        if not database_admin_url:
            parser.error("BAHAR_DATABASE_ADMIN_URL is required")
        bootstrap_local(database_admin_url)
        return
    if args.command in {"provision-objects", "backup", "verify-backup"}:
        settings = ProductionSettings.from_environment()
        object_store = S3ObjectStore(
            endpoint_url=settings.object_endpoint,
            region=settings.object_region,
            access_key=settings.object_access_key,
            secret_key=settings.object_secret_key,
            kms_key_id=settings.object_kms_key_id,
            encryption_mode=settings.object_encryption_mode,
            client_key=settings.object_client_key,
            buckets={
                "quarantine": settings.quarantine_bucket,
                "governed": settings.governed_bucket,
                "derived": settings.derived_bucket,
                "export": settings.exports_bucket,
                "audit": settings.audit_bucket,
                "backup": os.environ.get("BAHAR_OBJECT_BUCKET_BACKUP", "bahar-backup"),
            },
        )
        if args.command == "provision-objects":
            object_store.provision()
        elif args.command == "backup":
            if not settings.database_admin_url:
                parser.error("BAHAR_DATABASE_ADMIN_URL is required")
            print(create_backup(settings.database_admin_url, object_store, Path(args.output_directory)))
        else:
            if not settings.database_admin_url:
                parser.error("BAHAR_DATABASE_ADMIN_URL is required")
            print(json.dumps(verify_backup(
                settings.database_admin_url, object_store, Path(args.manifest),
                exercise_restore=args.exercise_restore,
            ), indent=2))
        return
    if args.command == "demo":
        filename = "demo_ready_case.json" if args.case == "ready" else "demo_case.json"
        case = load_case(filename)
    else:
        case = read_case(args.path)
    result = AssessmentEngine().assess(case)
    print(json.dumps(result, ensure_ascii=False, indent=2, allow_nan=False))


if __name__ == "__main__":
    main()
