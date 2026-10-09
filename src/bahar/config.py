from __future__ import annotations

import os
from dataclasses import dataclass


class ConfigurationError(RuntimeError):
    pass


def _positive_int(name: str, default: int) -> int:
    raw = os.environ.get(name, str(default))
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigurationError(f"{name} must be an integer") from exc
    if value <= 0:
        raise ConfigurationError(f"{name} must be positive")
    return value


@dataclass(frozen=True)
class ProductionSettings:
    database_url: str
    database_admin_url: str | None
    object_endpoint: str
    object_region: str
    object_access_key: str
    object_secret_key: str
    object_kms_key_id: str
    object_encryption_mode: str
    object_client_key: bytes | None
    quarantine_bucket: str
    governed_bucket: str
    derived_bucket: str
    exports_bucket: str
    audit_bucket: str
    audit_hmac_key: bytes
    clamd_host: str
    clamd_port: int
    tesseract_languages: str
    max_upload_bytes: int
    max_pages: int
    max_expanded_bytes: int
    max_expansion_ratio: int

    @classmethod
    def from_environment(cls) -> "ProductionSettings":
        required = {
            "BAHAR_DATABASE_URL": os.environ.get("BAHAR_DATABASE_URL"),
            "BAHAR_OBJECT_ENDPOINT": os.environ.get("BAHAR_OBJECT_ENDPOINT"),
            "BAHAR_OBJECT_ACCESS_KEY": os.environ.get("BAHAR_OBJECT_ACCESS_KEY"),
            "BAHAR_OBJECT_SECRET_KEY": os.environ.get("BAHAR_OBJECT_SECRET_KEY"),
            "BAHAR_OBJECT_KMS_KEY_ID": os.environ.get("BAHAR_OBJECT_KMS_KEY_ID"),
            "BAHAR_AUDIT_HMAC_KEY": os.environ.get("BAHAR_AUDIT_HMAC_KEY"),
        }
        missing = [name for name, value in required.items() if not value]
        if missing:
            raise ConfigurationError("missing production settings: " + ", ".join(sorted(missing)))
        key = str(required["BAHAR_AUDIT_HMAC_KEY"]).encode("utf-8")
        if len(key) < 32:
            raise ConfigurationError("BAHAR_AUDIT_HMAC_KEY must contain at least 32 bytes")
        encryption_mode = os.environ.get("BAHAR_OBJECT_ENCRYPTION_MODE", "aws-kms")
        if encryption_mode not in {"aws-kms", "client-aesgcm"}:
            raise ConfigurationError("BAHAR_OBJECT_ENCRYPTION_MODE must be aws-kms or client-aesgcm")
        client_key_text = os.environ.get("BAHAR_OBJECT_CLIENT_KEY")
        if encryption_mode == "client-aesgcm" and (not client_key_text or len(client_key_text.encode()) < 32):
            raise ConfigurationError("BAHAR_OBJECT_CLIENT_KEY must contain at least 32 bytes")
        return cls(
            database_url=str(required["BAHAR_DATABASE_URL"]),
            database_admin_url=os.environ.get("BAHAR_DATABASE_ADMIN_URL"),
            object_endpoint=str(required["BAHAR_OBJECT_ENDPOINT"]),
            object_region=os.environ.get("BAHAR_OBJECT_REGION", "us-east-1"),
            object_access_key=str(required["BAHAR_OBJECT_ACCESS_KEY"]),
            object_secret_key=str(required["BAHAR_OBJECT_SECRET_KEY"]),
            object_kms_key_id=str(required["BAHAR_OBJECT_KMS_KEY_ID"]),
            object_encryption_mode=encryption_mode,
            object_client_key=client_key_text.encode("utf-8") if client_key_text else None,
            quarantine_bucket=os.environ.get("BAHAR_OBJECT_BUCKET_QUARANTINE", "bahar-quarantine"),
            governed_bucket=os.environ.get("BAHAR_OBJECT_BUCKET_GOVERNED", "bahar-governed"),
            derived_bucket=os.environ.get("BAHAR_OBJECT_BUCKET_DERIVED", "bahar-derived"),
            exports_bucket=os.environ.get("BAHAR_OBJECT_BUCKET_EXPORTS", "bahar-exports"),
            audit_bucket=os.environ.get("BAHAR_OBJECT_BUCKET_AUDIT", "bahar-audit"),
            audit_hmac_key=key,
            clamd_host=os.environ.get("BAHAR_CLAMD_HOST", "127.0.0.1"),
            clamd_port=_positive_int("BAHAR_CLAMD_PORT", 3310),
            tesseract_languages=os.environ.get("BAHAR_TESSERACT_LANGUAGES", "aze+eng+rus"),
            max_upload_bytes=_positive_int("BAHAR_MAX_UPLOAD_BYTES", 100 * 1024 * 1024),
            max_pages=_positive_int("BAHAR_MAX_PAGES", 1000),
            max_expanded_bytes=_positive_int("BAHAR_MAX_EXPANDED_BYTES", 500 * 1024 * 1024),
            max_expansion_ratio=_positive_int("BAHAR_MAX_EXPANSION_RATIO", 100),
        )
