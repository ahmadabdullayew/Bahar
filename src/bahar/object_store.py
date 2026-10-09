from __future__ import annotations

import base64
import hashlib
import io
import os
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Protocol

import boto3
from botocore.client import Config
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .audit import sha256_bytes


class ObjectStoreError(RuntimeError):
    pass


class IntegrityError(ObjectStoreError):
    pass


@dataclass(frozen=True)
class StoredObject:
    bucket: str
    key: str
    version_id: str | None
    byte_length: int
    sha256: str
    encryption_method: str
    encryption_key_id: str
    created_at: str


class ArtifactStore(Protocol):
    def put(self, storage_class: str, data: bytes, *, media_type: str, retention_class: str) -> StoredObject: ...
    def read(self, reference: StoredObject) -> bytes: ...


class MemoryObjectStore:
    """Deterministic test store with the same digest-on-read custody check."""

    def __init__(self) -> None:
        self.objects: dict[tuple[str, str, str | None], bytes] = {}

    def put(self, storage_class: str, data: bytes, *, media_type: str, retention_class: str) -> StoredObject:
        del media_type, retention_class
        key = f"{storage_class}/{uuid.uuid4()}"
        version = str(uuid.uuid4())
        self.objects[(storage_class, key, version)] = bytes(data)
        return StoredObject(
            storage_class, key, version, len(data), sha256_bytes(data), "memory-test", "memory-test",
            datetime.now(timezone.utc).isoformat(),
        )

    def read(self, reference: StoredObject) -> bytes:
        try:
            data = self.objects[(reference.bucket, reference.key, reference.version_id)]
        except KeyError as exc:
            raise ObjectStoreError("object is missing") from exc
        if sha256_bytes(data) != reference.sha256:
            raise IntegrityError("stored object digest mismatch")
        return data


class S3ObjectStore:
    """Versioned S3 custody store with KMS or client-side AES-256-GCM.

    ``aws-kms`` is the production mode. ``client-aesgcm`` exists so a local
    MinIO deployment still stores only authenticated ciphertext without a KMS.
    The client key must be delivered by a secret manager, never stored beside
    the objects or embedded in object metadata.
    """

    def __init__(
        self,
        *,
        endpoint_url: str,
        region: str,
        access_key: str,
        secret_key: str,
        kms_key_id: str,
        buckets: dict[str, str],
        encryption_mode: str = "aws-kms",
        client_key: bytes | None = None,
    ) -> None:
        if encryption_mode not in {"aws-kms", "client-aesgcm"}:
            raise ObjectStoreError("unsupported object encryption mode")
        if encryption_mode == "client-aesgcm" and (client_key is None or len(client_key) < 32):
            raise ObjectStoreError("client AES-GCM mode requires at least 32 bytes of secret key material")
        required = {"quarantine", "governed", "derived", "export", "audit", "backup"}
        if set(buckets) != required or any(not value for value in buckets.values()):
            raise ObjectStoreError("an explicit bucket is required for every storage class")
        self.buckets = dict(buckets)
        self.kms_key_id = kms_key_id
        self.encryption_mode = encryption_mode
        self._client_key = hashlib.sha256(client_key).digest() if client_key else None
        self.client = boto3.client(
            "s3",
            endpoint_url=endpoint_url,
            region_name=region,
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            config=Config(signature_version="s3v4", s3={"addressing_style": "path"}),
        )

    def provision(self) -> None:
        existing = {item["Name"] for item in self.client.list_buckets().get("Buckets", [])}
        for bucket in sorted(set(self.buckets.values())):
            if bucket not in existing:
                self.client.create_bucket(Bucket=bucket)
            self.client.put_bucket_versioning(
                Bucket=bucket, VersioningConfiguration={"Status": "Enabled"}
            )

    def _encrypt(self, plaintext: bytes) -> tuple[bytes, dict[str, str], dict[str, object]]:
        if self.encryption_mode == "aws-kms":
            return plaintext, {}, {
                "ServerSideEncryption": "aws:kms",
                "SSEKMSKeyId": self.kms_key_id,
                "BucketKeyEnabled": True,
            }
        assert self._client_key is not None
        nonce = os.urandom(12)
        ciphertext = AESGCM(self._client_key).encrypt(nonce, plaintext, None)
        return ciphertext, {"lg-nonce": base64.b64encode(nonce).decode("ascii")}, {}

    def put(self, storage_class: str, data: bytes, *, media_type: str, retention_class: str) -> StoredObject:
        if storage_class not in self.buckets:
            raise ObjectStoreError(f"unknown storage class: {storage_class}")
        digest = sha256_bytes(data)
        key = f"{datetime.now(timezone.utc):%Y/%m/%d}/{uuid.uuid4()}"
        stored, encryption_metadata, encryption_args = self._encrypt(data)
        metadata = {
            "lg-sha256": digest,
            "lg-plain-length": str(len(data)),
            "lg-retention-class": retention_class,
            "lg-encryption": self.encryption_mode,
            **encryption_metadata,
        }
        response = self.client.put_object(
            Bucket=self.buckets[storage_class], Key=key, Body=io.BytesIO(stored),
            ContentType=media_type, Metadata=metadata, **encryption_args,
        )
        return StoredObject(
            bucket=self.buckets[storage_class], key=key, version_id=response.get("VersionId"),
            byte_length=len(data), sha256=digest, encryption_method=self.encryption_mode,
            encryption_key_id=self.kms_key_id,
            created_at=datetime.now(timezone.utc).isoformat(),
        )

    def read(self, reference: StoredObject) -> bytes:
        arguments: dict[str, str] = {"Bucket": reference.bucket, "Key": reference.key}
        if reference.version_id:
            arguments["VersionId"] = reference.version_id
        response = self.client.get_object(**arguments)
        payload = response["Body"].read()
        metadata = response.get("Metadata", {})
        if metadata.get("lg-encryption") == "client-aesgcm":
            if self._client_key is None:
                raise ObjectStoreError("client decryption key is unavailable")
            try:
                nonce = base64.b64decode(metadata["lg-nonce"], validate=True)
                payload = AESGCM(self._client_key).decrypt(nonce, payload, None)
            except Exception as exc:
                raise IntegrityError("object authentication or decryption failed") from exc
        if len(payload) != reference.byte_length or sha256_bytes(payload) != reference.sha256:
            raise IntegrityError("stored object digest or length mismatch")
        return payload
