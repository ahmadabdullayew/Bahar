from __future__ import annotations

import csv
import io
import json
import socket
import struct
import uuid
import zipfile
from dataclasses import asdict, dataclass, field
from datetime import date, datetime, timezone
from pathlib import PurePosixPath
from typing import Any, Protocol

import pymupdf as fitz
from openpyxl import load_workbook

from .object_store import ArtifactStore, StoredObject
from .audit import stable_bytes
from sqlalchemy import text


class IngestionError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class IngestionLimits:
    max_upload_bytes: int = 100 * 1024 * 1024
    max_pages: int = 1000
    max_archive_entries: int = 10_000
    max_expanded_bytes: int = 500 * 1024 * 1024
    max_expansion_ratio: int = 100
    max_csv_rows: int = 1_000_000
    max_cell_characters: int = 1_000_000


@dataclass(frozen=True)
class DocumentMetadata:
    document_identity: str
    version: str
    supplier_id: str | None
    scope: dict[str, Any]
    signature_state: str
    valid_from: date | None
    valid_until: date | None
    applicable_lots: tuple[str, ...] = ()
    retention_class: str = "regulatory-evidence"

    def validate(self) -> None:
        if not self.document_identity.strip() or not self.version.strip():
            raise IngestionError("METADATA_INVALID", "document identity and version are required")
        if self.valid_from and self.valid_until and self.valid_until <= self.valid_from:
            raise IngestionError("METADATA_INVALID", "valid_until must be later than valid_from")
        if self.signature_state not in {"not_evaluated", "unsigned", "valid", "invalid", "unknown"}:
            raise IngestionError("METADATA_INVALID", "invalid signature state")
        if len(set(self.applicable_lots)) != len(self.applicable_lots):
            raise IngestionError("METADATA_INVALID", "applicable lots must be unique")


@dataclass(frozen=True)
class ScanResult:
    clean: bool
    engine: str
    engine_version: str
    signature: str | None = None


class MalwareScanner(Protocol):
    def scan(self, data: bytes) -> ScanResult: ...


class ClamdScanner:
    def __init__(self, host: str, port: int, *, timeout_seconds: float = 30.0) -> None:
        self.host = host
        self.port = port
        self.timeout_seconds = timeout_seconds

    def scan(self, data: bytes) -> ScanResult:
        try:
            with socket.create_connection((self.host, self.port), self.timeout_seconds) as connection:
                connection.settimeout(self.timeout_seconds)
                connection.sendall(b"zINSTREAM\0")
                for offset in range(0, len(data), 64 * 1024):
                    chunk = data[offset : offset + 64 * 1024]
                    connection.sendall(struct.pack("!I", len(chunk)) + chunk)
                connection.sendall(struct.pack("!I", 0))
                response = bytearray()
                while not response.endswith(b"\0") and len(response) < 16_384:
                    block = connection.recv(4096)
                    if not block:
                        break
                    response.extend(block)
        except (OSError, TimeoutError) as exc:
            raise IngestionError("MALWARE_SCANNER_UNAVAILABLE", "malware scanner unavailable") from exc
        text = response.rstrip(b"\0\n").decode("utf-8", "replace")
        if text.endswith(" OK"):
            return ScanResult(True, "clamd", "remote")
        if text.endswith(" FOUND"):
            signature = text.rsplit(": ", 1)[-1].removesuffix(" FOUND")
            return ScanResult(False, "clamd", "remote", signature)
        raise IngestionError("MALWARE_SCANNER_ERROR", f"unrecognized scanner response: {text[:200]}")


class FixedScanner:
    """Explicit test double; never selected by production configuration."""

    def __init__(self, *, clean: bool = True, signature: str | None = None) -> None:
        self.clean = clean
        self.signature = signature

    def scan(self, data: bytes) -> ScanResult:
        del data
        return ScanResult(self.clean, "fixed-test-scanner", "1", self.signature)


@dataclass
class IngestionRecord:
    ingestion_id: str
    state: str
    filename: str
    claimed_media_type: str | None
    detected_media_type: str | None
    metadata: DocumentMetadata
    quarantine_object: StoredObject | None = None
    governed_object: StoredObject | None = None
    failure_code: str | None = None
    events: list[dict[str, Any]] = field(default_factory=list)


class InMemoryIngestionRepository:
    def __init__(self) -> None:
        self.records: dict[str, IngestionRecord] = {}
        self.accepted_facts: list[dict[str, Any]] = []

    def create(self, record: IngestionRecord) -> None:
        self.records[record.ingestion_id] = record

    def transition(self, ingestion_id: str, state: str, **detail: Any) -> None:
        record = self.records[ingestion_id]
        record.state = state
        record.events.append({
            "state": state,
            "detail": detail,
            "at": datetime.now(timezone.utc).isoformat(),
        })
        if "failure_code" in detail:
            record.failure_code = detail["failure_code"]

    def accept(self, ingestion_id: str, fact: dict[str, Any]) -> None:
        if self.records[ingestion_id].state != "accepted":
            raise IngestionError("STATE_VIOLATION", "facts can only be recorded after acceptance")
        self.accepted_facts.append(fact)


class IngestionRepository(Protocol):
    def create(self, record: IngestionRecord) -> None: ...
    def transition(self, ingestion_id: str, state: str, **detail: Any) -> None: ...
    def accept(self, ingestion_id: str, fact: dict[str, Any]) -> None: ...


class PostgresIngestionRepository:
    """Transactional custody metadata repository bound to a tenant-scoped store."""

    def __init__(self, postgres_store: Any) -> None:
        self.store = postgres_store
        self.records: dict[str, IngestionRecord] = {}
        self._identifiers: dict[str, tuple[uuid.UUID, int]] = {}
        self._attempts: dict[str, int] = {}

    def create(self, record: IngestionRecord) -> None:
        if record.quarantine_object is None:
            raise IngestionError("STATE_VIOLATION", "quarantine object must exist before database custody")
        organization_id = str(self.store.context.organization_id)
        artifact_id = uuid.uuid5(
            self.store.context.organization_id,
            f"artifact:{record.metadata.document_identity}:{record.metadata.supplier_id or ''}",
        )
        with self.store.transaction(serializable=True) as connection:
            current_version = connection.execute(
                text(
                    """
                    SELECT current_version FROM artifacts
                    WHERE organization_id = :organization_id AND artifact_id = :artifact_id
                    FOR UPDATE
                    """
                ),
                {"organization_id": organization_id, "artifact_id": str(artifact_id)},
            ).scalar_one_or_none()
            version = int(current_version or 0) + 1
            if current_version is None:
                connection.execute(
                    text(
                        """
                        INSERT INTO artifacts (
                          organization_id, artifact_id, artifact_type, document_identity,
                          declared_version, document_scope, supplier_identifier, current_version,
                          created_by
                        ) VALUES (
                          :organization_id, :artifact_id, 'source_document', :document_identity,
                          :declared_version, CAST(:document_scope AS jsonb), :supplier_identifier,
                          :current_version, :created_by
                        )
                        """
                    ),
                    {
                        "organization_id": organization_id, "artifact_id": str(artifact_id),
                        "document_identity": record.metadata.document_identity,
                        "declared_version": record.metadata.version,
                        "document_scope": stable_bytes(record.metadata.scope).decode("utf-8"),
                        "supplier_identifier": record.metadata.supplier_id,
                        "current_version": version,
                        "created_by": str(self.store.context.principal_id),
                    },
                )
            else:
                connection.execute(
                    text(
                        """
                        UPDATE artifacts SET current_version = :current_version
                        WHERE organization_id = :organization_id AND artifact_id = :artifact_id
                          AND current_version = :expected
                        """
                    ),
                    {
                        "current_version": version, "organization_id": organization_id,
                        "artifact_id": str(artifact_id), "expected": int(current_version),
                    },
                )
            original = record.quarantine_object
            connection.execute(
                text(
                    """
                    INSERT INTO artifact_versions (
                      organization_id, artifact_id, version, storage_class, bucket_name, object_key,
                      provider_version_id, byte_length, sha256, claimed_media_type,
                      detected_media_type, encryption_method, encryption_key_id, retention_class,
                      valid_from, valid_until, signature_state, custody_state
                    ) VALUES (
                      :organization_id, :artifact_id, :version, 'quarantine', :bucket_name, :object_key,
                      :provider_version_id, :byte_length, :sha256, :claimed_media_type,
                      'application/octet-stream', :encryption_method, :encryption_key_id, :retention_class,
                      :valid_from, :valid_until, :signature_state, 'preserved_quarantined'
                    )
                    """
                ),
                {
                    "organization_id": organization_id, "artifact_id": str(artifact_id), "version": version,
                    "bucket_name": original.bucket, "object_key": original.key,
                    "provider_version_id": original.version_id, "byte_length": original.byte_length,
                    "sha256": original.sha256, "claimed_media_type": record.claimed_media_type,
                    "encryption_method": original.encryption_method,
                    "encryption_key_id": original.encryption_key_id,
                    "retention_class": record.metadata.retention_class,
                    "valid_from": record.metadata.valid_from, "valid_until": record.metadata.valid_until,
                    "signature_state": record.metadata.signature_state,
                },
            )
            connection.execute(
                text(
                    """
                    INSERT INTO ingestion_requests (
                      organization_id, ingestion_id, artifact_id, artifact_version, state,
                      claimed_filename, claimed_media_type, submitted_by
                    ) VALUES (
                      :organization_id, :ingestion_id, :artifact_id, :artifact_version,
                      'original_preserved', :filename, :claimed_media_type, :submitted_by
                    )
                    """
                ),
                {
                    "organization_id": organization_id, "ingestion_id": record.ingestion_id,
                    "artifact_id": str(artifact_id), "artifact_version": version,
                    "filename": record.filename, "claimed_media_type": record.claimed_media_type,
                    "submitted_by": str(self.store.context.principal_id),
                },
            )
        self.records[record.ingestion_id] = record
        self._identifiers[record.ingestion_id] = (artifact_id, version)
        self._attempts[record.ingestion_id] = 0

    def artifact_reference(self, ingestion_id: str, *, governed: bool = True) -> dict[str, Any]:
        """Return the immutable database reference created by this ingestion.

        The governed copy is one version after the preserved quarantine original.
        This method exposes identifiers only; bytes remain in the custody store.
        """
        try:
            artifact_id, original_version = self._identifiers[ingestion_id]
            record = self.records[ingestion_id]
        except KeyError as exc:
            raise IngestionError("INGESTION_NOT_FOUND", "ingestion is not available in this process") from exc
        if governed and record.state != "accepted":
            raise IngestionError("STATE_VIOLATION", "document has no accepted governed artifact")
        return {
            "artifact_id": str(artifact_id),
            "artifact_version": original_version + 1 if governed else original_version,
            "custody_state": "governed_available" if governed else "preserved_quarantined",
            "sha256": (record.governed_object if governed else record.quarantine_object).sha256,
        }

    def transition(self, ingestion_id: str, state: str, **detail: Any) -> None:
        record = self.records[ingestion_id]
        artifact_id, original_version = self._identifiers[ingestion_id]
        organization_id = str(self.store.context.organization_id)
        self._attempts[ingestion_id] += 1
        with self.store.transaction(serializable=True) as connection:
            if state == "extraction_ready":
                if record.governed_object is None or record.detected_media_type is None:
                    raise IngestionError("STATE_VIOLATION", "governed object and detected type are required")
                governed = record.governed_object
                governed_version = original_version + 1
                updated = connection.execute(
                    text(
                        """
                        UPDATE artifacts SET current_version = :governed_version
                        WHERE organization_id = :organization_id AND artifact_id = :artifact_id
                          AND current_version = :original_version
                        """
                    ),
                    {
                        "governed_version": governed_version, "organization_id": organization_id,
                        "artifact_id": str(artifact_id), "original_version": original_version,
                    },
                )
                if updated.rowcount != 1:
                    raise IngestionError("CONCURRENCY_CONFLICT", "artifact changed during promotion")
                connection.execute(
                    text(
                        """
                        INSERT INTO artifact_versions (
                          organization_id, artifact_id, version, storage_class, bucket_name, object_key,
                          provider_version_id, byte_length, sha256, claimed_media_type,
                          detected_media_type, encryption_method, encryption_key_id, retention_class,
                          valid_from, valid_until, signature_state, custody_state
                        ) VALUES (
                          :organization_id, :artifact_id, :version, 'governed', :bucket_name, :object_key,
                          :provider_version_id, :byte_length, :sha256, :claimed_media_type,
                          :detected_media_type, :encryption_method, :encryption_key_id, :retention_class,
                          :valid_from, :valid_until, :signature_state, 'governed_available'
                        )
                        """
                    ),
                    {
                        "organization_id": organization_id, "artifact_id": str(artifact_id),
                        "version": governed_version, "bucket_name": governed.bucket,
                        "object_key": governed.key, "provider_version_id": governed.version_id,
                        "byte_length": governed.byte_length, "sha256": governed.sha256,
                        "claimed_media_type": record.claimed_media_type,
                        "detected_media_type": record.detected_media_type,
                        "encryption_method": governed.encryption_method,
                        "encryption_key_id": governed.encryption_key_id,
                        "retention_class": record.metadata.retention_class,
                        "valid_from": record.metadata.valid_from, "valid_until": record.metadata.valid_until,
                        "signature_state": record.metadata.signature_state,
                    },
                )
            connection.execute(
                text(
                    """
                    UPDATE ingestion_requests SET state = :state,
                      detected_media_type = COALESCE(:detected_media_type, detected_media_type),
                      failure_code = :failure_code, updated_at = clock_timestamp()
                    WHERE organization_id = :organization_id AND ingestion_id = :ingestion_id
                    """
                ),
                {
                    "state": state, "detected_media_type": record.detected_media_type,
                    "failure_code": detail.get("failure_code"), "organization_id": organization_id,
                    "ingestion_id": ingestion_id,
                },
            )
            connection.execute(
                text(
                    """
                    INSERT INTO ingestion_attempts (
                      organization_id, ingestion_id, attempt, stage, tool_name, tool_version,
                      result_state, details, started_at, completed_at
                    ) VALUES (
                      :organization_id, :ingestion_id, :attempt, :stage, 'bahar-ingestion',
                      '2.0.0', :result_state, CAST(:details AS jsonb), clock_timestamp(), clock_timestamp()
                    )
                    """
                ),
                {
                    "organization_id": organization_id, "ingestion_id": ingestion_id,
                    "attempt": self._attempts[ingestion_id], "stage": state,
                    "result_state": "failed" if state in {"rejected", "quarantined"} else "passed",
                    "details": stable_bytes(detail).decode("utf-8"),
                },
            )
            if state in {"accepted", "rejected", "quarantined"}:
                self.store._audit(
                    connection, action=f"document_{state}", target_type="artifact",
                    target_id=str(artifact_id), target_revision=original_version,
                    outcome="success" if state == "accepted" else "failure",
                    reason=detail.get("message", state), operation_id=f"ingestion:{ingestion_id}:{state}",
                    detail={"ingestion_id": ingestion_id, **detail},
                )
        record.state = state
        record.events.append({"state": state, "detail": detail, "at": datetime.now(timezone.utc).isoformat()})
        if detail.get("failure_code"):
            record.failure_code = str(detail["failure_code"])

    def accept(self, ingestion_id: str, fact: dict[str, Any]) -> None:
        del fact
        record = self.records[ingestion_id]
        if record.state != "accepted":
            raise IngestionError("STATE_VIOLATION", "facts can only be recorded after acceptance")
        artifact_id, _ = self._identifiers[ingestion_id]
        with self.store.transaction() as connection:
            connection.execute(
                text(
                    """
                    UPDATE artifacts SET state = 'active'
                    WHERE organization_id = :organization_id AND artifact_id = :artifact_id
                    """
                ),
                {
                    "organization_id": str(self.store.context.organization_id),
                    "artifact_id": str(artifact_id),
                },
            )
            for lot in record.metadata.applicable_lots:
                connection.execute(
                    text(
                        """
                        INSERT INTO document_applicable_lots (
                          organization_id, artifact_id, lot_identifier, declared_scope
                        ) VALUES (
                          :organization_id, :artifact_id, :lot_identifier, CAST(:declared_scope AS jsonb)
                        ) ON CONFLICT DO NOTHING
                        """
                    ),
                    {
                        "organization_id": str(self.store.context.organization_id),
                        "artifact_id": str(artifact_id), "lot_identifier": lot,
                        "declared_scope": stable_bytes(record.metadata.scope).decode("utf-8"),
                    },
                )


SUPPORTED_MEDIA_TYPES = {
    "application/pdf",
    "image/png",
    "image/jpeg",
    "image/tiff",
    "image/webp",
    "text/csv",
    "application/json",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.ms-excel",
    "application/vnd.oasis.opendocument.spreadsheet",
}


def detect_media_type(data: bytes) -> str:
    if data.startswith(b"%PDF-"):
        return "application/pdf"
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if data.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if data.startswith((b"II*\x00", b"MM\x00*")):
        return "image/tiff"
    if len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp"
    if data.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "application/vnd.ms-excel"
    if data.startswith(b"PK\x03\x04"):
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                names = set(archive.namelist())
        except zipfile.BadZipFile as exc:
            raise IngestionError("ARCHIVE_MALFORMED", "ZIP container is malformed") from exc
        if "[Content_Types].xml" in names and any(name.startswith("xl/") for name in names):
            return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        if "mimetype" in names:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                with archive.open("mimetype") as stream:
                    if stream.read(200) == b"application/vnd.oasis.opendocument.spreadsheet":
                        return "application/vnd.oasis.opendocument.spreadsheet"
        raise IngestionError("ARCHIVE_UNSUPPORTED", "ZIP container is not a supported spreadsheet")
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise IngestionError("TYPE_UNSUPPORTED", "unrecognized binary document type") from exc
    try:
        parsed = json.loads(text)
        if isinstance(parsed, (dict, list)):
            return "application/json"
    except (json.JSONDecodeError, RecursionError):
        pass
    sample = text[:64_000]
    if "\x00" not in sample and any(delimiter in sample for delimiter in (",", ";", "\t")):
        try:
            csv.Sniffer().sniff(sample)
            return "text/csv"
        except csv.Error:
            pass
    raise IngestionError("TYPE_UNSUPPORTED", "document type is not supported")


def _validate_archive(data: bytes, limits: IngestionLimits) -> None:
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        entries = archive.infolist()
        if len(entries) > limits.max_archive_entries:
            raise IngestionError("ARCHIVE_ENTRY_LIMIT", "archive contains too many entries")
        expanded = 0
        for entry in entries:
            path = PurePosixPath(entry.filename)
            if path.is_absolute() or ".." in path.parts:
                raise IngestionError("ARCHIVE_PATH_TRAVERSAL", "archive contains an unsafe path")
            if entry.flag_bits & 0x1:
                raise IngestionError("ARCHIVE_ENCRYPTED", "encrypted archive entries are not accepted")
            if (entry.external_attr >> 16) & 0o170000 == 0o120000:
                raise IngestionError("ARCHIVE_SYMLINK", "archive symlinks are not accepted")
            lowered = entry.filename.casefold()
            if lowered.endswith((".zip", ".7z", ".rar", ".tar", ".gz", ".bz2", ".xz")):
                raise IngestionError("ARCHIVE_NESTED", "nested archives are not accepted")
            if "vbaproject.bin" in lowered or lowered.startswith("xl/externallinks/"):
                raise IngestionError("SPREADSHEET_ACTIVE_CONTENT", "macros and external workbook links are not accepted")
            expanded += entry.file_size
            if expanded > limits.max_expanded_bytes:
                raise IngestionError("ARCHIVE_EXPANDED_LIMIT", "archive expanded size exceeds policy")
            ratio = entry.file_size / max(1, entry.compress_size)
            if ratio > limits.max_expansion_ratio:
                raise IngestionError("ARCHIVE_RATIO_LIMIT", "archive expansion ratio exceeds policy")


def validate_structure(data: bytes, media_type: str, limits: IngestionLimits) -> dict[str, Any]:
    if media_type == "application/pdf":
        if any(token in data for token in (b"/JavaScript", b"/JS ", b"/Launch", b"/EmbeddedFile")):
            raise IngestionError("PDF_ACTIVE_CONTENT", "PDF active or embedded content is not accepted")
        try:
            document = fitz.open(stream=data, filetype="pdf")
            pages = document.page_count
            document.close()
        except Exception as exc:
            raise IngestionError("PDF_MALFORMED", "PDF parser rejected the document") from exc
        if pages <= 0 or pages > limits.max_pages:
            raise IngestionError("PDF_PAGE_LIMIT", "PDF page count is outside policy")
        return {"pages": pages}
    if media_type.startswith("image/"):
        from PIL import Image
        try:
            with Image.open(io.BytesIO(data)) as image:
                image.verify()
                width, height = image.size
        except Exception as exc:
            raise IngestionError("IMAGE_MALFORMED", "image decoder rejected the document") from exc
        if width * height > 250_000_000:
            raise IngestionError("IMAGE_PIXEL_LIMIT", "image pixel count exceeds policy")
        return {"width": width, "height": height}
    if media_type in {
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "application/vnd.oasis.opendocument.spreadsheet",
    }:
        _validate_archive(data, limits)
        if media_type.endswith("sheetml.sheet"):
            try:
                workbook = load_workbook(io.BytesIO(data), read_only=True, data_only=False, keep_links=False)
                dimensions = {sheet.title: sheet.calculate_dimension() for sheet in workbook.worksheets}
                workbook.close()
            except Exception as exc:
                raise IngestionError("SPREADSHEET_MALFORMED", "spreadsheet parser rejected the document") from exc
            return {"worksheets": dimensions}
        return {"container": "validated"}
    if media_type == "text/csv":
        try:
            reader = csv.reader(io.StringIO(data.decode("utf-8-sig")))
            count = 0
            for row in reader:
                count += 1
                if count > limits.max_csv_rows:
                    raise IngestionError("CSV_ROW_LIMIT", "CSV row count exceeds policy")
                if any(len(cell) > limits.max_cell_characters for cell in row):
                    raise IngestionError("CSV_CELL_LIMIT", "CSV cell size exceeds policy")
        except UnicodeDecodeError as exc:
            raise IngestionError("CSV_ENCODING", "CSV must use UTF-8") from exc
        return {"rows": count}
    if media_type == "application/json":
        try:
            value = json.loads(data.decode("utf-8-sig"))
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
            raise IngestionError("JSON_MALFORMED", "structured API record is invalid JSON") from exc
        if not isinstance(value, (dict, list)):
            raise IngestionError("JSON_SHAPE", "structured API record must be an object or array")
        return {"root_type": type(value).__name__}
    if media_type == "application/vnd.ms-excel":
        return {"container": "ole-compound-document", "requires_sandboxed_extractor": True}
    raise IngestionError("TYPE_UNSUPPORTED", "document type is not supported")


class IngestionService:
    def __init__(
        self,
        store: ArtifactStore,
        scanner: MalwareScanner,
        repository: IngestionRepository,
        limits: IngestionLimits | None = None,
    ) -> None:
        self.store = store
        self.scanner = scanner
        self.repository = repository
        self.limits = limits or IngestionLimits()

    def ingest(
        self,
        data: bytes,
        *,
        filename: str,
        claimed_media_type: str | None,
        metadata: DocumentMetadata,
    ) -> IngestionRecord:
        metadata.validate()
        if not data:
            raise IngestionError("EMPTY_UPLOAD", "empty documents are not accepted")
        if len(data) > self.limits.max_upload_bytes:
            raise IngestionError("UPLOAD_LIMIT", "upload size exceeds policy")
        ingestion_id = str(uuid.uuid4())
        original = self.store.put(
            "quarantine", data, media_type="application/octet-stream", retention_class=metadata.retention_class
        )
        record = IngestionRecord(
            ingestion_id, "original_preserved", filename, claimed_media_type, None, metadata,
            quarantine_object=original,
        )
        self.repository.create(record)
        self.repository.transition(ingestion_id, "original_preserved", sha256=original.sha256)
        try:
            # Scan the original bytes before any parser or type classifier. This
            # ensures unknown/malformed malicious files cannot bypass the malware
            # control merely because they fail format recognition first.
            scan = self.scanner.scan(data)
            if not scan.clean:
                raise IngestionError("MALWARE_DETECTED", f"malware detected: {scan.signature or 'unknown'}")
            self.repository.transition(
                ingestion_id, "malware_scan_passed", engine=scan.engine, version=scan.engine_version
            )
            detected = detect_media_type(data)
            record.detected_media_type = detected
            if detected not in SUPPORTED_MEDIA_TYPES:
                raise IngestionError("TYPE_UNSUPPORTED", "detected document type is not permitted")
            if claimed_media_type and claimed_media_type not in {"application/octet-stream", detected}:
                raise IngestionError("TYPE_MISMATCH", "claimed and detected media types differ")
            self.repository.transition(ingestion_id, "type_verified", detected_media_type=detected)
            structure = validate_structure(data, detected, self.limits)
            self.repository.transition(ingestion_id, "structure_validated", structure=structure)
            governed = self.store.put(
                "governed", data, media_type=detected, retention_class=metadata.retention_class
            )
            if governed.sha256 != original.sha256:
                raise IngestionError("PROMOTION_DIGEST_MISMATCH", "promoted bytes differ from preserved original")
            record.governed_object = governed
            self.repository.transition(ingestion_id, "extraction_ready", governed_key=governed.key)
            self.repository.transition(ingestion_id, "accepted")
            self.repository.accept(ingestion_id, {
                "ingestion_id": ingestion_id,
                "media_type": detected,
                "sha256": governed.sha256,
                "metadata": asdict(metadata),
                "structure": structure,
            })
            return record
        except IngestionError as exc:
            state = "quarantined" if exc.code.startswith(("MALWARE_SCANNER", "PROMOTION_")) else "rejected"
            self.repository.transition(ingestion_id, state, failure_code=exc.code, message=str(exc))
            return record
