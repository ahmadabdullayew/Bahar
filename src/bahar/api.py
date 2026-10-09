from __future__ import annotations

import json
import base64
import binascii
import mimetypes
import os
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from sqlalchemy.exc import DBAPIError, IntegrityError

from .bahar_adapter import BaharAIAdapter
from .governed_workflow import GovernedWorkflow, GovernanceError
from .evidence_governance import EvidenceCustody
from .config import ProductionSettings
from .ingestion import (
    ClamdScanner,
    DocumentMetadata,
    IngestionError,
    IngestionLimits,
    IngestionService,
    PostgresIngestionRepository,
)
from .extraction import ExtractionError, LayoutExtractor, label_declaration_candidates
from .governance_repository import PostgresExtractionRepository
from .object_store import S3ObjectStore
from .operations import OperationsError, OperationsService
from .operational_scope import OperationalScopeError, operational_assurance
from .operational_workflow import OperationalWorkflow
from .persistence import PostgresBaharStore
from .resources import WEB_DIR, load_case
from .service import BaharService
from .store import StoreError
from .http_identity import (OIDCSettings, OIDCAuthenticator, PostgreSQLMembershipDirectory,
                            AuthenticationError, READ_ROLES, WRITE_ROLES, PRIVILEGED_ROUTES, HTTP_OPERATION_ACTIONS)
from .reviewer_workflow import ReviewerWorkflow
from .authorization import OPERATION_ACTION_ROLES
from .persistence import TenantContext
import uuid


MAX_BODY_BYTES = 25 * 1_048_576
STATIC_FILES = {
    "/": "index.html",
    "/index.html": "index.html",
    "/app.js": "app.js",
    "/identity.js": "identity.js",
    "/styles.css": "styles.css",
}


def strict_json_loads(raw: bytes) -> Any:
    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON member: {key}")
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise ValueError(f"non-finite JSON number is forbidden: {value}")

    return json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=unique_object,
        parse_constant=reject_constant,
    )


class BaharHandler(BaseHTTPRequestHandler):
    server_version = "Bahar/2.1"

    @property
    def service(self) -> BaharService:
        return getattr(self, "_scoped_service", self.server.service)  # type: ignore[attr-defined]

    @property
    def operations(self) -> OperationsService | None:
        return getattr(self, "_scoped_operations", self.server.operations)  # type: ignore[attr-defined]

    @property
    def bahar(self) -> BaharAIAdapter:
        return getattr(self, "_scoped_bahar", self.server.bahar)  # type: ignore[attr-defined]

    @property
    def workflow(self) -> GovernedWorkflow:
        return getattr(self, "_scoped_workflow", self.server.workflow)  # type: ignore[attr-defined]

    @property
    def ingestion(self) -> IngestionService | None:
        return getattr(self, "_scoped_ingestion", self.server.ingestion)  # type: ignore[attr-defined]

    @property
    def ingestion_repository(self) -> PostgresIngestionRepository | None:
        return getattr(self, "_scoped_ingestion_repository", self.server.ingestion_repository)  # type: ignore[attr-defined]

    @property
    def layout_extractor(self) -> LayoutExtractor | None:
        return self.server.layout_extractor  # type: ignore[attr-defined]

    @property
    def extraction_repository(self) -> PostgresExtractionRepository | None:
        return getattr(self, "_scoped_extraction_repository", self.server.extraction_repository)  # type: ignore[attr-defined]

    def _security_error(self, exc: AuthenticationError) -> None:
        self._json(exc.status, {'error': exc.code, 'message': 'Authentication, role or recent MFA requirement not satisfied'})

    def _authorize_http(self, path: str, method: str) -> bool:
        authenticator: OIDCAuthenticator | None = getattr(self.server, 'authenticator', None)
        if authenticator is None:
            return True  # Explicit local SQLite demo only. Production startup requires OIDC.
        if (method == 'GET' and path in ('/api/health','/api/ai/identity','/api/ai/lookup',
                                        '/api/demo/ready','/api/demo/unsafe','/api/auth/config')):
            return True
        if method == 'POST' and path=='/api/operational/preview':
            return True
        if not path.startswith('/api/'):
            return True
        try:
            actor = authenticator.authenticate(self.headers.get('Authorization'))
            if method=='GET' and path=='/api/auth/tenants':
                entries=authenticator.memberships(actor)
                result={}
                for row in entries:
                    if row.get('facility_id') is not None:
                        continue  # Explicit facility grants never become organization-wide grants.
                    tenant=str(row['organization_id'])
                    result.setdefault(tenant,set()).add(str(row['role_name']))
                self._json(HTTPStatus.OK,{'tenants':[{'organization_id':k,'roles':sorted(v)} for k,v in sorted(result.items())]})
                return False
            identity=authenticator.select_tenant(actor,self.headers.get('X-Bahar-Tenant'))
            roles=set(identity['roles'])
            if method=='GET':
                if not (roles & READ_ROLES):
                    raise AuthenticationError('read_role_not_granted',403)
                if path=='/api/reviewers' and 'tenant_administrator' not in roles:
                    raise AuthenticationError('reviewer_directory_role_required',403)
                if path.startswith('/api/evidence/') and not roles.intersection({'reviewer','auditor','regulatory_approver','tenant_administrator'}):
                    raise AuthenticationError('evidence_read_role_not_granted',403)
            elif method=='POST':
                role=WRITE_ROLES.get(path)
                if role is None:
                    role=OPERATION_ACTION_ROLES.get(HTTP_OPERATION_ACTIONS.get(path,''))
                if role is None:
                    raise AuthenticationError('operation_not_authorized',403)
                authenticator.require(identity,role,actor,privileged=path in PRIVILEGED_ROUTES)
            else:
                raise AuthenticationError('unsupported_method',405)
            service_store=self.server.service.store
            scoped_store=PostgresBaharStore(
                os.environ['BAHAR_DATABASE_URL'],
                TenantContext(uuid.UUID(identity['organization_id']),uuid.UUID(identity['principal_id'])),
                service_store.audit_hmac_key,audit_key_id=service_store.audit_key_id,
                engine=service_store.engine)
            # One request => one actor and one tenant; no mutable server-global context.
            self._scoped_service=BaharService(store=scoped_store)
            self._scoped_operations=OperationsService(scoped_store)
            self._scoped_bahar=BaharAIAdapter(scoped_store)
            self._scoped_workflow=GovernedWorkflow(scoped_store,self._scoped_service)
            self._scoped_ingestion_repository=PostgresIngestionRepository(scoped_store) if self.server.ingestion else None
            self._scoped_ingestion=(IngestionService(self.server.ingestion.store,
                self.server.ingestion.scanner,self._scoped_ingestion_repository,
                self.server.ingestion.limits) if self.server.ingestion else None)
            self._scoped_extraction_repository=(PostgresExtractionRepository(scoped_store)
                if self.server.extraction_repository else None)
            self._verified_context=identity
            self._verified_actor=actor
            if method=='GET' and path=='/api/auth/me':
                self._json(HTTPStatus.OK,{'principal_id':identity['principal_id'],
                    'organization_id':identity['organization_id'],'roles':identity['roles'],
                    'facility_limited_roles':identity['facility_limited_roles'],
                    'mfa_fresh':actor.fresh_mfa(authenticator.clock(),authenticator.settings),
                    'allowed_post_routes':([route for route, role in WRITE_ROLES.items() if role in roles]+
                        [route for route, action in HTTP_OPERATION_ACTIONS.items() if
                         OPERATION_ACTION_ROLES[action] in roles])})
                return False
            return True
        except AuthenticationError as exc:
            self._security_error(exc)
            return False

    def log_message(self, format: str, *args: Any) -> None:
        print(f"{self.address_string()} - {format % args}")

    def _content_security_policy(self) -> str:
        """Permit public SPA PKCE token exchange only to the configured issuer."""
        from urllib.parse import urlsplit
        auth=getattr(self.server,'authenticator',None)
        token_origin=''
        if auth is not None:
            token=urlsplit(auth.settings.token_url)
            token_origin=f" {token.scheme}://{token.netloc}"
        return ("default-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; "
                "form-action 'self'; style-src 'self'; script-src 'self'; "
                f"connect-src 'self'{token_origin}; img-src 'self' data:")

    def _json(self, status: int, payload: Any) -> None:
        encoded = json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", self._content_security_policy())
        self.end_headers()
        self.wfile.write(encoded)

    def _read_json(self) -> dict[str, Any]:
        if self.headers.get_content_type() != "application/json":
            raise ValueError("Content-Type must be application/json")
        raw_length = self.headers.get("Content-Length")
        if raw_length is None:
            raise ValueError("Content-Length is required")
        length = int(raw_length)
        if length < 0 or length > MAX_BODY_BYTES:
            raise ValueError("request body exceeds the 25 MiB API limit")
        raw = self.rfile.read(length)
        value = strict_json_loads(raw)
        if not isinstance(value, dict):
            raise ValueError("request body must be a JSON object")
        return value

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path
        if path == '/api/auth/config':
            auth=getattr(self.server,'authenticator',None)
            if auth is None:
                self._json(HTTPStatus.OK,{'mode':'local_demonstration','enabled':False})
            else:
                settings=auth.settings
                self._json(HTTPStatus.OK,{'enabled':True,'mode':'oidc_pkce',
                    'issuer':settings.issuer,'client_id':settings.client_id,
                    'authorize_url':settings.authorize_url,'token_url':settings.token_url,
                    'redirect_uri':settings.redirect_uri,'audience':settings.audience,
                    'fresh_auth_seconds':settings.fresh_auth_seconds})
            return
        if not self._authorize_http(path,'GET'):
            return
        # This developer server does not authenticate independent HTTP users.
        # Tenant-bound service credentials cannot stand in for user identity.
        if isinstance(self.service.store,PostgresBaharStore) and not hasattr(self,'_verified_context') and (
            path == '/api/dashboard' or path.startswith('/api/records/')
            or path.startswith('/api/formulations/') or path.startswith('/api/assessments/')
            or path == '/api/evidence/corrections'):
            self._json(HTTPStatus.FORBIDDEN,{'error':'per_request_authentication_required'})
            return
        if path == "/api/health":
            self._json(HTTPStatus.OK, {
                "status": "ok", "service": "bahar", "version": "2.1.0",
                "production_persistence": self.operations is not None,
                "bahar_ai_core": self.bahar.identity.__dict__,
            })
            return
        if path == "/api/ai/identity":
            self._json(HTTPStatus.OK, self.bahar.identity.__dict__)
            return
        if path == "/api/ai/lookup":
            query = parse_qs(parsed.query).get("q", [""])[0]
            if not query.strip():
                self._json(HTTPStatus.BAD_REQUEST, {"error": "q is required"})
            else:
                self._json(HTTPStatus.OK, self.bahar.lookup(query))
            return
        if path == '/api/reviewers':
            if not hasattr(self,'_verified_context'):
                self._json(HTTPStatus.FORBIDDEN,{'error':'authenticated_admin_required'})
                return
            from sqlalchemy import text
            with self.service.store.transaction() as conn:
                rows=conn.execute(text("""SELECT DISTINCT p.principal_id,p.display_name
                  FROM memberships m JOIN principals p ON p.principal_id=m.principal_id
                  WHERE m.organization_id=:org AND m.role_name='reviewer' AND m.facility_id IS NULL
                    AND p.state='active' AND m.valid_from<=clock_timestamp()
                    AND (m.valid_until IS NULL OR m.valid_until>clock_timestamp())
                  ORDER BY p.display_name NULLS LAST,p.principal_id"""),
                  {'org':self._verified_context['organization_id']}).mappings().all()
            self._json(HTTPStatus.OK,{'reviewers':[{'principal_id':str(r['principal_id']),
                'display_name':str(r['display_name'] or 'Qualified reviewer')} for r in rows]})
            return
        if path == "/api/dashboard":
            if self.operations is None:
                self._json(HTTPStatus.SERVICE_UNAVAILABLE, {"error": "production persistence is not configured"})
            else:
                self._json(HTTPStatus.OK, self.operations.dashboard())
            return
        if path.startswith("/api/records/"):
            if self.operations is None:
                self._json(HTTPStatus.SERVICE_UNAVAILABLE, {"error": "production persistence is not configured"})
            else:
                try:
                    query = parse_qs(parsed.query)
                    limit = int(query.get("limit", ["40"])[0])
                    offset = int(query.get("offset", ["0"])[0])
                    search = query.get("q", [""])[0]
                    self._json(HTTPStatus.OK, self.operations.list_records_page(
                        path.removeprefix("/api/records/"),
                        limit=limit, offset=offset, search=search,
                    ))
                except (ValueError, OperationsError) as exc:
                    self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_record_query", "message": str(exc)})
            return
        if path.startswith("/api/formulations/") and path.endswith("/resolve"):
            if self.operations is None:
                self._json(HTTPStatus.SERVICE_UNAVAILABLE, {"error": "production persistence is not configured"})
            else:
                parts = path.strip("/").split("/")
                version = int(parse_qs(parsed.query).get("version", ["1"])[0])
                self._json(HTTPStatus.OK, self.operations.resolve_formulation(parts[2], version))
            return
        if path == "/api/demo/unsafe":
            sample = load_case("demo_case.json")
            sample['rules'] = []  # historical example is NOT an approved legal source
            self._json(HTTPStatus.OK, sample)
            return
        if path == "/api/demo/ready":
            sample = load_case("demo_ready_case.json")
            sample['rules'] = []
            self._json(HTTPStatus.OK, sample)
            return
        if path.startswith("/api/assessments/"):
            if path.endswith('/verify-replay'):
                if isinstance(self.service.store, PostgresBaharStore) and not hasattr(self,'_verified_context'):
                    self._json(HTTPStatus.FORBIDDEN, {'error': 'authenticated_access_required'})
                    return
                assessment_id = path.removeprefix('/api/assessments/').removesuffix('/verify-replay')
                try:
                    self._json(HTTPStatus.OK, self.workflow.verify_assessment_replay(assessment_id))
                except StoreError as exc:
                    self._json(HTTPStatus.CONFLICT, {'error': 'replay_verification_failed', 'message': str(exc)})
                return
            if path.endswith('/provenance'):
                if isinstance(self.service.store, PostgresBaharStore) and not hasattr(self,'_verified_context'):
                    self._json(HTTPStatus.FORBIDDEN, {'error': 'authenticated_access_required'})
                    return
                assessment_id = path.removeprefix('/api/assessments/').removesuffix('/provenance')
                rec = self.service.store.get_assessment(assessment_id)
                self._json(HTTPStatus.OK if rec else HTTPStatus.NOT_FOUND,
                           ({'assessment_id': assessment_id, 'graph': rec.get('provenance_graph'),
                             'assurance': rec.get('evidence_assurance'), 'manifest': rec.get('manifest')}
                            if rec else {'error': 'not_found'}))
                return
            assessment_id = path.removeprefix("/api/assessments/")
            record = self.service.store.get_assessment(assessment_id)
            self._json(HTTPStatus.OK if record else HTTPStatus.NOT_FOUND, record or {"error": "not_found"})
            return
        if path.startswith('/api/operational/records/'):
            if isinstance(self.service.store,PostgresBaharStore) or self.server.server_address[0] not in ('127.0.0.1','::1'):
                self._json(HTTPStatus.FORBIDDEN,{'error':'per_request_authentication_required'})
                return
            parts=path.split('/')
            if len(parts)!=6:
                self._json(HTTPStatus.BAD_REQUEST,{'error':'expected /api/operational/records/{kind}/{record_id}'})
                return
            try:
                record=OperationalWorkflow(self.service.store).read(parts[4],parts[5])
                self._json(HTTPStatus.OK if record else HTTPStatus.NOT_FOUND,record or {'error':'not_found'})
            except (StoreError,ValueError) as exc:
                self._json(HTTPStatus.BAD_REQUEST,{'error':'invalid_record','message':str(exc)})
            return
        if path == '/api/evidence/corrections':
            if isinstance(self.service.store, PostgresBaharStore) and not hasattr(self,'_verified_context'):
                self._json(HTTPStatus.FORBIDDEN, {'error': 'authenticated_access_required'})
                return
            ref = parse_qs(parsed.query).get('source_ref', [''])[0]
            try:
                self._json(HTTPStatus.OK, EvidenceCustody(self.service.store).correction_history(ref))
            except (StoreError, ValueError) as exc:
                self._json(HTTPStatus.CONFLICT, {'error': 'invalid_correction_history', 'message': str(exc)})
            return
        if path.startswith('/api/reviews/'):
            if not hasattr(self,'_verified_context'):
                self._json(HTTPStatus.FORBIDDEN,{'error':'authenticated_review_read_required'})
            else:
                key=path.removeprefix('/api/reviews/')
                try:self._json(HTTPStatus.OK,ReviewerWorkflow(self.service.store).history(key))
                except StoreError as exc:self._json(HTTPStatus.CONFLICT,{'error':'review_state_conflict','message':str(exc)})
            return
        if path in STATIC_FILES:
            file_path = WEB_DIR / STATIC_FILES[path]
            content = file_path.read_bytes()
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", mimetypes.guess_type(file_path.name)[0] or "application/octet-stream")
            self.send_header("Content-Length", str(len(content)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Security-Policy", self._content_security_policy())
            self.end_headers()
            self.wfile.write(content)
            return
        self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"})

    def do_POST(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        try:
            if not self._authorize_http(path,'POST'):
                return
            payload = self._read_json()
            if hasattr(self,'_verified_context') and any(k in payload for k in (
                'organization_id','principal_id','actor_id','authority_role','service_identity')):
                self._json(HTTPStatus.BAD_REQUEST,{'error':'untrusted_identity_fields_forbidden'})
                return
            if path in ('/api/reviews/assign','/api/reviews/decision','/api/reviews/regulatory-decision'):
                if not hasattr(self,'_verified_context'):
                    self._json(HTTPStatus.FORBIDDEN,{'error':'authenticated_review_required'})
                    return
                reviews=ReviewerWorkflow(self.service.store)
                if path.endswith('/assign'):
                    output=reviews.assign(str(payload['assessment_id']),str(payload['reviewer_id']),str(payload['reason']))
                elif path.endswith('/regulatory-decision'):
                    output=reviews.regulatory_decide(str(payload['assessment_id']),str(payload['verdict']),str(payload['reason']))
                else:
                    output=reviews.decide(str(payload['assessment_id']),str(payload['verdict']),str(payload['reason']))
                self._json(HTTPStatus.CREATED,output)
                return
            if isinstance(self.service.store,PostgresBaharStore) and not hasattr(self,'_verified_context') and path in {
                '/api/assess','/api/assess/governed','/api/ai/audit','/api/ai/compare',
                '/api/ai/reviewed'}:
                self._json(HTTPStatus.FORBIDDEN,{
                    'error':'per_request_authentication_required',
                    'message':'Use a separately authenticated, tenant-bound service for governed assessments.'})
                return
            demo_evidence_routes = {
                '/api/evidence/sources': 'retain_source',
                '/api/evidence/assertions': 'propose_assertion',
                '/api/evidence/reviews': 'review_assertion',
                '/api/evidence/coverage': 'register_coverage',
                '/api/evidence/bundles': 'register_bundle',
                '/api/evidence/corrections': 'propose_correction',
                '/api/evidence/correction-decisions': 'decide_correction',
                '/api/evidence/derivatives': 'materialize_corrected_source',
            }
            if path in demo_evidence_routes:
                # The HTTP server still has no request-bound authenticated user.
                # Its interactive evidence ledger is only a LOCAL DEMONSTRATION.
                # Production mutations are deliberately available solely to
                # an authenticated service/CLI with membership-backed roles.
                if ((isinstance(self.service.store, PostgresBaharStore) and not hasattr(self,'_verified_context')) or
                    self.server.server_address[0] not in ('127.0.0.1', '::1')):
                    self._json(HTTPStatus.FORBIDDEN, {'error': 'authenticated_reviewer_required',
                        'message': 'Production evidence mutation requires per-request authenticated qualified reviewer authority.'})
                    return
                result = getattr(EvidenceCustody(self.service.store), demo_evidence_routes[path])(**payload)
                self._json(HTTPStatus.CREATED, result)
                return
            if path == "/api/assess":
                # Compatibility endpoint for DEMONSTRATION examples only.
                # Regulatory rules and precedence cannot be created by client JSON.
                if (payload.get('contract', {}).get('mode') != 'demonstration'
                    or payload.get('rules') or payload.get('context', {}).get('approved_precedence_policy')):
                    self._json(HTTPStatus.FORBIDDEN, {
                        'error': 'governed_assessment_required',
                        'message': 'Untrusted rules, precedence and production claims are forbidden here. Use /api/assess/governed.'})
                    return
                result = self.service.assess(payload, commit=True)
                self._json(HTTPStatus.OK, result)
                return
            if path == "/api/assess/governed":
                result = self.workflow.assess_governed(payload)
                self._json(HTTPStatus.OK, result)
                return
            if path == "/api/ai/compare":
                result = self.bahar.compare(
                    product_id=str(payload['product_id']),
                    before=payload['before'], after=payload['after'])
                result['governance_stage'] = 'LEXICAL_COMPARISON_ONLY'
                result['reassessment_required'] = result.get('reassessment_required', True)
                result['definitive_unaffected_claim_permitted'] = False
                self._json(HTTPStatus.OK, result)
                return
            if path == "/api/ai/reviewed":
                result = self.workflow.reviewed_audit(str(payload['audit_id']))
                self._json(HTTPStatus.OK, result)
                return
            if path == "/api/changes/impact":
                self._json(HTTPStatus.FORBIDDEN, {
                    'error': 'authenticated_mutation_required',
                    'message': 'Change-impact mutations run atomically during governed material-record writes; unauthenticated web callers cannot trigger release suspension.'})
                return
            if path == "/api/ai/audit":
                result = self.bahar.audit(
                    product_id=str(payload["product_id"]),
                    formulation_version=str(payload["formulation_version"]),
                    formulation_text=str(payload["formulation_text"]),
                    label_version=str(payload["label_version"]),
                    label_text=str(payload["label_text"]),
                    evidence_assertions=payload.get("evidence_assertions", []),
                    persist=True,
                )
                result['governance_stage'] = 'LEXICAL_CANDIDATES_ONLY'
                result['authoritative_structured_assessment'] = False
                result['promotion_required'] = True
                self._json(HTTPStatus.CREATED, result)
                return
            if path == "/api/documents":
                if isinstance(self.service.store, PostgresBaharStore) and not hasattr(self,'_verified_context'):
                    self._json(HTTPStatus.FORBIDDEN, {'error':'authenticated_ingestion_user_required',
                        'message':'Production document ingestion requires a request-authenticated principal.'})
                    return
                if self.ingestion is None or self.ingestion_repository is None:
                    self._json(HTTPStatus.SERVICE_UNAVAILABLE, {"error": "secure ingestion is not configured"})
                    return
                _required_upload = ("content_base64", "filename", "document_identity", "version")
                missing = [name for name in _required_upload if payload.get(name) in (None, "")]
                if missing:
                    raise ValueError("missing required fields: " + ", ".join(missing))
                try:
                    document_bytes = base64.b64decode(str(payload["content_base64"]), validate=True)
                except (ValueError, binascii.Error) as exc:
                    raise ValueError("content_base64 is invalid") from exc
                from datetime import date
                metadata = DocumentMetadata(
                    document_identity=str(payload["document_identity"]), version=str(payload["version"]),
                    supplier_id=str(payload["supplier_id"]) if payload.get("supplier_id") else None,
                    scope=payload.get("scope", {}), signature_state=payload.get("signature_state", "not_evaluated"),
                    valid_from=date.fromisoformat(payload["valid_from"]) if payload.get("valid_from") else None,
                    valid_until=date.fromisoformat(payload["valid_until"]) if payload.get("valid_until") else None,
                    applicable_lots=tuple(payload.get("applicable_lots", [])),
                )
                record = self.ingestion.ingest(
                    document_bytes, filename=str(payload["filename"]),
                    claimed_media_type=payload.get("claimed_media_type"), metadata=metadata,
                )
                response = {"ingestion_id": record.ingestion_id, "state": record.state,
                            "failure_code": record.failure_code, "detected_media_type": record.detected_media_type,
                            "events": record.events}
                if record.state == "accepted":
                    artifact_reference = self.ingestion_repository.artifact_reference(record.ingestion_id)
                    response.update(artifact_reference)
                    if self.layout_extractor is not None and self.extraction_repository is not None:
                        try:
                            media_type = str(record.detected_media_type)
                            if media_type == "application/pdf":
                                extraction = self.layout_extractor.extract_pdf(document_bytes)
                            elif media_type.startswith("image/"):
                                extraction = self.layout_extractor.extract_image(document_bytes)
                            elif media_type == "text/csv":
                                extraction = self.layout_extractor.extract_csv(document_bytes)
                            elif media_type == "application/json":
                                extraction = self.layout_extractor.extract_structured_record(document_bytes)
                            elif media_type in {
                                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                                "application/vnd.oasis.opendocument.spreadsheet",
                            }:
                                extraction = self.layout_extractor.extract_spreadsheet(document_bytes)
                            else:
                                extraction = None
                            if extraction is not None:
                                self.extraction_repository.save(
                                    extraction, artifact_id=str(artifact_reference["artifact_id"]),
                                    artifact_version=int(artifact_reference["artifact_version"]),
                                )
                                response["extraction"] = extraction.as_dict()
                                response["label_declaration_candidates"] = label_declaration_candidates(extraction)
                            else:
                                response["extraction"] = {"state": "not_supported_for_legacy_container"}
                        except ExtractionError as exc:
                            response["extraction"] = {"state": "failed", "message": str(exc)}
                self._json(HTTPStatus.CREATED if record.state == "accepted" else HTTPStatus.UNPROCESSABLE_ENTITY,
                           response)
                return
            if path == "/api/operational/records":
                if isinstance(self.service.store,PostgresBaharStore) or self.server.server_address[0] not in ('127.0.0.1','::1'):
                    self._json(HTTPStatus.FORBIDDEN,{'error':'authenticated_operational_user_required'})
                    return
                result=OperationalWorkflow(self.service.store).record(
                    str(payload.get('kind','')),str(payload.get('record_id','')),
                    payload.get('record'),expected_version=payload.get('expected_version',0))
                self._json(HTTPStatus.CREATED,result)
                return
            if path == "/api/operational/preview":
                # Stateless, candidate-only safety diagnostics. A request can
                # NEVER self-assign qualified=True or assert legal compliance.
                kind = str(payload.get('kind',''))
                body = payload.get('record')
                if not isinstance(body,dict):
                    raise ValueError('record must be a JSON object')
                output = operational_assurance(kind,body,qualified=False)
                self._json(HTTPStatus.OK, {'evaluation':output,'authority':'UNQUALIFIED_PREVIEW',
                    'production_compliance':'NOT_ESTABLISHED'})
                return
            operation_routes = {
                "/api/suppliers": "create_supplier",
                "/api/materials": "create_material",
                "/api/supplier-identifiers": "create_supplier_identifier",
                "/api/specifications": "create_specification",
                "/api/lots": "create_lot",
                "/api/receipts": "create_receipt",
                "/api/origin-findings": "add_origin_finding",
                "/api/supplier-corrections": "create_supplier_correction",
                "/api/formulations": "create_formulation",
                "/api/formulation-versions": "add_formulation_version",
                "/api/labels": "create_label_text",
                "/api/printer-specifications": "create_printer_specification",
                "/api/artworks": "create_artwork",
                "/api/artwork-assessments": "assess_artwork",
                "/api/lines": "create_line",
                "/api/equipment": "create_equipment",
                "/api/packaging-lots": "create_packaging_lot",
                "/api/batches": "create_batch",
                "/api/camera-qualifications": "create_camera_qualification",
                "/api/sampling-plans": "create_sampling_plan",
                "/api/inspections": "create_inspection",
                "/api/cleaning-events": "create_cleaning_event",
                "/api/cross-contact-assessments": "create_cross_contact_assessment",
            }
            if path in operation_routes:
                # The bundled HTTP server is intentionally *not* an identity
                # provider. An environment service principal must not stand in
                # for per-request manufacturer users. Service SDK methods can
                # be invoked only by a separately authenticated application.
                if isinstance(self.service.store, PostgresBaharStore) and not hasattr(self,'_verified_context'):
                    self._json(HTTPStatus.FORBIDDEN, {'error':'authenticated_operational_user_required',
                        'message':'Production operational mutations require per-request authentication and role/scope checks.'})
                    return
                if self.operations is None:
                    self._json(HTTPStatus.SERVICE_UNAVAILABLE,
                               {"error": "production persistence is not configured"})
                    return
                result = getattr(self.operations, operation_routes[path])(payload)
                self._json(HTTPStatus.CREATED, result)
                return
            if path == "/api/releases":
                if not hasattr(self,'_verified_context'):
                    self._json(HTTPStatus.FORBIDDEN,{'error':'authenticated_approval_required'})
                    return
                result=self.service.approve_release(str(payload['release_id']),str(payload['assessment_id']),
                    actor_id=self._verified_context['principal_id'],authority_role='release_authority',
                    reason=str(payload['reason']))
                self._json(HTTPStatus.CREATED,result)
                return
            self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
        except (ValueError, KeyError, json.JSONDecodeError, UnicodeDecodeError, OperationalScopeError) as exc:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request", "message": str(exc)})
        except (OperationsError, StoreError) as exc:
            self._json(HTTPStatus.CONFLICT, {"error": "state_conflict", "message": str(exc)})
        except IngestionError as exc:
            self._json(HTTPStatus.UNPROCESSABLE_ENTITY,
                       {"error": exc.code, "message": str(exc)})
        except IntegrityError as exc:
            self._json(HTTPStatus.CONFLICT,
                       {"error": "database_constraint", "message": "record violates a uniqueness or reference constraint"})
        except DBAPIError:
            self._json(HTTPStatus.BAD_REQUEST,
                       {"error": "database_request_rejected", "message": "the database rejected the record"})
        except Exception:
            self._json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "internal_error"})


class BaharServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], service: BaharService,
                 operations: OperationsService | None, bahar: BaharAIAdapter,
                 ingestion: IngestionService | None = None,
                 ingestion_repository: PostgresIngestionRepository | None = None,
                 layout_extractor: LayoutExtractor | None = None,
                 extraction_repository: PostgresExtractionRepository | None = None,
                 authenticator: OIDCAuthenticator | None = None):
        self.service = service
        self.authenticator = authenticator
        self.operations = operations
        self.bahar = bahar
        self.workflow = GovernedWorkflow(service.store, service)
        self.ingestion = ingestion
        self.ingestion_repository = ingestion_repository
        self.layout_extractor = layout_extractor
        self.extraction_repository = extraction_repository
        super().__init__(address, BaharHandler)


def serve(host: str = "127.0.0.1", port: int = 8088, database: str | Path = "bahar.sqlite3") -> None:
    if host not in ('127.0.0.1','::1','localhost'):
        if not (host=='0.0.0.0' and os.environ.get('BAHAR_ALLOW_CONTAINER_BIND')=='1'
                and os.environ.get('BAHAR_DATABASE_URL')):
            raise ValueError('Network binding requires an explicit private-container deployment and PostgreSQL')
    service = BaharService.from_environment() if os.environ.get("BAHAR_DATABASE_URL") else BaharService(database)
    operations = None
    ingestion = None
    ingestion_repository = None
    layout_extractor = None
    extraction_repository = None
    if isinstance(service.store, PostgresBaharStore):
        if host not in ('127.0.0.1','::1','localhost') and not (
                host=='0.0.0.0' and os.environ.get('BAHAR_ALLOW_CONTAINER_BIND')=='1'):
            raise ValueError('Production server requires loopback or explicitly configured private container binding')
        operations = OperationsService(service.store)
        # Production reference data and memberships are provisioned separately.
        # An environment service identity never acts as an HTTP user.
        settings = ProductionSettings.from_environment()
        object_store = S3ObjectStore(
            endpoint_url=settings.object_endpoint, region=settings.object_region,
            access_key=settings.object_access_key, secret_key=settings.object_secret_key,
            kms_key_id=settings.object_kms_key_id,
            buckets={
                "quarantine": settings.quarantine_bucket, "governed": settings.governed_bucket,
                "derived": settings.derived_bucket, "export": settings.exports_bucket,
                "audit": settings.audit_bucket,
                "backup": os.environ.get("BAHAR_OBJECT_BUCKET_BACKUP", "bahar-backup"),
            },
            encryption_mode=settings.object_encryption_mode, client_key=settings.object_client_key,
        )
        object_store.provision()
        ingestion_repository = PostgresIngestionRepository(service.store)
        ingestion = IngestionService(
            object_store, ClamdScanner(settings.clamd_host, settings.clamd_port), ingestion_repository,
            IngestionLimits(
                max_upload_bytes=settings.max_upload_bytes, max_pages=settings.max_pages,
                max_expanded_bytes=settings.max_expanded_bytes,
                max_expansion_ratio=settings.max_expansion_ratio,
            ),
        )
        layout_extractor = LayoutExtractor(tesseract_languages=settings.tesseract_languages)
        extraction_repository = PostgresExtractionRepository(service.store)
    authenticator = (OIDCAuthenticator(OIDCSettings.from_environment(),
        PostgreSQLMembershipDirectory(service.store.engine))
        if isinstance(service.store, PostgresBaharStore) else None)
    bahar = BaharAIAdapter(service.store)
    server = BaharServer(
        (host, port), service, operations, bahar, ingestion, ingestion_repository,
        layout_extractor, extraction_repository, authenticator,
    )
    print(f"Bahar listening on http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Bahar stopped.")
    finally:
        server.server_close()
        service.close()
