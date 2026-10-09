"""Fail-closed OIDC resource-server identity and tenant membership binding.

Bearer ACCESS tokens are verified against a configured issuer, API audience and
trusted JWKS. Only the database's membership records grant roles; JWT fields,
client JSON, request headers and the old service principal never grant roles.

No implicit user provisioning, no self-service role assignment, no local
password database, and no permission to change the access-token issuer.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from functools import cached_property
import json
import os
import time
import uuid
from typing import Any, Protocol
from urllib.parse import urlsplit

import jwt
from jwt import PyJWKClient
from sqlalchemy import text


class AuthenticationError(ValueError):
    def __init__(self, code: str, status: int = 401):
        super().__init__(code)
        self.code = code
        self.status = status


def trusted_https(value: str, label: str) -> str:
    parts = urlsplit(value)
    if parts.scheme != 'https' or not parts.hostname or parts.username or parts.password or parts.fragment:
        raise ValueError(f'{label} must be an HTTPS URL without credentials or a fragment')
    return value


@dataclass(frozen=True)
class OIDCSettings:
    issuer: str
    audience: str
    jwks_url: str
    client_id: str
    authorize_url: str
    token_url: str
    redirect_uri: str
    mfa_acr_values: tuple[str, ...] = ()
    fresh_auth_seconds: int = 300

    @classmethod
    def from_environment(cls) -> 'OIDCSettings':
        names = ('ISSUER','AUDIENCE','JWKS_URL','CLIENT_ID','AUTHORIZE_URL','TOKEN_URL','REDIRECT_URI')
        values = {name: os.environ.get('BAHAR_OIDC_'+name, '').strip() for name in names}
        missing = [name for name, value in values.items() if not value]
        if missing:
            raise ValueError('Production authentication requires OIDC settings: '+', '.join(missing))
        issuer = trusted_https(values['ISSUER'],'issuer').rstrip('/')
        jwks = trusted_https(values['JWKS_URL'],'JWKS URL')
        authorize = trusted_https(values['AUTHORIZE_URL'],'authorization URL')
        token = trusted_https(values['TOKEN_URL'],'token URL')
        redirect = trusted_https(values['REDIRECT_URI'],'redirect URL')
        # JWKS/token/authorize must be held by the configured issuer origin.
        origin = (urlsplit(issuer).hostname, urlsplit(issuer).port)
        for label, uri in [('JWKS',jwks),('authorize',authorize),('token',token)]:
            part=urlsplit(uri)
            if (part.hostname,part.port)!=origin:
                raise ValueError(label+' endpoint must share the issuer origin')
        if not values['AUDIENCE'] or values['AUDIENCE']==values['CLIENT_ID']:
            raise ValueError('API audience must be distinct from browser client_id (never accept ID tokens)')
        return cls(issuer=issuer,audience=values['AUDIENCE'],jwks_url=jwks,
          client_id=values['CLIENT_ID'],authorize_url=authorize,token_url=token,
          redirect_uri=redirect,
          mfa_acr_values=tuple(filter(None,os.getenv('BAHAR_OIDC_MFA_ACR','').split(','))),
          fresh_auth_seconds=int(os.getenv('BAHAR_OIDC_FRESH_AUTH_SECONDS','300')))


@dataclass(frozen=True)
class VerifiedActor:
    issuer: str
    subject: str
    expires_at: int
    auth_time: int | None
    amr: tuple[str, ...]
    acr: str | None

    def fresh_mfa(self, now: int, settings: OIDCSettings) -> bool:
        mfa = 'mfa' in self.amr or 'otp' in self.amr or 'hwk' in self.amr or (
            bool(self.acr) and self.acr in settings.mfa_acr_values)
        return bool(mfa and self.auth_time is not None and
                    0 <= now-self.auth_time <= settings.fresh_auth_seconds)


class MembershipDirectory(Protocol):
    def memberships(self, actor: VerifiedActor) -> list[dict[str, Any]]: ...


class PostgreSQLMembershipDirectory:
    """Authorized lookup is performed by a restricted SECURITY DEFINER SQL function.

    The function is the only global identity lookup exposed to bahar_app.
    The application always verifies the JWT BEFORE passing issuer/sub here.
    """
    def __init__(self, engine: Any):
        self.engine = engine

    def memberships(self, actor: VerifiedActor) -> list[dict[str, Any]]:
        with self.engine.connect() as conn:
            rows=conn.execute(text('SELECT * FROM auth_actor_memberships(:issuer,:subject)'),
                 {'issuer':actor.issuer,'subject':actor.subject}).mappings().all()
        return [dict(row) for row in rows]


class OIDCAuthenticator:
    def __init__(self, settings: OIDCSettings, directory: MembershipDirectory,
                 *, jwks_client: Any = None, clock: Any = None):
        self.settings=settings
        self.directory=directory
        self.jwks_client=jwks_client or PyJWKClient(settings.jwks_url,
            cache_jwk_set=True,lifespan=300,cache_keys=False)
        self.clock=clock or (lambda:int(time.time()))

    def authenticate(self, authorization: str | None) -> VerifiedActor:
        if not authorization or not authorization.startswith('Bearer ') or authorization.count(' ')!=1:
            raise AuthenticationError('bearer_access_token_required')
        token=authorization[7:]
        if not token or len(token)>16384:
            raise AuthenticationError('invalid_access_token')
        try:
            key=self.jwks_client.get_signing_key_from_jwt(token).key
            claims=jwt.decode(token,key,algorithms=['RS256','ES256'],
              audience=self.settings.audience,issuer=self.settings.issuer,
              options={'require':['iss','sub','aud','exp','iat','nbf']},leeway=15)
            # The browser API accepts only access tokens minted for this
            # configured public client, not a different OAuth client sharing
            # the same API audience.
            authorized_client=claims.get('azp',claims.get('client_id'))
            if authorized_client != self.settings.client_id:
                raise AuthenticationError('access_token_client_not_authorized')
            if claims.get('token_use','access')!='access':
                raise AuthenticationError('id_token_not_accepted')
            subject=claims.get('sub')
            if not isinstance(subject,str) or not 1<=len(subject)<=512:
                raise AuthenticationError('invalid_access_token')
            amr=claims.get('amr',[])
            if not isinstance(amr,list) or any(not isinstance(x,str) for x in amr):
                amr=[]
            auth_time=claims.get('auth_time')
            if auth_time is not None and (type(auth_time) is not int or auth_time>self.clock()+15):
                raise AuthenticationError('invalid_auth_time')
            if int(claims['exp'])-int(claims['iat'])>900:
                raise AuthenticationError('access_token_lifetime_exceeds_policy')
            return VerifiedActor(self.settings.issuer,subject,int(claims['exp']),auth_time,
                                 tuple(amr),claims.get('acr') if isinstance(claims.get('acr'),str) else None)
        except AuthenticationError:
            raise
        except Exception as exc:
            raise AuthenticationError('invalid_access_token') from exc

    def memberships(self, actor: VerifiedActor) -> list[dict[str, Any]]:
        # Never infer a tenant or role from token-controlled custom claims.
        return self.directory.memberships(actor)

    def select_tenant(self, actor: VerifiedActor, tenant: str | None) -> dict[str, Any]:
        try:
            organization_id=str(uuid.UUID(tenant or ''))
        except (ValueError,AttributeError) as exc:
            raise AuthenticationError('tenant_selection_required',403) from exc
        entries=[r for r in self.memberships(actor) if str(r['organization_id'])==organization_id]
        if not entries:
            raise AuthenticationError('tenant_access_denied',403)
        principals={str(r['principal_id']) for r in entries}
        if len(principals)!=1:
            raise AuthenticationError('ambiguous_actor_identity',403)
        return {'organization_id':organization_id,'principal_id':next(iter(principals)),
                'roles':sorted({str(r['role_name']) for r in entries if r.get('facility_id') is None}),
                'facility_limited_roles':sorted({str(r['role_name']) for r in entries if r.get('facility_id') is not None})}

    def require(self, identity: dict[str,Any], role: str, actor: VerifiedActor,
                *, privileged: bool = False) -> None:
        if role not in identity['roles']:
            raise AuthenticationError('role_not_granted',403)
        if privileged and not actor.fresh_mfa(self.clock(),self.settings):
            raise AuthenticationError('fresh_mfa_required',403)


# Exact action × role matrix, not permissive wildcard matching.
HTTP_GET_ROLE = {
    '/api/dashboard':'auditor',  # analyst/reviewer can also access via READ_ROLES below
    '/api/evidence/corrections':'reviewer',
}
READ_ROLES = frozenset({'auditor','analyst','reviewer','regulatory_approver',
                        'release_authority','incident_manager','tenant_administrator'})
WRITE_ROLES = {
    '/api/assess':'analyst','/api/assess/governed':'analyst',
    '/api/ai/audit':'analyst','/api/ai/compare':'analyst',
    '/api/ai/reviewed':'reviewer','/api/documents':'analyst',
    '/api/evidence/sources':'reviewer','/api/evidence/assertions':'reviewer',
    '/api/evidence/reviews':'reviewer','/api/evidence/coverage':'reviewer',
    '/api/evidence/bundles':'reviewer','/api/evidence/corrections':'reviewer',
    '/api/evidence/correction-decisions':'reviewer','/api/evidence/derivatives':'reviewer',
    '/api/releases':'release_authority',
    '/api/reviews/assign':'tenant_administrator',
    '/api/reviews/decision':'reviewer',
    '/api/reviews/regulatory-decision':'regulatory_approver',
}
HTTP_OPERATION_ACTIONS={
    '/api/suppliers':'supplier_registered','/api/materials':'material_registered',
    '/api/supplier-identifiers':'supplier_material_identifier_registered',
    '/api/specifications':'material_specification_registered','/api/lots':'supplier_lot_registered',
    '/api/receipts':'material_receipt_registered','/api/origin-findings':'origin_finding_recorded',
    '/api/supplier-corrections':'supplier_correction_recorded',
    '/api/formulations':'formulation_registered','/api/formulation-versions':'formulation_version_registered',
    '/api/labels':'label_text_registered','/api/printer-specifications':'printer_specification_registered',
    '/api/artworks':'artwork_registered','/api/artwork-assessments':'artwork_assessed',
    '/api/lines':'production_line_registered','/api/equipment':'equipment_registered',
    '/api/packaging-lots':'packaging_lot_registered','/api/batches':'manufacturing_batch_recorded',
    '/api/camera-qualifications':'camera_qualification_registered',
    '/api/sampling-plans':'sampling_plan_registered','/api/inspections':'physical_package_inspected',
    '/api/cleaning-events':'cleaning_event_recorded',
    '/api/cross-contact-assessments':'cross_contact_assessed',
}

PRIVILEGED_ROUTES=frozenset({'/api/releases','/api/reviews/assign','/api/reviews/decision','/api/reviews/regulatory-decision'})


def required_post_role(path: str) -> str | None:
    if path in WRITE_ROLES:
        return WRITE_ROLES[path]
    if path in ('/api/operational/preview',):
        return None
    return None  # other operational routes are resolved by explicit route map
