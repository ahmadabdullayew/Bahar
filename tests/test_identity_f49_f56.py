"""Security tests: cryptographic identity, tenant selection, roles and MFA."""
from __future__ import annotations
import os
from http import HTTPStatus
from types import SimpleNamespace
import time
import uuid

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from bahar.http_identity import (
    OIDCSettings,OIDCAuthenticator,AuthenticationError,VerifiedActor,
    HTTP_OPERATION_ACTIONS,WRITE_ROLES,PRIVILEGED_ROUTES,
)
from bahar.authorization import OPERATION_ACTION_ROLES
from bahar.api import BaharHandler

ORG1=str(uuid.uuid4());ORG2=str(uuid.uuid4());OTHER=str(uuid.uuid4());ACTOR=str(uuid.uuid4())
SETTINGS=OIDCSettings('https://sso.example.test/realms/bahar','bahar-api',
    'https://sso.example.test/realms/bahar/protocol/openid-connect/certs','bahar-spa',
    'https://sso.example.test/realms/bahar/protocol/openid-connect/auth',
    'https://sso.example.test/realms/bahar/protocol/openid-connect/token',
    'https://app.example.test/',('urn:example:mfa',),300)
KEY=rsa.generate_private_key(public_exponent=65537,key_size=2048)

class SigningKey:
    def __init__(self):self.key=KEY.public_key()
class JWKSStub:
    def get_signing_key_from_jwt(self,token):return SigningKey()
class Directory:
    def __init__(self):self.records=[
        {'organization_id':ORG1,'principal_id':ACTOR,'role_name':'analyst','facility_id':None},
        {'organization_id':ORG1,'principal_id':ACTOR,'role_name':'reviewer','facility_id':str(uuid.uuid4())},
        {'organization_id':ORG2,'principal_id':ACTOR,'role_name':'auditor','facility_id':None}]
    def memberships(self,actor):
        return self.records if (actor.issuer,actor.subject)==(SETTINGS.issuer,'user-123') else []

NOW=int(time.time())
def token(**overrides):
    claims={'iss':SETTINGS.issuer,'aud':SETTINGS.audience,'sub':'user-123',
        'iat':NOW-5,'nbf':NOW-5,'exp':NOW+300,'azp':SETTINGS.client_id,'amr':['mfa'], 'auth_time':NOW-10}
    claims.update(overrides)
    return jwt.encode(claims,KEY,algorithm='RS256',headers={'kid':'test-key'})

def authenticator():return OIDCAuthenticator(SETTINGS,Directory(),jwks_client=JWKSStub(),clock=lambda:NOW)

def test_token_cryptographic_validation_and_claims():
    obj=authenticator();actor=obj.authenticate('Bearer '+token())
    assert actor.subject=='user-123'
    for bad in (token(aud='elsewhere'),token(iss='https://other.test'),token(exp=NOW-500),
                token(iat=NOW-900,exp=NOW+1000)):
        with pytest.raises(AuthenticationError):obj.authenticate('Bearer '+bad)
    for bad in (token(azp='other-spa'), token(token_use='id')):
        with pytest.raises(AuthenticationError):obj.authenticate('Bearer '+bad)
    with pytest.raises(AuthenticationError):obj.authenticate(None)
    with pytest.raises(AuthenticationError):obj.authenticate('Bearer invalid')
    with pytest.raises(AuthenticationError):obj.authenticate('Bearer '+jwt.encode(
        {'iss':SETTINGS.issuer,'sub':'user-123','aud':SETTINGS.audience,'iat':NOW,'nbf':NOW,'exp':NOW+60},
        'attacker-secret-strongly-random-32-bytes',algorithm='HS256'))


def test_role_claims_cannot_create_membership_and_cross_tenant_refused():
    obj=authenticator();actor=obj.authenticate('Bearer '+token(roles=['release_authority'],organization_id=OTHER))
    ctx=obj.select_tenant(actor,ORG1)
    assert ctx['principal_id']==ACTOR
    assert ctx['roles']==['analyst']
    assert ctx['facility_limited_roles']==['reviewer']
    with pytest.raises(AuthenticationError) as exc:obj.require(ctx,'release_authority',actor)
    assert exc.value.status==403
    with pytest.raises(AuthenticationError):obj.select_tenant(actor,OTHER)
    with pytest.raises(AuthenticationError):obj.select_tenant(actor,None)
    assert obj.select_tenant(actor,ORG2)['roles']==['auditor']
    with pytest.raises(AuthenticationError):obj.require(obj.select_tenant(actor,ORG2),'analyst',actor)


def test_privileged_requires_fresh_actual_mfa():
    obj=authenticator();identity={'roles':['release_authority']}
    obj.require(identity,'release_authority',obj.authenticate('Bearer '+token()),privileged=True)
    for claims in ({'amr':[],'acr':'password'}, {'auth_time':NOW-400}, {'auth_time':None},
                   {'amr':['pwd'],'acr':None}):
        actor=obj.authenticate('Bearer '+token(**claims))
        with pytest.raises(AuthenticationError) as exc:
            obj.require(identity,'release_authority',actor,privileged=True)
        assert exc.value.code=='fresh_mfa_required'
    assert all(path in PRIVILEGED_ROUTES for path in
        ('/api/releases','/api/reviews/assign','/api/reviews/decision','/api/reviews/regulatory-decision'))


def make_handler(roles=('analyst',),selected=ORG1,jwt_string=None):
    obj=authenticator();directory=obj.directory
    directory.records=[{'organization_id':ORG1,'principal_id':ACTOR,'role_name':role,'facility_id':None} for role in roles]
    engine=object()
    store=SimpleNamespace(engine=engine,audit_hmac_key=b'x'*32,audit_key_id='test')
    server=SimpleNamespace(authenticator=obj,service=SimpleNamespace(store=store),
        operations=None,bahar=None,workflow=None,ingestion=None,ingestion_repository=None,
        extraction_repository=None)
    handler=object.__new__(BaharHandler)
    handler.server=server
    handler.headers={'Authorization':'Bearer '+(jwt_string or token()),'X-Bahar-Tenant':selected}
    replies=[];handler._json=lambda code,body:replies.append((int(code),body))
    return handler,replies


def test_http_default_denies_unassigned_authority(monkeypatch):
    monkeypatch.setenv('BAHAR_DATABASE_URL','postgresql+psycopg://example/bahar')
    for path in ('/api/releases','/api/reviews/decision','/api/evidence/reviews','/api/inspections',
                 '/api/not-a-whitelisted-action'):
        handler,responses=make_handler(roles=('analyst',))
        assert handler._authorize_http(path,'POST') is False
        assert responses[-1][0]==403
        assert not hasattr(handler,'_verified_context')


def test_http_actor_bound_without_app_global_mutation(monkeypatch):
    monkeypatch.setenv('BAHAR_DATABASE_URL','postgresql+psycopg://example/bahar')
    handler,responses=make_handler()
    assert handler._authorize_http('/api/assess','POST') is True
    assert handler.service.store.context.principal_id==uuid.UUID(ACTOR)
    assert handler.service.store.context.organization_id==uuid.UUID(ORG1)
    assert handler.service.store.context.service_identity is None
    handler,responses=make_handler(selected=OTHER)
    assert handler._authorize_http('/api/assess','POST') is False
    assert responses[-1][1]['error']=='tenant_access_denied'
    handler,responses=make_handler(jwt_string=token(aud='wrong'))
    assert handler._authorize_http('/api/assess','POST') is False
    assert responses[-1][0]==401


def test_get_tenant_list_does_not_include_other_tenants(monkeypatch):
    monkeypatch.setenv('BAHAR_DATABASE_URL','postgresql+psycopg://example/bahar')
    handler,responses=make_handler()
    assert handler._authorize_http('/api/auth/tenants','GET') is False
    assert responses[-1][0]==200
    assert [t['organization_id'] for t in responses[-1][1]['tenants']]==[ORG1]


def test_http_operation_paths_are_mapped_and_no_wildcard():
    assert len(HTTP_OPERATION_ACTIONS)>=20
    assert len(HTTP_OPERATION_ACTIONS)==len(set(HTTP_OPERATION_ACTIONS))
    assert all(operation in OPERATION_ACTION_ROLES for operation in HTTP_OPERATION_ACTIONS.values())
    assert WRITE_ROLES['/api/releases']=='release_authority'
    assert WRITE_ROLES['/api/reviews/regulatory-decision']=='regulatory_approver'
    assert WRITE_ROLES['/api/evidence/sources']=='reviewer'
    assert '/api/a-secret-backdoor' not in WRITE_ROLES


def test_oidc_production_env_fail_closed(monkeypatch):
    for key in ('BAHAR_OIDC_ISSUER','BAHAR_OIDC_AUDIENCE','BAHAR_OIDC_CLIENT_ID'):
        monkeypatch.delenv(key,raising=False)
    with pytest.raises(ValueError):OIDCSettings.from_environment()


def test_reviewer_directory_requires_tenant_admin(monkeypatch):
    monkeypatch.setenv('BAHAR_DATABASE_URL','postgresql+psycopg://example/bahar')
    handler,responses=make_handler(roles=('analyst',))
    assert handler._authorize_http('/api/reviewers','GET') is False
    assert responses[-1][1]['error']=='reviewer_directory_role_required'


def test_client_actor_claim_rejected_before_release_write():
    handler,responses=make_handler(roles=('release_authority',))
    handler.path='/api/releases'
    handler._authorize_http=lambda path,method:True
    handler._read_json=lambda: {'release_id':'r','assessment_id':'a','actor_id':'attacker',
                                'authority_role':'release_authority','reason':'bad'}
    handler._verified_context={'principal_id':ACTOR}
    handler.do_POST()
    assert responses[-1][0]==400
    assert responses[-1][1]['error']=='untrusted_identity_fields_forbidden'


def test_csp_permits_only_configured_https_token_exchange_origin():
    handler,_=make_handler()
    csp=handler._content_security_policy()
    assert "connect-src 'self' https://sso.example.test" in csp
    assert "object-src 'none'" in csp
    assert "frame-ancestors 'none'" in csp
