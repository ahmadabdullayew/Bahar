"""Governed operational evidence ledger for F39-F48.

Privileged methods are for an authenticated service layer with a distinct, verified
TenantContext per real user. They MUST NOT be exposed by the developer HTTP server.
PostgreSQL revisions, audit entry and conservative release invalidation share one
transaction. SQLite is exclusively for local demonstrations.
"""
from __future__ import annotations
import uuid
from copy import deepcopy
from typing import Any
from sqlalchemy import text
from .assessment import digest
from .audit import stable_bytes
from .operational_scope import (
    OperationalScopeError, POLICY_ROLES, MATERIAL_KINDS, AUTHORITATIVE_KINDS,
    operational_assurance, incident_transition,
)
from .persistence import PostgresBaharStore
from .store import StoreError


class OperationalWorkflowError(StoreError):
    pass


class OperationalWorkflow:
    def __init__(self, store: Any):
        self.store=store

    def _actor(self) -> str:
        return str(self.store.context.principal_id) if isinstance(self.store,PostgresBaharStore) else 'LOCAL_DEMO'

    @staticmethod
    def _key(kind: str, record_id: str) -> str:
        if kind not in POLICY_ROLES:
            raise OperationalWorkflowError('unrecognized operational event kind')
        if not isinstance(record_id,str) or not record_id or len(record_id)>180 or '/' in record_id:
            raise OperationalWorkflowError('record_id must be an unambiguous short identifier')
        return f'operational:{kind}:{record_id}'

    def _get(self,key: str) -> dict|None:
        if not isinstance(self.store,PostgresBaharStore):
            return self.store.get_object(key)
        with self.store.transaction() as connection:
            row=connection.execute(text('''
              SELECT revision,kind,body,body_sha256,actor_id,created_at
              FROM operational_assurance_events
              WHERE organization_id=:org AND record_key=:key
              ORDER BY revision DESC LIMIT 1'''),
              {'org':str(self.store.context.organization_id),'key':key}).mappings().first()
        if not row:return None
        value=dict(row)
        return {'id':key,'version':int(value['revision']),'type':str(value['kind']),
                'body':dict(value['body']),'digest':str(value['body_sha256']),
                'actor_id':str(value['actor_id']),'created_at':str(value['created_at'])}

    def read(self,kind:str,record_id:str) -> dict|None:
        record=self._get(self._key(kind,record_id))
        if record and record['digest'] != digest(record['body']):
            raise OperationalWorkflowError('operational record integrity failure')
        return record

    def _validate(self,kind:str,body:dict,previous:dict|None) -> dict:
        if not isinstance(body,dict):
            raise OperationalWorkflowError('operational payload must be a JSON object')
        if 'actor_id' in body or 'approved_by' in body or 'authority_role' in body:
            raise OperationalWorkflowError('actor authority cannot be supplied in business data')
        if kind=='incident':
            if previous is None:
                if body.get('state')!='reported' or not body.get('incident_id') or not body.get('description'):
                    raise OperationalWorkflowError('new incident requires reported state, incident_id, description')
            else:
                checked=incident_transition(previous['body']['payload'],str(body.get('state')),
                           evidence_refs=body.get('evidence_refs',[]),affected_lots=body.get('affected_lots',[]),
                           rationale=str(body.get('reason','')))
                if checked['incident_id']!=body.get('incident_id'):
                    raise OperationalWorkflowError('incident identity cannot change')
                body={**body,'external_notification_state':'NOT_SENT_BY_BAHAR'}
        if kind=='external_notification_receipt':
            if not all(body.get(x) for x in ('incident_ref','authority','destination','receipt_artifact_ref','receipt_digest','sent_at')):
                raise OperationalWorkflowError('external notification needs independently retained delivery receipt')
            if body.get('delivery_verified') is not True:
                raise OperationalWorkflowError('a proposed notification cannot be recorded as delivered')
        if kind=='legal_interpretation':
            if not all(body.get(x) for x in ('jurisdiction','citation','legal_source_ref','interpretation_version')):
                raise OperationalWorkflowError('legal interpretation requires exact source and jurisdiction')
        if kind=='market_package_configuration':
            checked=operational_assurance(kind,body,qualified=False)
            if checked['state']=='indeterminate':
                raise OperationalWorkflowError('configuration identity is incomplete: '+','.join(checked['missing']))
        return body

    def record(self,kind:str,record_id:str,body:dict,*,expected_version:int=0) -> dict:
        """Append an observed/draft record; NEVER elevate its data to factual truth."""
        key=self._key(kind,record_id)
        if type(expected_version) is not int or expected_version<0:
            raise OperationalWorkflowError('expected_version must be a nonnegative integer')
        previous=self.read(kind,record_id)
        if (previous['version'] if previous else 0)!=expected_version:
            raise OperationalWorkflowError('stale operational revision')
        body=self._validate(kind,deepcopy(body),previous)
        entry={'kind':kind,'record_id':record_id,'payload':body,'proposer_id':self._actor(),
               'authority':'UNQUALIFIED_OPERATIONAL_RECORD',
               'scope':'PRODUCTION_RECORD_NOT_DOMAIN_VERIFIED' if isinstance(self.store,PostgresBaharStore) else 'DEMO_ONLY'}
        # Do not silently accept a claimed legal qualification, external system
        # acknowledgment, signed method record, or completed physical inspection.
        if not isinstance(self.store,PostgresBaharStore):
            created=self.store.put_object(key,kind,entry,actor_id='LOCAL_DEMO',
                operation_id=f'operational:{uuid.uuid4()}',expected_latest_version=expected_version)
            return {'record':created,'assurance':operational_assurance(kind,body,qualified=False),
                    'authority':'DEMO_ONLY','transactional_release_invalidation':'NOT_APPLICABLE'}
        org=str(self.store.context.organization_id)
        actor=self._actor()
        def commit():
            with self.store.transaction(serializable=True) as connection:
                self.store._require_role(connection,POLICY_ROLES[kind])
                # Advisory lock serializes first write and prevents create-create races.
                connection.execute(text('SELECT pg_advisory_xact_lock(hashtext(:org),hashtext(:key))'),
                                   {'org':org,'key':key})
                last=connection.execute(text('''SELECT revision,kind FROM operational_assurance_events
                   WHERE organization_id=:org AND record_key=:key ORDER BY revision DESC LIMIT 1'''),
                   {'org':org,'key':key}).mappings().first()
                if (int(last['revision']) if last else 0)!=expected_version:
                    raise OperationalWorkflowError('stale operational revision')
                if last and str(last['kind'])!=kind:
                    raise OperationalWorkflowError('operational kind cannot change')
                version=expected_version+1
                operation_id=f'operational:{key}:{version}:{uuid.uuid4()}'
                connection.execute(text('''INSERT INTO operational_assurance_events
                  (organization_id,record_key,revision,kind,body,body_sha256,actor_id,operation_id)
                  VALUES (:org,:key,:version,:kind,CAST(:body AS jsonb),:sha,:actor,:operation)'''),
                  {'org':org,'key':key,'version':version,'kind':kind,
                   'body':stable_bytes(entry).decode('utf-8'),'sha':digest(entry),
                   'actor':actor,'operation':operation_id})
                impact=self.store.suspend_active_releases_in_transaction(
                    connection,change_key=key,reason=f'{kind} operational event requires scope review') \
                    if kind in MATERIAL_KINDS else {'impact_completeness':'not_assessed','suspended_release_ids':[]}
                self.store._audit(connection,action=f'operational_{kind}_recorded',target_type='operational_event',
                    target_id=key,target_revision=version,outcome='success',reason='unqualified record received',
                    operation_id=operation_id,detail={'digest':digest(entry),'impact_control':impact})
                return {'record':{'id':key,'type':kind,'version':version,'digest':digest(entry)},
                        'assurance':operational_assurance(kind,body,qualified=False),
                        'authority':'UNQUALIFIED_OPERATIONAL_RECORD','impact_control':impact}
        return self.store.retry_serializable(commit)

    def qualify(self,kind:str,record_id:str,*,basis_refs:list[str],decision_reason:str) -> dict:
        """Second-person record review. A reviewer signature is NOT scientific truth.

        Required for production; a mere boolean approved in the payload is ignored.
        Authentication must happen outside this service, binding TenantContext to
        the real individual. Baseline HTTP does not expose this method.
        """
        if not isinstance(self.store,PostgresBaharStore):
            raise OperationalWorkflowError('qualified operational approval requires authenticated production governance')
        if kind not in AUTHORITATIVE_KINDS:
            raise OperationalWorkflowError('this record kind has no standalone qualification transition')
        observed=self.read(kind,record_id)
        if not observed:
            raise OperationalWorkflowError('review subject missing')
        proposer=observed['body']['proposer_id']
        if proposer==self._actor():
            raise OperationalWorkflowError('segregation of duties: proposer cannot qualify own record')
        if not decision_reason.strip() or not isinstance(basis_refs,list) or not basis_refs:
            raise OperationalWorkflowError('qualification needs reason and independently retained basis references')
        for ref in basis_refs:
            source=self.store.get_object(str(ref))
            if not source or source.get('type') not in {'regulatory_source','governed_rule','evidence_source',
                'evidence_bundle','assessment_contract','regulated_artifact','evidence_assertion'}:
                raise OperationalWorkflowError(f'qualification basis is not governed: {ref}')
        if kind=='legal_interpretation' and observed['body']['payload']['legal_source_ref'] not in basis_refs:
            raise OperationalWorkflowError('legal source must be included in independently verified basis')
        with self.store.transaction() as connection:
            self.store._require_role(connection,POLICY_ROLES[kind])
        # Separate append-only record. Do not modify the original. A production
        # verifier must check external scientific suitability before stronger claims.
        key=f'qualification:{kind}:{record_id}:{observed["version"]}'
        value={'source_record_key':observed['id'],'source_revision':observed['version'],
               'source_digest':observed['digest'],'basis_refs':basis_refs,
               'decision_reason':decision_reason,'qualified_by':self._actor(),
               'qualification_level':'DOCUMENTARY_GOVERNANCE_ONLY',
               'production_compliance_verdict':'NOT_ESTABLISHED'}
        return self.store.put_object(key,'operational_qualification',value,
            actor_id=self._actor(),operation_id=f'qualification:{uuid.uuid4()}',expected_latest_version=0)
