"""Attributable, immutable and tenant-scoped review and regulatory decisions.

No decision grants production release by itself; service release gates remain
independently mandatory. Identities and qualified roles come from the verified
per-request PostgresBaharStore context, never from submitted JSON.
"""
from __future__ import annotations
from sqlalchemy import text
from .persistence import PostgresBaharStore
from .store import StoreError

class ReviewerWorkflow:
    def __init__(self,store:PostgresBaharStore):self.store=store

    def _assessment(self,conn,key):
        row=conn.execute(text('SELECT input_sha256, technical_readiness FROM assessments WHERE organization_id=:o AND external_key=:k'),
            {'o':str(self.store.context.organization_id),'k':key}).mappings().first()
        if row is None:raise StoreError('assessment is not registered in this tenant')
        return row

    def _params(self,key):
        if not isinstance(key,str) or not (1<=len(key)<=256):raise StoreError('invalid assessment key')
        return {'o':str(self.store.context.organization_id),'k':key,'actor':str(self.store.context.principal_id)}

    def assign(self,key:str,reviewer_id:str,reason:str):
        import uuid
        p=self._params(key)
        try:p['reviewer']=str(uuid.UUID(reviewer_id))
        except (TypeError,ValueError) as exc:raise StoreError('invalid reviewer identifier') from exc
        if not isinstance(reason,str) or not reason.strip():raise StoreError('assignment rationale required')
        with self.store.transaction(serializable=True) as conn:
            self.store._require_role(conn,'tenant_administrator')
            self._assessment(conn,key)
            # Reviewers must hold an unrestricted, currently valid role.
            qualified=conn.execute(text('''SELECT EXISTS(SELECT 1 FROM memberships WHERE organization_id=:o AND principal_id=:reviewer
                AND role_name='reviewer' AND facility_id IS NULL AND valid_from<=clock_timestamp()
                AND (valid_until IS NULL OR valid_until>clock_timestamp()))'''),p).scalar_one()
            if not qualified:raise StoreError('assigned reviewer has no valid tenant-wide reviewer appointment')
            creator=conn.execute(text('''SELECT actor_id FROM audit_events WHERE organization_id=:o
                AND action='assessment_committed' AND target_id=:k ORDER BY created_at DESC LIMIT 1'''),p).scalar_one_or_none()
            if creator is None:raise StoreError('cannot prove the original assessment author')
            if str(creator) in (p['reviewer'],p['actor']):
                raise StoreError('independent reviewer and separate assignment authority required')
            conn.execute(text('''INSERT INTO review_assignments
                (organization_id,assessment_key,reviewer_id,assigned_by,assignment_reason)
                VALUES (:o,:k,:reviewer,:actor,:reason)'''),{**p,'reason':reason.strip()})
            self.store._audit(conn,action='review_assigned',target_type='assessment',target_id=key,
                 target_revision=None,outcome='success',reason=reason.strip(),
                 operation_id=f'review:{key}:assign',detail={'reviewer_id':p['reviewer']})
        return {'assessment_id':key,'reviewer_id':p['reviewer'],'state':'assigned'}

    def decide(self,key:str,verdict:str,reason:str):
        if verdict not in {'accepted_for_review','rejected','needs_changes'}:raise StoreError('invalid reviewer decision')
        p=self._params(key)
        if not isinstance(reason,str) or not reason.strip():raise StoreError('review reason required')
        with self.store.transaction(serializable=True) as conn:
            self.store._require_role(conn,'reviewer')
            rec=self._assessment(conn,key)
            assignment=conn.execute(text('''SELECT reviewer_id FROM review_assignments
                WHERE organization_id=:o AND assessment_key=:k FOR UPDATE'''),p).scalar_one_or_none()
            if str(assignment)!=p['actor']:raise StoreError('assessment not assigned to this reviewer')
            if verdict=='accepted_for_review' and str(rec['technical_readiness']).lower()!='ready_for_review':
                raise StoreError('technical readiness prerequisite not satisfied')
            conn.execute(text('''INSERT INTO review_decisions
                (organization_id,assessment_key,reviewer_id,verdict,reason,assessment_digest)
                VALUES (:o,:k,:actor,:v,:reason,:digest)'''),{**p,'v':verdict,'reason':reason.strip(),
                                                               'digest':str(rec['input_sha256'])})
            self.store._audit(conn,action='review_decision',target_type='assessment',target_id=key,
                 target_revision=None,outcome=verdict,reason=reason.strip(),
                 operation_id=f'review:{key}:decision',detail={'verdict':verdict})
        return {'assessment_id':key,'decision':verdict,'claim':'HUMAN_REVIEW_ONLY'}

    def regulatory_decide(self,key:str,verdict:str,reason:str):
        if verdict not in {'approved_for_further_release_checks','rejected'}:raise StoreError('invalid regulatory decision')
        if not isinstance(reason,str) or not reason.strip():raise StoreError('regulatory reason required')
        p=self._params(key)
        with self.store.transaction(serializable=True) as conn:
            self.store._require_role(conn,'regulatory_approver')
            rec=self._assessment(conn,key)
            last=conn.execute(text('''SELECT reviewer_id,verdict,assessment_digest FROM review_decisions
                WHERE organization_id=:o AND assessment_key=:k ORDER BY decided_at DESC, decision_id DESC LIMIT 1'''),p).mappings().first()
            if not last or last['verdict']!='accepted_for_review' or last['assessment_digest']!=rec['input_sha256']:
                raise StoreError('qualified current reviewer acceptance is missing')
            if str(last['reviewer_id'])==p['actor']:raise StoreError('regulatory approver cannot self-approve review')
            conn.execute(text('''INSERT INTO regulatory_review_decisions
                (organization_id,assessment_key,approver_id,verdict,reason,assessment_digest)
                VALUES (:o,:k,:actor,:v,:reason,:digest)'''),{**p,'v':verdict,'reason':reason.strip(),
                                                             'digest':str(rec['input_sha256'])})
            self.store._audit(conn,action='regulatory_review_decision',target_type='assessment',target_id=key,
                 target_revision=None,outcome=verdict,reason=reason.strip(),
                 operation_id=f'review:{key}:regulatory',detail={'verdict':verdict})
        return {'assessment_id':key,'decision':verdict,'claim':'NOT_A_RELEASE_AUTHORIZATION'}

    def require_release_reviews(self,key:str,release_authority:str) -> None:
        """Independent current human decisions are mandatory, but never sufficient, for release."""
        p=self._params(key)
        with self.store.transaction() as conn:
            record=self._assessment(conn,key)
            review=conn.execute(text("""SELECT reviewer_id, verdict, assessment_digest, decided_at
                FROM review_decisions WHERE organization_id=:o AND assessment_key=:k
                ORDER BY decided_at DESC, decision_id DESC LIMIT 1"""),p).mappings().first()
            reg=conn.execute(text("""SELECT approver_id, verdict, assessment_digest, decided_at
                FROM regulatory_review_decisions WHERE organization_id=:o AND assessment_key=:k
                ORDER BY decided_at DESC, decision_id DESC LIMIT 1"""),p).mappings().first()
            if not review or review['verdict']!='accepted_for_review' or review['assessment_digest']!=record['input_sha256']:
                raise StoreError('current independent reviewer acceptance is required')
            if not reg or reg['verdict']!='approved_for_further_release_checks' or reg['assessment_digest']!=record['input_sha256']:
                raise StoreError('current regulatory approval is required')
            if reg['decided_at']<review['decided_at']:
                raise StoreError('regulatory approval predates latest reviewer decision')
            if len({str(review['reviewer_id']),str(reg['approver_id']),str(release_authority)})!=3:
                raise StoreError('reviewer, regulatory approver and release authority must be distinct')

    def history(self,key:str):
        p=self._params(key)
        with self.store.transaction() as conn:
            self._assessment(conn,key)
            assignment=conn.execute(text('''SELECT assessment_key,reviewer_id,assigned_by,assigned_at,assignment_reason
                FROM review_assignments WHERE organization_id=:o AND assessment_key=:k'''),p).mappings().first()
            reviews=conn.execute(text('''SELECT reviewer_id,verdict,reason,assessment_digest,decided_at
                FROM review_decisions WHERE organization_id=:o AND assessment_key=:k ORDER BY decided_at'''),p).mappings().all()
            regulatory=conn.execute(text('''SELECT approver_id,verdict,reason,assessment_digest,decided_at
                FROM regulatory_review_decisions WHERE organization_id=:o AND assessment_key=:k ORDER BY decided_at'''),p).mappings().all()
        def normal(rows):return [{k:v.isoformat() if hasattr(v,'isoformat') else str(v) if k.endswith('_id') else v
                                  for k,v in row.items()} for row in rows]
        return {'assessment_id':key,'assignment':normal([assignment])[0] if assignment else None,
                'review_decisions':normal(reviews),'regulatory_decisions':normal(regulatory),
                'release_authorized':False}
