"""Explicit authority boundaries connecting lexical observations and controlled assessment.

A lexical observation is NEVER silently upgraded into an accepted identity or
regulatory rule. Governance operations are privileged service operations; the
public HTTP server does not expose rule or reviewer approval mutations.
"""
from __future__ import annotations

from copy import deepcopy
import re
from sqlalchemy import text
from typing import Any

from .assessment import DEFAULT_REQUIRED_CHECKS, digest
from bahar_ai_core.knowledge import KNOWLEDGE
from .knowledge import normalize_candidate
from .persistence import PostgresBaharStore
from .store import StoreError


class GovernanceError(StoreError):
    pass


def _principal(store: Any) -> str:
    return str(store.context.principal_id) if hasattr(store, 'context') else 'LOCAL_DEMONSTRATION_ONLY'


def _require_role(store: Any, role: str) -> None:
    if isinstance(store, PostgresBaharStore):
        with store.transaction() as connection:
            store._require_role(connection, role)


def _put_once(store: Any, key: str, kind: str, body: dict[str, Any]) -> dict[str, Any]:
    existing = store.get_object(key)
    if existing is not None:
        if existing['type'] != kind or existing['digest'] != digest(body):
            raise GovernanceError(f'immutable governance record conflicts: {key}')
        return existing
    created = store.put_object(key, kind, body, actor_id=_principal(store),
                               operation_id=f'governance:{key}:register', expected_latest_version=0)
    return store.get_object(key) or created


class GovernedWorkflow:
    """Trusted orchestration. Service/CLI may call approval methods after authentication.

    SQLite registrations are ALWAYS demonstration-only; only PostgreSQL with
    membership-backed regulatory approval may activate legally binding rules.
    """

    def __init__(self, store: Any, assessment_service: Any):
        self.store = store
        self.service = assessment_service

    def register_rule(self, rule: dict[str, Any], *, source_key: str) -> dict[str, Any]:
        from .rules import validate_rule
        if not isinstance(rule, dict) or not isinstance(source_key, str) or not source_key.strip():
            raise GovernanceError('rule and authoritative source record are required')
        _require_role(self.store, 'regulatory_approver')
        errors = validate_rule(rule)
        if errors:
            raise GovernanceError('; '.join(errors))
        if isinstance(self.store, PostgresBaharStore) and str(rule.get('interpretation_approved_by')) != _principal(self.store):
            raise GovernanceError('approved interpretation must be authorized by the authenticated regulatory approver')
        source = self.store.get_object(source_key)
        if source is None or source['type'] != 'regulatory_source':
            raise GovernanceError('rule source must be an existing governed regulatory_source')
        if str(rule['source_id']) != str(source['body'].get('source_id')):
            raise GovernanceError('rule source identity conflicts with governed source')
        key = f"governed-rule:{rule['id']}:{rule['version']}"
        body = {'rule': deepcopy(rule), 'source_key': source_key,
                'source_digest': source['digest'], 'approved_by': _principal(self.store),
                'approval_basis': 'membership-backed regulatory_approver' if isinstance(self.store, PostgresBaharStore) else 'DEMO_NOT_LEGALLY_APPROVED',
                'activation_scope': 'production' if isinstance(self.store, PostgresBaharStore) else 'demonstration'}
        return _put_once(self.store, key, 'governed_rule', body)

    def register_source(self, source: dict[str, Any]) -> dict[str, Any]:
        _require_role(self.store, 'regulatory_approver')
        if not isinstance(source, dict) or not all(source.get(k) for k in ('source_id', 'jurisdiction', 'citation', 'source_digest')):
            raise GovernanceError('regulatory source needs source_id, jurisdiction, citation, source_digest')
        if not re.fullmatch(r'[0-9a-f]{64}', str(source['source_digest'])):
            raise GovernanceError('source_digest must be SHA-256 in lowercase hexadecimal')
        if isinstance(self.store, PostgresBaharStore):
            if not source.get('artifact_id') or not source.get('artifact_version'):
                raise GovernanceError('registered regulation must reference an existing governed artifact')
            with self.store.transaction() as connection:
                record = connection.execute(text("""
                    SELECT sha256, custody_state FROM artifact_versions
                    WHERE organization_id=:org AND artifact_id=:id AND version=:version
                """), {'org': str(self.store.context.organization_id), 'id': str(source['artifact_id']),
                        'version': int(source['artifact_version'])}).mappings().first()
            if not record or record['custody_state'] != 'governed_available' or str(record['sha256']) != str(source['source_digest']):
                raise GovernanceError('regulatory source artifact has not passed governed custody/integrity verification')
        return _put_once(self.store, f"regulatory-source:{source['source_id']}:{source['source_digest']}",
                         'regulatory_source', deepcopy(source))

    def register_precedence(self, policy: dict[str, Any]) -> dict[str, Any]:
        _require_role(self.store, 'regulatory_approver')
        if not isinstance(policy, dict) or not all(policy.get(k) for k in ('id','version','jurisdiction', 'selection')):
            raise GovernanceError('precedence policy requires id, version, jurisdiction and selection')
        if not isinstance(policy['selection'], dict) or not all(isinstance(k,str) and isinstance(v,str) for k,v in policy['selection'].items()):
            raise GovernanceError('invalid precedence mapping')
        return _put_once(self.store, f"governed-precedence:{policy['id']}:{policy['version']}",
                         'governed_precedence', {'policy': deepcopy(policy), 'approved_by': _principal(self.store),
                                                 'activation_scope': 'production' if isinstance(self.store, PostgresBaharStore) else 'demonstration'})

    def review_candidate(self, audit_id: str, candidate_id: str, *, accepted_concept: str,
                         source_snapshot_sha256: str) -> dict[str, Any]:
        _require_role(self.store, 'reviewer')
        observed = self.store.get_object(f'bahar-ai:{audit_id}')
        if observed is None or observed['type'] != 'bahar_ai_assessment':
            raise GovernanceError('stored lexical audit required before identity review')
        audit = observed['body']
        if audit.get('execution_status') != 'COMPLETED':
            raise GovernanceError('incomplete lexical audit cannot be reviewed')
        if audit.get('snapshot_sha256') != source_snapshot_sha256:
            raise GovernanceError('candidate review source snapshot mismatch')
        matches = [row for row in audit.get('candidates', []) if row.get('candidate_id') == candidate_id]
        if len(matches) != 1 or accepted_concept not in matches[0].get('accepted_concepts', []):
            raise GovernanceError('accepted concept must be an actual candidate of the stored source span')
        body = {'audit_id': audit_id, 'candidate_id': candidate_id,
                'accepted_concept': accepted_concept, 'source_snapshot_sha256': source_snapshot_sha256,
                'source_audit_digest': observed['digest'],
                'candidate_source_span': matches[0].get('span'), 'candidate_source_text': matches[0].get('text'),
                'reviewer_id': _principal(self.store),
                'review_level': 'qualified_candidate_identity' if isinstance(self.store, PostgresBaharStore) else 'DEMO_REVIEW_ONLY',
                'rule_authority': 'NONE'}
        return _put_once(self.store, f'candidate-review:{audit_id}:{candidate_id}', 'candidate_review', body)

    def reviewed_audit(self, audit_id: str) -> dict[str, Any]:
        observed = self.store.get_object(f'bahar-ai:{audit_id}')
        if observed is None or observed['type'] != 'bahar_ai_assessment':
            raise GovernanceError('stored lexical audit not found')
        audit = observed['body']
        reviewed, pending = [], []
        for candidate in audit.get('candidates', []):
            review = self.store.get_object(f"candidate-review:{audit_id}:{candidate['candidate_id']}")
            if review and review['type'] == 'candidate_review' and review['body'].get('source_audit_digest') == observed['digest']:
                reviewed.append(deepcopy(review['body']))
            else:
                pending.append(candidate['candidate_id'])
        return {'workflow': 'candidate_review', 'source_audit_id': audit_id, 'source_audit_digest': observed['digest'],
                'qualified_candidate_reviews': reviewed, 'unreviewed_candidate_ids': pending,
                'identity_review_complete': len(pending) == 0 and audit.get('execution_status') == 'COMPLETED',
                'regulatory_assessment_issued': False, 'release_authorized': False,
                'disclaimer': 'Candidate identity reviews are not material-lot truth, regulatory assessment or release.'}

    def assess_governed(self, requested: dict[str, Any]) -> dict[str, Any]:
        """Only server-resolved policy may enter binding rule selection.

        This intentionally refuses client-controlled rule lists and policy maps.
        Production requires membership-backed governance and registered contract;
        non-production SQLite use is expressly demonstration only.
        """
        if not isinstance(requested, dict):
            raise GovernanceError('assessment request must be an object')
        case = deepcopy(requested)
        context = case.setdefault('context', {})
        if not isinstance(context, dict):
            raise GovernanceError('invalid context')
        if case.get('rules') or context.get('approved_precedence_policy'):
            raise GovernanceError('client supplied regulatory rules or precedence are forbidden')
        if case.get('source_records') or case.get('evidence'):
            raise GovernanceError('caller-provided source records and evidence are forbidden in governed assessments; use a retained evidence bundle')
        contract = case.get('contract')
        if not isinstance(contract, dict):
            raise GovernanceError('assessment contract required')
        if not set(DEFAULT_REQUIRED_CHECKS).issubset(set(contract.get('required_checks', []))):
            raise GovernanceError('assessment contract cannot omit baseline mandatory checks')
        mode = contract.get('mode')
        audit_id = case.pop('candidate_audit_id', None)
        if mode == 'production' and not audit_id:
            raise GovernanceError('production requires reviewed input lineage; arbitrary accepted identities are forbidden')
        if audit_id:
            reviewed = self.reviewed_audit(str(audit_id))
            if not reviewed['identity_review_complete']:
                raise GovernanceError('every lexical candidate must have a qualified review or explicit unresolved disposition')
            original = self.store.get_object(f'bahar-ai:{audit_id}')['body']['source_snapshot']
            scope = contract.get('scope', {})
            if str(scope.get('product_id')) != original['product_id'] or str(scope.get('formulation_version')) != original['recipe_version']:
                raise GovernanceError('assessment scope does not match reviewed recipe snapshot')
            label = case.get('label', {})
            if str(label.get('version')) != original['label_version'] or str(label.get('ingredient_text')) != original['label_text']:
                raise GovernanceError('label differs from reviewed lexical source snapshot')
            formulation = case.get('formulation', {})
            if formulation.get('subrecipes') or case.get('formulations'):
                raise GovernanceError('nested formulations need separately qualified governed source lineage')
            items = formulation.get('ingredients', [])
            by_id = {review['candidate_id']: review for review in reviewed['qualified_candidate_reviews']}
            if len(items) != len(by_id) or {item.get('candidate_id') for item in items} != set(by_id):
                raise GovernanceError('reviewed candidate and formulation occurrences must match exactly')
            for item in items:
                review = by_id[item['candidate_id']]
                if item.get('name') != review['candidate_source_text']:
                    raise GovernanceError('ingredient source text differs from reviewed occurrence')
                preferred = KNOWLEDGE.raw_concepts[review['accepted_concept']]['preferred_name']
                identity = normalize_candidate(preferred)
                if item.get('accepted_identity') and item['accepted_identity'] != identity:
                    raise GovernanceError('untrusted identity override conflicts with governed reviewer selection')
                # A reviewer-selected generic name is NOT independently verified
                # supplier-lot identity. Retain it only as an AI candidate.
                item.pop('accepted_identity', None)
                item.pop('verified_origin', None)
                item['ai_candidate'] = identity
            case['candidate_review_lineage'] = {'audit_id': audit_id, 'audit_digest': reviewed['source_audit_digest'],
                                                'review_count': len(by_id), 'identity_is_material_truth': False}
            if mode == 'production':
                raise GovernanceError('editorial lexical candidate reviews do not qualify independent production material identity; attach verified material-lot identity through a separate governed source workflow')
        elif mode == 'production':
            raise GovernanceError('unreviewed production identity is forbidden')
        if mode == 'production' and not isinstance(self.store, PostgresBaharStore):
            raise GovernanceError('production assessments need membership-backed PostgreSQL governance')
        # F39-F48: production claims require exact market/package identity and
        # separately qualified operational evidence. A client declaring these
        # properties true is insufficient; the rule/evidence record must be
        # retrieved from independently governed custody.
        if mode == 'production':
            from .operational_scope import context_identity
            identity = context_identity(contract.get('scope', {}))
            if identity['state'] != 'identity_defined_not_verified':
                raise GovernanceError('production product-market-package-event scope is incomplete')
            if not case.get('operational_qualification_refs'):
                raise GovernanceError('production operational qualification records required; supplier/lab/physical claims cannot be assumed')
            if not isinstance(self.store, PostgresBaharStore):
                raise GovernanceError('production qualification requires tenant-authenticated governance')
            for qualification_ref in case.pop('operational_qualification_refs'):
                value = self.store.get_object(str(qualification_ref))
                if not value or value['type'] != 'operational_qualification' or value['body'].get('production_compliance_verdict') != 'NOT_ESTABLISHED':
                    raise GovernanceError('unregistered or invalid operational qualification record')
            case['production_operational_claim'] = 'NOT_ESTABLISHED'

        evidence_ref = case.pop('evidence_bundle_ref', None)
        if mode == 'production' and not evidence_ref:
            raise GovernanceError('production assessment requires replay-verified governed evidence bundle')
        replay = None
        if evidence_ref:
            from .evidence_governance import EvidenceCustody
            relevant_time = context.get('relevant_times', {}).get('assessment')
            replay = EvidenceCustody(self.store).replay(str(evidence_ref), required_scope=contract.get('scope'),
                                                        relevant_date=relevant_time)
            case['source_records'] = [
                {'id': item['record']['body']['source_id'],
                 'version': item['record']['body']['version'],
                 'digest': item['record']['digest'], 'source_ref': item['record']['id'],
                 'verified_content_sha256': item['record']['body']['content_sha256']}
                for item in replay['sources']]
            case['evidence'] = replay['assertions']
            case['evidence_custody'] = {'bundle_ref': str(evidence_ref),
                'bundle_digest': replay['bundle']['digest'],
                'coverage_ref': replay['coverage']['id'],
                'coverage_digest': replay['coverage']['digest'],
                'retrieval_complete_within_declared_universe': replay['retrieval_complete'],
                'global_exhaustiveness': False}
        registered_contract = self.store.get_object(str(contract.get('id', '')))
        if mode == 'production' and (not registered_contract or registered_contract['digest'] != digest(contract)
                                     or registered_contract['type'] != 'assessment_contract'):
            raise GovernanceError('production contract must be an immutable governed contract')
        rule_refs = case.pop('rule_refs', [])
        if not isinstance(rule_refs, list):
            raise GovernanceError('rule_refs must be an array')
        rules = []
        trusted_rule_refs = {}
        trusted_rule_source_refs = {}
        for ref in rule_refs:
            record = self.store.get_object(str(ref))
            if not record or record['type'] != 'governed_rule':
                raise GovernanceError(f'governed rule not found: {ref}')
            rule_record = record['body']
            if mode == 'production' and rule_record['activation_scope'] != 'production':
                raise GovernanceError('demo rule cannot authorize production assessment')
            source_record = self.store.get_object(rule_record['source_key'])
            if not source_record or source_record['digest'] != rule_record['source_digest']:
                raise GovernanceError('source authority no longer matches approved rule record')
            if rule_record['rule'].get('jurisdiction') != context.get('jurisdiction'):
                raise GovernanceError('jurisdiction mismatch')
            rules.append(rule_record['rule'])
            trusted_rule_refs[rule_record['rule']['id']] = record['id']
            trusted_rule_source_refs[rule_record['rule']['id']] = rule_record['source_key']
        policy_ref = case.pop('precedence_policy_ref', None)
        if policy_ref:
            record = self.store.get_object(str(policy_ref))
            if not record or record['type'] != 'governed_precedence':
                raise GovernanceError('unregistered precedence policy')
            policy = record['body']['policy']
            if mode == 'production' and record['body']['activation_scope'] != 'production':
                raise GovernanceError('demo precedence policy cannot authorize production')
            if policy['jurisdiction'] != context.get('jurisdiction'):
                raise GovernanceError('precedence policy jurisdiction mismatch')
            selected = policy['selection']
            available = {(r['obligation_id'], r['id']) for r in rules}
            if any((obligation, rid) not in available for obligation, rid in selected.items()):
                raise GovernanceError('precedence policy refers to rule outside approved assessment')
            # Select exact approved rule versions in a trusted service operation.
            # The core rule selector never reads caller context as authority.
            for obligation, preferred_id in selected.items():
                matching = [r for r in rules if r['obligation_id'] == obligation]
                if len(matching) < 1 or sum(r['id'] == preferred_id for r in matching) != 1:
                    raise GovernanceError('precedence policy is inapplicable to selected rules')
            rules = [r for r in rules if r['obligation_id'] not in selected or r['id'] == selected[r['obligation_id']]]
            trusted_rule_refs = {r['id']: trusted_rule_refs[r['id']] for r in rules}
            trusted_rule_source_refs = {r['id']: trusted_rule_source_refs[r['id']] for r in rules}
            case['trusted_precedence_policy_digest'] = record['digest']
        context.pop('approved_precedence_policy', None)
        case['rules'] = rules
        if mode == 'demonstration' and not isinstance(self.store, PostgresBaharStore):
            case.setdefault('limitations', []).append('Local governance is demonstrative, without independent identity assurance')
        result = self.service.assess(case, commit=False)
        if replay:
            from .evidence_governance import finding_provenance, EvidenceCustody
            graph = finding_provenance(result, replay, trusted_rule_refs, trusted_rule_source_refs)
            result['provenance_graph'] = graph
            bound_inputs = EvidenceCustody(self.store).validate_input_bindings(case, replay)
            complete = (replay['retrieval_complete'] and graph['fully_evidence_grounded']
                        and bound_inputs['complete'])
            result['evidence_assurance'] = {
                'replay_verified': True, 'retained_source_count': len(replay['sources']),
                'qualified_assertion_count': sum(all(item[key] for key in ('source_identity_verified',
                     'integrity_verified', 'relevant', 'applicable','substantively_qualified')) for item in replay['assertions']),
                'retrieval_complete_within_declared_universe': replay['retrieval_complete'],
                'finding_lineage_complete': graph['fully_evidence_grounded'],
                'source_input_bindings': bound_inputs,
                'global_source_universe_coverage_proven': False,
                'favorable_claim_supported': complete,
                'limits': 'Content integrity and attributable review do not establish independent factual truth or universally complete retrieval.'}
            if not complete and result['technical_readiness'] == 'ready_for_review':
                result['technical_readiness'] = 'needs_review'
                result['final_outcome'] = 'assessment_requires_action'
            result['checks']['provenance_and_coverage'] = {
                'state': 'pass' if complete else 'indeterminate',
                'message': 'Lineage and declared-universe retrieval verified.' if complete else 'Lineage or retrieval incomplete; favorable conclusions withheld.'}
        else:
            result['evidence_assurance'] = {
                'replay_verified': False, 'favorable_claim_supported': False,
                'limits': 'No governed source custody/evidence bundle; demonstration only.'}
            if result['technical_readiness'] == 'ready_for_review':
                result['technical_readiness'] = 'needs_review'
                result['final_outcome'] = 'assessment_requires_action'
        # Preserve the complete controlled engine input alongside retained
        # source bytes. A digest without the original input is insufficient
        # for independent replay (F19).
        input_ref = f'assessment-input:{result["assessment_id"]}'
        input_snapshot = _put_once(self.store, input_ref, 'assessment_input_snapshot',
                                   {'case': deepcopy(case), 'case_digest': digest(case),
                                    'captured_by': _principal(self.store)})
        result['manifest'] = self.service.engine._manifest(case, result)
        result['manifest']['source_custody_verified'] = bool(replay)
        result['manifest']['input_snapshot_ref'] = input_ref
        result['manifest']['input_snapshot_record_digest'] = input_snapshot['digest']
        result['manifest']['manifest_digest'] = digest({k:v for k,v in result['manifest'].items()
                                                        if k != 'manifest_digest'})
        return self.store.commit_assessment(result)

    def verify_assessment_replay(self, assessment_id: str) -> dict[str, Any]:
        """Verify persisted bytes and hashes without claiming external-model determinism.

        Old result history is preserved even when a source is later withdrawn;
        current source applicability must be checked separately.
        """
        record = self.store.get_assessment(str(assessment_id))
        if not record:
            raise GovernanceError('assessment not found')
        manifest = record['manifest']
        ref = manifest.get('input_snapshot_ref')
        if not ref:
            raise GovernanceError('assessment predates replayable input snapshot retention')
        snapshot = self.store.get_object(ref)
        if not snapshot or snapshot['type'] != 'assessment_input_snapshot':
            raise GovernanceError('assessment input snapshot missing')
        if snapshot['digest'] != manifest.get('input_snapshot_record_digest') or digest(snapshot['body']) != snapshot['digest']:
            raise GovernanceError('assessment input snapshot integrity mismatch')
        case = snapshot['body']['case']
        if digest(case) != snapshot['body']['case_digest'] or digest(case) != manifest['input_digest']:
            raise GovernanceError('assessment execution input digest mismatch')
        if digest({key:value for key,value in record.items() if key not in ('manifest','started_at','completed_at')}) != manifest['result_digest']:
            raise GovernanceError('saved assessment result was altered after execution')
        if digest({key:value for key,value in manifest.items() if key != 'manifest_digest'}) != manifest['manifest_digest']:
            raise GovernanceError('assessment manifest integrity mismatch')
        from .evidence_governance import EvidenceCustody
        custody = EvidenceCustody(self.store)
        for entry in manifest.get('source_versions', []):
            source_ref = entry.get('source_ref')
            if not source_ref:
                raise GovernanceError('assessment source reference was not retained')
            observed = custody.resolve_source(source_ref)['record']
            if (observed['digest'] != entry['digest'] or
                observed['body']['content_sha256'] != entry['verified_content_sha256'] or
                observed['body']['version'] != entry['version']):
                raise GovernanceError('assessment source no longer matches source manifest')
        return {'assessment_id': assessment_id, 'verified_input_snapshot': True,
                'verified_manifest_and_result_hashes': True,
                'verified_retained_source_count': len(manifest.get('source_versions', [])),
                'reproduced_external_ai_output': False,
                'claim_limits': 'Hash and snapshot integrity verified; source truth, legal authority, completeness outside the declared universe and deterministic external AI replay are not established.'}
