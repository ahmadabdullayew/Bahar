"""Regression suite for F08-F17 architecture corrections."""
from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
from pathlib import Path
import json

import pytest

from bahar_ai_core.engine import Input
from bahar.bahar_adapter import BaharAIAdapter
from bahar.governed_workflow import GovernedWorkflow, GovernanceError
from bahar.resources import load_case
from bahar.rules import select_rules
from bahar.service import BaharService
from bahar.store import BaharStore


@pytest.fixture
def setup(tmp_path):
    service = BaharService(tmp_path / 'test.sqlite3')
    workflow = GovernedWorkflow(service.store, service)
    adapter = BaharAIAdapter(service.store)
    yield service, workflow, adapter
    service.close()


def audit_tahini(adapter):
    result = adapter.audit(product_id='product-demo-001', formulation_version='1',
                           formulation_text='tahini', label_version='1', label_text='tahini', persist=True)
    assert result['execution_status'] == 'COMPLETED'
    return result


def test_f08_audit_is_a_candidate_only_and_structured_requires_governance(setup):
    service, workflow, adapter = setup
    result = audit_tahini(adapter)
    assert result['assessment_contract']['mode'] == 'DEMONSTRATION_ONLY'
    assert result['legal_verdict'] == 'NOT_EVALUATED'
    with pytest.raises(GovernanceError, match='client supplied regulatory rules'):
        workflow.assess_governed({'contract': {'mode': 'demonstration'},
                                  'rules': [{'id': 'untrusted-law'}], 'context': {}})
    assert workflow.reviewed_audit(result['assessment_id'])['identity_review_complete'] is False


def test_f09_review_requires_stored_grounded_candidate_and_correct_source(setup):
    _, workflow, adapter = setup
    result = audit_tahini(adapter)
    candidate = result['candidates'][0]
    with pytest.raises(GovernanceError, match='source snapshot mismatch'):
        workflow.review_candidate(result['assessment_id'], candidate['candidate_id'],
                                  accepted_concept='ING-TAHINI', source_snapshot_sha256='not-real')
    with pytest.raises(GovernanceError, match='actual candidate'):
        workflow.review_candidate(result['assessment_id'], candidate['candidate_id'],
                                  accepted_concept='ING-NONEXISTENT', source_snapshot_sha256=result['snapshot_sha256'])
    review = workflow.review_candidate(result['assessment_id'], candidate['candidate_id'],
                                       accepted_concept='ING-TAHINI', source_snapshot_sha256=result['snapshot_sha256'])
    assert review['body']['review_level'] == 'DEMO_REVIEW_ONLY'
    assert workflow.reviewed_audit(result['assessment_id'])['identity_review_complete'] is True
    same = workflow.review_candidate(result['assessment_id'], candidate['candidate_id'],
                                      accepted_concept='ING-TAHINI', source_snapshot_sha256=result['snapshot_sha256'])
    assert same['digest'] == review['digest']  # immutable, repeat-safe


def test_f09_reviewed_identity_does_not_become_material_truth(setup):
    _, workflow, adapter = setup
    audit = audit_tahini(adapter)
    candidate = audit['candidates'][0]
    workflow.review_candidate(audit['assessment_id'], candidate['candidate_id'],
                              accepted_concept='ING-TAHINI', source_snapshot_sha256=audit['snapshot_sha256'])
    case = load_case('demo_ready_case.json')
    case['rules'] = []
    case['assessment_id'] = 'reviewed-candidate-structured-1'
    case['contract']['scope']['product_id'] = 'product-demo-001'
    case['contract']['scope']['formulation_version'] = '1'
    case['contract']['mode'] = 'demonstration'
    case['candidate_audit_id'] = audit['assessment_id']
    case['formulation']['ingredients'] = [{'id': 'c1', 'candidate_id': candidate['candidate_id'],
                                           'name': candidate['text'], 'role':'intentional_ingredient'}]
    case['label']['version'] = '1'
    case['label']['ingredient_text'] = 'tahini'
    result = workflow.assess_governed(case)
    assert result['resolved_ingredients'][0]['accepted_identity'] is None
    assert result['resolved_ingredients'][0]['ai_candidate'] == 'tahini'
    assert result['checks']['composition_resolution']['state'] == 'indeterminate'


def test_f10_recipe_comparison_persists_candidate_only_with_unknown_downstream(setup):
    service, workflow, adapter = setup
    outcome = adapter.compare(product_id='p',
                              before={'formulation_version':'v1','formulation_text':'sunflower oil',
                                      'label_version':'l1','label_text':'sunflower oil'},
                              after={'formulation_version':'v2','formulation_text':'sunflower oil, tahini',
                                     'label_version':'l1','label_text':'sunflower oil'})
    assert outcome['status'] == 'COMPLETED'
    assert 'sesame' in outcome['added_allergen_categories']
    assert outcome['definitive_unaffected_claim_permitted'] is False
    assert outcome['dependency_knowledge'] == 'unknown'
    record = service.store.get_object('bahar-comparison:'+outcome['comparison_id'])
    assert record['type'] == 'bahar_candidate_comparison'
    assert record['body']['comparison_id'] == outcome['comparison_id']


def test_f11_f12_f16_f17_atomic_release_suspension_and_audit(setup, monkeypatch):
    service, workflow, adapter = setup
    store = service.store
    with store.transaction() as connection:
        connection.execute("INSERT INTO assessments VALUES(?,?,?,?,?,?,?)",
                           ('assess-1','manifest-1','input-1','{}','completed','ready_for_review','2026-01-01'))
        for rid in ('release-1', 'release-2'):
            connection.execute('''INSERT INTO releases VALUES(?,?,?,?,?,?,?,?,?,?,?,?)''',
                               (rid,'assess-1','approved',1,'scope','config','evidence','actor',
                                'release_authority','approved','2026-01-01','2026-01-01'))
    # Empty or partial graph must not justify an unaffected claim.
    assert store.affected('supplier:1')['definitive_unaffected_claim_permitted'] is False
    original = store.append_audit
    def fail(*args, **kwargs):
        raise RuntimeError('simulated audit persistence failure')
    monkeypatch.setattr(store, 'append_audit', fail)
    with pytest.raises(RuntimeError, match='audit persistence'):
        store.invalidate_releases('supplier:1', reason='corrected allergen source')
    assert {r['state'] for r in store.list_releases()} == {'approved'}
    monkeypatch.setattr(store, 'append_audit', original)
    report = service.process_change('supplier:1', actor_id='actor', authority_role='release_authority',
                                    reason='corrected allergen source')
    assert report['impact_completeness'] == 'incomplete'
    assert report['suspended_release_ids'] == ['release-1','release-2']
    assert {r['state'] for r in store.list_releases()} == {'suspended'}
    events = store.connection.execute('SELECT action FROM audit_events').fetchall()
    assert sum(x['action'] == 'release_suspended_due_to_change' for x in events) == 2
    # Retry is idempotent at the state level.
    retry = store.invalidate_releases('supplier:1', reason='corrected allergen source')
    assert retry['suspended_release_ids'] == []


def test_f13_f14_unregistered_rules_and_status_claims_cannot_authorize(setup):
    _, workflow, adapter = setup
    case = load_case('demo_ready_case.json')
    case['rules'] = []
    case['rule_refs'] = ['governed-rule:made-up:1']
    with pytest.raises(GovernanceError, match='governed rule not found'):
        workflow.assess_governed(case)
    with pytest.raises(GovernanceError, match='source_digest must be SHA-256'):
        workflow.register_source({'source_id':'any','jurisdiction':'AZ',
                                  'citation':'example','source_digest':'client-says-approved'})


def test_f15_client_precedence_cannot_override_conflicts(setup):
    _, workflow, adapter = setup
    rule = load_case('demo_ready_case.json')['rules'][0]
    other = deepcopy(rule)
    other['id'] = 'conflicting-rule'
    other['visual_emphasis_required'] = not rule.get('visual_emphasis_required', False)
    context = {'jurisdiction':'AZ', 'relevant_times':{'market':'2027-03-01'},
               'approved_precedence_policy':{rule['obligation_id']:rule['id']}}
    applicable, conflicts, errors = select_rules([rule,other],context)
    assert conflicts, 'caller-supplied precedence must not erase the conflict'
    case = load_case('demo_ready_case.json');case['rules']=[]
    case['context']['approved_precedence_policy'] = {rule['obligation_id']:rule['id']}
    with pytest.raises(GovernanceError, match='client supplied'):
        workflow.assess_governed(case)


def test_production_cannot_promote_editorial_candidate_to_verified_material(setup):
    _, workflow, adapter = setup
    case = load_case('demo_ready_case.json');case['rules']=[]
    case['contract']['mode']='production'
    with pytest.raises(GovernanceError, match='reviewed input lineage'):
        workflow.assess_governed(case)


def test_f08_f10_f13_and_security_http_routes_are_consistent(tmp_path):
    """Actual request dispatch, not just service-level calls."""
    from http.client import HTTPConnection
    from threading import Thread
    from bahar.api import BaharServer
    service = BaharService(tmp_path / 'server.sqlite3')
    adapter = BaharAIAdapter(service.store)
    server = BaharServer(('127.0.0.1', 0), service, None, adapter)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()

    def send(route, body):
        client = HTTPConnection('127.0.0.1', server.server_port, timeout=5)
        client.request('POST', route, body=json.dumps(body), headers={'Content-Type':'application/json'})
        response = client.getresponse()
        status, data = response.status, json.loads(response.read())
        client.close()
        return status, data

    try:
        status, observation = send('/api/ai/audit', {
            'product_id':'p', 'formulation_version':'1', 'formulation_text':'tahini',
            'label_version':'1','label_text':'tahini'})
        assert status == 201
        assert observation['governance_stage'] == 'LEXICAL_CANDIDATES_ONLY'
        assert observation['authoritative_structured_assessment'] is False
        audit_id = observation['assessment_id']
        status, reviewed = send('/api/ai/reviewed', {'audit_id': audit_id})
        assert status == 200 and reviewed['identity_review_complete'] is False

        status, comparison = send('/api/ai/compare', {'product_id':'p',
            'before': {'formulation_version':'1', 'formulation_text':'sunflower oil',
                       'label_version':'1', 'label_text':'sunflower oil'},
            'after': {'formulation_version':'2', 'formulation_text':'sunflower oil, tahini',
                      'label_version':'1', 'label_text':'sunflower oil'}})
        assert status == 200
        assert comparison['governance_stage'] == 'LEXICAL_COMPARISON_ONLY'
        assert comparison['definitive_unaffected_claim_permitted'] is False

        sample = load_case('demo_ready_case.json')
        status, blocked = send('/api/assess', sample)
        assert status == 403 and blocked['error'] == 'governed_assessment_required'
        status, blocked = send('/api/releases', {'release_id':'r', 'assessment_id':'a',
            'actor_id':'spoof','authority_role':'release_authority','reason':'spoof'})
        assert status == 403 and blocked['error'] == 'authenticated_approval_required'
        status, blocked = send('/api/changes/impact', {'changed_object_id':'foo','reason':'spoof'})
        assert status == 403 and blocked['error'] == 'authenticated_mutation_required'
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
        service.close()
