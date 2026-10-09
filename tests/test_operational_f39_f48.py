"""Adversarial F39-F48 tests: claim limits, temporal selection, roles, custody and lifecycle."""
import json
import pytest
from bahar.operational_scope import (
    OperationalScopeError, context_identity, legal_applicability, cross_contact_risk,
    external_connector_state, physical_package_scope, laboratory_custody,
    incident_transition, batch_conformity,
)
from bahar.operational_workflow import OperationalWorkflow, OperationalWorkflowError
from bahar.authorization import OPERATION_ACTION_ROLES, authorize_operational_action
from bahar.store import BaharStore,StoreError
from bahar.resources import load_case
from bahar.service import BaharService


def market():
    return dict(product_id='P-1',formulation_version='v2',market='AZ',jurisdiction='AZ',
        package_configuration_id='pouch250',artwork_version='A3',label_version='L3',
        language='az',site_id='SITE1',legally_relevant_event='market',event_date='2026-10-09',
        assessment_purpose='recipe_label',legal_profile_ref='governed-law:2026')


def profile():
    return {'approval_state':'qualified','source_artifact_ref':'regulated:123',
       'obligations':[{'id':'O1','source_provision':'article-17.2', 'event_type':'market',
                       'effective_from':'2027-01-01','applicability_approved':True,
                       'exceptions_unresolved':False}]}


def pal():
    return dict(risk_profile_state='approved',allergen='sesame',sample_evidence_ref='s1',
        method_qualification_ref='m1',approved_reference_dose_ref='r1',controls_verification_ref='c1',
        product_configuration_ref='p1',concentration_mg_kg='20',upper_uncertainty_mg_kg='10',
        reference_dose_mg='1',consumption_g='50',mitigation_evaluated=True,
        sampling_representative=True)


def lab():
    return dict(sample_id='s',material_lot_id='lot',sampled_at='2026-10-09T10:00Z',
       sampling_plan_ref='plan',lab_id='lab',method_id='method',method_version='1',
       matrix='food',method_validation_ref='valid',calibration_ref='cal',
       reported_at='2026-10-09T11:30Z',lod_mg_kg='1',loq_mg_kg='2',result_evidence_ref='report',
       method_valid_for_matrix=True,independent_lab_verification=True,
       custody_events=[{'event_id':'1','actor_ref':'sampler','timestamp':'2026-10-09T10:00:00Z',
              'action':'collected','evidence_ref':'s1'},
             {'event_id':'2','actor_ref':'lab','timestamp':'2026-10-09T11:00:00Z',
              'action':'received','evidence_ref':'s2'}])


def batch():
    return {'batch_id':'b','product_configuration_ref':'p','planned_formulation_ref':'f',
            'planned_lots':['L1'],'consumed_lots':['L1'],'consumption_record_refs':['r'],
            'packaging_lot_ref':'p1','rework_records':[], 'operator_verification_ref':'o',
            'line_clearance_ref':'l','independent_physical_check':True,
            'source_records_verified':True}


def test_f39_unqualified_legislative_claim_is_indeterminate():
    assert legal_applicability(profile(),{'market':'2027-02-02'})['legal_verdict']=='NOT_EVALUATED'


def test_f39_empty_authoritative_universe_cannot_pass():
    x=profile();x['obligations']=[]
    assert legal_applicability(x,{'market':'2027-02-02'},qualified=True)['state']=='indeterminate'


def test_f40_effective_date_boundary_and_distinct_events():
    assert legal_applicability(profile(),{'market':'2026-10-09'},qualified=True)['selected_obligations'][0]['applicable'] is False
    assert legal_applicability(profile(),{'market':'2027-01-01'},qualified=True)['selected_obligations'][0]['applicable'] is True
    assert legal_applicability(profile(),{'manufactured':'2027-02-01'},qualified=True)['state']=='indeterminate'


def test_f40_unresolved_exceptions_and_approval_stop_selection():
    p=profile();p['obligations'][0]['exceptions_unresolved']=True
    assert legal_applicability(p,{'market':'2027-02-01'},qualified=True)['state']=='indeterminate'
    p=profile();p['obligations'][0]['applicability_approved']=False
    assert legal_applicability(p,{'market':'2027-02-01'},qualified=True)['state']=='indeterminate'


def test_f40_invalid_date_order_rejected():
    p=profile();p['obligations'][0]['effective_to']='2026-02-01'
    with pytest.raises(OperationalScopeError):legal_applicability(p,{'market':'2027-02-01'},qualified=True)


def test_f41_quantitative_screen_requires_governance():
    assert cross_contact_risk(pal())['pal_decision']=='NOT_AUTHORIZED'
    assert cross_contact_risk(pal(),qualified=True)['pal_decision']=='HUMAN_RISK_REVIEW_REQUIRED'


def test_f41_threshold_calculation_no_pal_decision():
    out=cross_contact_risk(pal(),qualified=True)
    assert out['estimated_upper_exposure_mg']=='1.5'
    assert out['screen']=='above_reference'
    assert out['pal_decision'] != 'LABEL_REQUIRED'


def test_f41_missing_and_negative_exposure_refuses():
    p=pal();p.pop('sample_evidence_ref')
    assert cross_contact_risk(p,qualified=True)['state']=='indeterminate'
    p=pal();p['concentration_mg_kg']='-1'
    with pytest.raises(OperationalScopeError):cross_contact_risk(p,qualified=True)


def test_f42_transport_not_source_truth():
    p={'system_kind':'ERP','system_instance':'sap','external_object_id':'a','external_version':'1',
        'mapping_version':'2','source_digest':'a'*64,'received_at':'2026','ingestion_id':'i'}
    for k in ('transport_acknowledged','schema_validated','semantic_validated','source_committed'):
        p[k]=True
    assert external_connector_state(p)['external_truth']=='NOT_VERIFIED'
    assert external_connector_state(p)['state']=='transport_and_mapping_reported_only'


def test_f42_invalid_external_checksum():
    p={'system_kind':'ERP','system_instance':'s','external_object_id':'x','external_version':'2',
       'mapping_version':'1','source_digest':'attacker','received_at':'today','ingestion_id':'1'}
    with pytest.raises(OperationalScopeError):external_connector_state(p)


def test_f43_physical_match_not_batch_proof():
    p={k:'ref' for k in ('sample_id','batch_id','packaging_lot_id','artwork_version',
       'camera_qualification_ref','calibration_evidence_ref','capture_artifact_ref',
       'sampling_plan_ref','captured_at')}
    p.update({k:'match' for k in ('product_identity_state','package_identity_state',
                                 'artwork_match_state','legibility_state','emphasis_state')})
    p.update(camera_current=True,sample_verified=True)
    assert physical_package_scope(p)['state']=='indeterminate'
    out=physical_package_scope(p,qualified=True)
    assert out['conclusion_scope']=='sample_only'


def test_f43_visual_error_never_passes():
    p={k:'ref' for k in ('sample_id','batch_id','packaging_lot_id','artwork_version',
      'camera_qualification_ref','calibration_evidence_ref','capture_artifact_ref',
      'sampling_plan_ref','captured_at')}
    p.update({k:'match' for k in ('product_identity_state','package_identity_state',
                                 'artwork_match_state','legibility_state','emphasis_state')})
    p.update(camera_current=True,sample_verified=True,representative_batch_plan_approved=True)
    p['emphasis_state']='unreadable'
    assert physical_package_scope(p,qualified=True)['conclusion_scope']=='sample_only'


def test_f44_lab_chain_requires_independently_qualified_method():
    assert laboratory_custody(lab())['state']=='indeterminate'
    assert laboratory_custody(lab(),qualified=True)['state']=='qualified_record_available'


def test_f44_custody_order_and_LOD_LOQ():
    p=lab();p['custody_events'][1]['timestamp']='2026-10-09T09:00:00Z'
    assert laboratory_custody(p,qualified=True)['state']=='indeterminate'
    p=lab();p['lod_mg_kg']='3'
    with pytest.raises(OperationalScopeError):laboratory_custody(p,qualified=True)


def test_f45_incident_allowed_and_forbidden_transitions():
    p={'incident_id':'INC','state':'reported'}
    assert incident_transition(p,'triaged',evidence_refs=['ev'],affected_lots=[],rationale='review')['state']=='triaged'
    with pytest.raises(OperationalScopeError):
        incident_transition(p,'closed_verified',evidence_refs=['e'],affected_lots=['lot'],rationale='skip')


def test_f45_affected_lots_needed_and_notification_not_claimed():
    p={'incident_id':'INC','state':'action_pending'}
    with pytest.raises(OperationalScopeError):
        incident_transition(p,'recall_in_progress',evidence_refs=['ev'],affected_lots=[],rationale='recall')
    x=incident_transition(p,'recall_in_progress',evidence_refs=['ev'],affected_lots=['L1'],rationale='recall')
    assert x['external_notification_state']=='NOT_SENT_BY_BAHAR'


def test_f46_deny_undefined_action_and_role_matrix():
    assert len(OPERATION_ACTION_ROLES)>=20
    with pytest.raises(StoreError):authorize_operational_action(None,None,'approve_everything')


def test_f47_exact_configuration_digest_changes_with_market():
    a=context_identity(market());p=market();p['market']='TR'
    assert a['configuration_digest']!=context_identity(p)['configuration_digest']
    p.pop('artwork_version')
    assert context_identity(p)['state']=='indeterminate'


def test_f47_reference_not_proof_of_registered_rule():
    assert context_identity(market())['state']=='identity_defined_not_verified'


def test_f48_planned_actual_materials_are_independent():
    assert batch_conformity(batch())['state']=='indeterminate'
    p=batch();p['consumed_lots']=['L2']
    result=batch_conformity(p,qualified=True)
    assert result['state']=='deviation' and result['unplanned_lots']==['L2']


def test_f48_even_full_documentary_match_not_physical_certification():
    assert batch_conformity(batch(),qualified=True)['batch_claim']=='PHYSICAL_CONFORMITY_NOT_CERTIFIED'


def test_ledger_versioning_and_demo_authority(tmp_path):
    store=BaharStore(tmp_path/'operations.sqlite3')
    try:
        ledger=OperationalWorkflow(store)
        record=ledger.record('incident','INC',{'incident_id':'INC','state':'reported','description':'suspected label error'})
        assert record['authority']=='DEMO_ONLY'
        with pytest.raises(OperationalWorkflowError,match='stale'):
            ledger.record('incident','INC',{'incident_id':'INC','state':'reported','description':'duplicate'})
        updated=ledger.record('incident','INC',{'incident_id':'INC','state':'triaged',
                    'evidence_refs':['doc'],'affected_lots':[],'reason':'triage'},expected_version=1)
        assert updated['record']['version']==2
        assert ledger.read('incident','INC')['body']['payload']['state']=='triaged'
        with pytest.raises(OperationalWorkflowError,match='qualified'):
            ledger.qualify('legal_interpretation','case',basis_refs=['x'],decision_reason='approved')
    finally:store.close()


def test_authority_not_taken_from_business_payload(tmp_path):
    store=BaharStore(tmp_path/'x.sqlite3')
    try:
        with pytest.raises(OperationalWorkflowError,match='cannot be supplied'):
            OperationalWorkflow(store).record('legal_interpretation','l',{'actor_id':'CEO'})
    finally:store.close()


def test_local_release_approval_denied_even_with_role_string():
    service=BaharService(':memory:')
    try:
        with pytest.raises(StoreError,match='assessment not found'):
            service.approve_release('r','anything',actor_id='self',authority_role='release_authority',reason='self')
    finally:service.close()


def test_preview_never_qualifies_law_or_pal():
    from bahar.operational_scope import operational_assurance
    assert operational_assurance('pal_risk_assessment',pal(),qualified=False)['pal_decision']=='NOT_AUTHORIZED'
    assert operational_assurance('legal_interpretation',profile(),qualified=False)['legal_verdict']=='NOT_EVALUATED'
