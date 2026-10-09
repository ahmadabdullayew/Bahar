"""Adversarial regression coverage for F18-F27. Tests run without external services.

These checks assert bounded electronic-record integrity, NOT independent scientific
truth or complete production/identity assurance.
"""
from __future__ import annotations

from copy import deepcopy
import json
import pytest

from bahar.assessment import digest
from bahar.evidence import support_for
from bahar.evidence_governance import EvidenceCustody
from bahar.governed_workflow import GovernedWorkflow, GovernanceError
from bahar.resources import load_case
from bahar.service import BaharService
from bahar.store import BaharStore


SCOPE = {'material_id':'M1', 'supplier_id':'S1', 'material_lot_id':'L1',
         'specification_version':'v1'}
PRODUCT = {'product_id':'cookie-002', 'formulation_version':'1.0.0'}

def all_confirmed():
    return {key:'confirmed' for key in ('authenticity','integrity','relevance','applicability',
                                        'substantive_verification','approval')}

@pytest.fixture
def env():
    service = BaharService(':memory:')
    yield service, EvidenceCustody(service.store), GovernedWorkflow(service.store, service)
    service.close()


def make_source(e):
    return e.retain_source(source_id='source-1', version='v1',
                           text='Supplier states contains sesame.', scope={'purpose':'supplier'})


def make_assertion(e, polarity='positive', scope=None, kind='material_lot_claim'):
    s=make_source(e)
    return e.propose_assertion(assertion_id='claim-1', source_ref=s['id'], start=16, end=31,
                               quoted_text='contains sesame', proposition='contains_sesame',
                               polarity=polarity, scope=scope or SCOPE, reference_kind=kind)


def make_bundle(e, *, complete=True, reviewed=True):
    source=make_source(e)
    a=make_assertion(e)
    if reviewed:
        e.review_assertion('claim-1', decisions=all_confirmed(), reason='Reviewed exact supplier quote')
    refs=[source['id']]
    cov=e.register_coverage(coverage_id='coverage-1', universe_basis='Declared supplier document set',
                            expected_source_refs=refs + ([] if complete else ['evidence-source:missing:v1']),
                            retrieved_source_refs=refs,
                            unresolved_source_refs=[] if complete else ['evidence-source:missing:v1'])
    b=e.register_bundle(bundle_id='bundle-1',coverage_ref=cov['id'],
                        assertion_refs=[a['id']],context_scope=PRODUCT)
    return b


def test_f18_source_manifest_cannot_accept_forged_sha(env):
    _,e,_=env
    source=make_source(e)
    assert e.resolve_source(source['id'])['record']['body']['content_sha256']
    with pytest.raises(GovernanceError,match='immutable governance record conflicts'):
        e.retain_source(source_id='source-1',version='v1',text='Source revised secretly')


def test_f19_mutated_source_content_fails_replay(env):
    service,e,_=env
    b=make_bundle(e)
    assert e.replay(b['id'])['retrieval_complete']
    conn=service.store.connection
    ref='evidence-source:source-1:v1'
    row=conn.execute('SELECT body_json FROM objects WHERE object_id=?',(ref,)).fetchone()
    body=json.loads(row[0]);body['content_b64']='c3Bvb2ZlZA=='
    conn.execute('UPDATE objects SET body_json=? WHERE object_id=?', (json.dumps(body),ref))
    with pytest.raises(GovernanceError,match='corrupted evidence_source'):
        e.replay(b['id'])


def test_f20_assertion_must_match_exact_retained_region(env):
    _,e,_=env;s=make_source(e)
    with pytest.raises(GovernanceError,match='exact|match retained'):
        e.propose_assertion(assertion_id='fake',source_ref=s['id'],start=16,end=31,
                            quoted_text='contains peanuts',proposition='contains_peanuts',
                            polarity='positive',scope=SCOPE)
    valid=make_assertion(e)
    assert valid['body']['source_region']['text']=='contains sesame'


def test_f21_six_dimensions_cannot_be_collapsed_to_one_approval_flag(env):
    _,e,_=env;make_assertion(e)
    with pytest.raises(GovernanceError,match='six independent'):
        e.review_assertion('claim-1',decisions={'approval':'confirmed'},reason='insufficient')
    d=all_confirmed();d['substantive_verification']='unknown'
    with pytest.raises(GovernanceError,match='approval cannot promote'):
        e.review_assertion('claim-1',decisions=d,reason='unknown facts')
    d['approval']='unknown'
    review=e.review_assertion('claim-1',decisions=d,reason='material origin still unknown')
    assert review['body']['decisions']['substantive_verification']=='unknown'


def test_f22_generic_knowledge_does_not_verify_supplier_lot(env):
    _,e,_=env
    a=make_assertion(e,kind='generic_knowledge')
    e.review_assertion('claim-1',decisions=all_confirmed(),reason='editorial knowledge verified')
    s=make_source(e)
    cov=e.register_coverage(coverage_id='c',universe_basis='known local source',expected_source_refs=[s['id']],retrieved_source_refs=[s['id']])
    b=e.register_bundle(bundle_id='b',coverage_ref=cov['id'],assertion_refs=[a['id']],context_scope=PRODUCT)
    assert e.replay(b['id'],required_scope={**PRODUCT,**SCOPE})['assertions'][0]['applicable'] is False


def test_f23_unknown_interpretation_is_explicit(env):
    _,e,_=env
    a=make_assertion(e)
    assert a['body']['interpretation_state']=='candidate'
    assert e.resolve_assertion(a['id'])['review'] is None
    b=make_bundle(e, reviewed=False)
    assert e.replay(b['id'])['assertions'][0]['substantively_qualified'] is False


def test_f24_negative_must_bind_material_supplier_lot_specification(env):
    _,e,_=env;source=make_source(e)
    with pytest.raises(GovernanceError,match='exact material'):
        e.propose_assertion(assertion_id='n',source_ref=source['id'],start=16,end=31,
                            quoted_text='contains sesame',proposition='contains_sesame',
                            polarity='negative',scope={'material_lot_id':'L1'})
    make_assertion(e,polarity='negative')
    e.review_assertion('claim-1',decisions=all_confirmed(),reason='negative statement assessed as a scoped claim')
    cov=e.register_coverage(coverage_id='c',universe_basis='lot records',expected_source_refs=[source['id']],retrieved_source_refs=[source['id']])
    b=e.register_bundle(bundle_id='b',coverage_ref=cov['id'],assertion_refs=['evidence-assertion:claim-1'],context_scope=PRODUCT)
    assertion=e.replay(b['id'],required_scope={**PRODUCT,**SCOPE,'material_lot_id':'other-lot'})['assertions'][0]
    assert not assertion['applicable']
    pair,_=support_for([assertion],'contains_sesame',{**SCOPE,'material_lot_id':'other-lot'})
    assert pair.negative is False


def test_f25_missing_source_makes_retrieval_incomplete(env):
    _,e,_=env
    b=make_bundle(e,complete=False)
    data=e.replay(b['id'])
    assert data['retrieval_complete'] is False
    assert data['global_exhaustiveness'] is False


def test_f25_bundle_pins_review_state_no_silent_promotion(env):
    _,e,_=env
    b=make_bundle(e,reviewed=False)
    e.review_assertion('claim-1',decisions=all_confirmed(),reason='review happened after the bundle was frozen')
    with pytest.raises(GovernanceError,match='adjudication has changed'):
        e.replay(b['id'])


def test_f26_withdrawn_source_cannot_support_current_complete_coverage(env):
    _,e,_=env
    b=make_bundle(e)
    e.withdraw_source('evidence-source:source-1:v1',reason='Supplier retracted document')
    data=e.replay(b['id'])
    assert data['retrieval_complete'] is False
    assert data['withdrawn_sources']==['evidence-source:source-1:v1']


def test_f27_rejected_correction_does_not_modify_original(env):
    _,e,_=env;s=make_source(e)
    c=e.propose_correction(correction_id='c1',source_ref=s['id'],start=0,end=8,
                           observed_text='Supplier',replacement_text='Vendor',reason='Possible typo')
    e.decide_correction(c['id'],decision='rejected',reason='Original confirmed')
    history=e.correction_history(s['id'])
    assert history['event_count']==1
    assert history['corrections'][0]['decision']['body']['decision']=='rejected'
    assert history['original_text']=='Supplier states contains sesame.'
    with pytest.raises(GovernanceError,match='unaccepted corrections'):
        e.materialize_corrected_source(source_ref=s['id'],correction_refs=[c['id']],derivative_version='v2')


def test_f27_accepted_correction_creates_new_version_with_provenance(env):
    _,e,_=env;s=make_source(e)
    c=e.propose_correction(correction_id='c2',source_ref=s['id'],start=0,end=8,
                           observed_text='Supplier',replacement_text='Manufacturer',reason='Text correction')
    e.decide_correction(c['id'],decision='accepted',reason='Validated transcription')
    derived=e.materialize_corrected_source(source_ref=s['id'],correction_refs=[c['id']],derivative_version='v2')
    assert e.resolve_source(s['id'])['text']=='Supplier states contains sesame.'
    assert e.resolve_source(derived['corrected_source_ref'])['text']=='Manufacturer states contains sesame.'
    assert derived['accepted_correction_refs']==[c['id']]
    assert e.correction_history(s['id'])['event_count']==1


def test_governed_path_rejects_unregistered_sources_and_evidence(env):
    _,e,w=env
    case=load_case('demo_ready_case.json');case['rules']=[]
    case['source_records']=[{'id':'forged','digest':'f'*64,'version':'fake'}]
    with pytest.raises(GovernanceError,match='caller-provided source records'):
        w.assess_governed(case)
    case['source_records']=[]
    case['evidence']=[{'id':'bad'}]
    with pytest.raises(GovernanceError,match='caller-provided source records'):
        w.assess_governed(case)


def test_governed_assessment_verifies_snapshot_and_pinned_sources(env):
    service,e,w=env
    b=make_bundle(e)
    case=load_case('demo_ready_case.json');case['rules']=[]
    case['assessment_id']='replay-1';case['evidence_bundle_ref']=b['id']
    result=w.assess_governed(case)
    assert result['manifest']['source_versions'][0]['source_ref']=='evidence-source:source-1:v1'
    assert result['evidence_assurance']['replay_verified']
    assert result['manifest']['input_snapshot_ref']=='assessment-input:replay-1'
    checked=w.verify_assessment_replay('replay-1')
    assert checked['verified_input_snapshot']
    assert checked['verified_retained_source_count']==1
    assert checked['reproduced_external_ai_output'] is False
    saved=service.store.get_assessment('replay-1')
    assert saved['manifest']['manifest_digest']==result['manifest']['manifest_digest']


def test_failed_manifest_reference_verification_is_detected(env):
    service,e,w=env
    b=make_bundle(e)
    case=load_case('demo_ready_case.json');case['rules']=[]
    case['assessment_id']='replay-2';case['evidence_bundle_ref']=b['id']
    w.assess_governed(case)
    source='evidence-source:source-1:v1'
    sql="UPDATE objects SET body_digest = ? WHERE object_id = ?"
    service.store.connection.execute(sql,('0'*64,source))
    with pytest.raises(GovernanceError,match='corrupted evidence_source'):
        w.verify_assessment_replay('replay-2')


def test_graph_does_not_invent_evidence_for_unlinked_finding(env):
    _,e,w=env
    b=make_bundle(e)
    case=load_case('demo_ready_case.json');case['rules']=[]
    case['assessment_id']='provenance-case';case['evidence_bundle_ref']=b['id']
    result=w.assess_governed(case)
    assert result['provenance_graph']['traversable'] is True
    if result['findings']:
        assert result['provenance_graph']['unresolved_findings']
        assert not result['evidence_assurance']['favorable_claim_supported']


def test_source_expiration_prevents_current_complete_retrieval(env):
    _,e,_=env
    s=e.retain_source(source_id='dated',version='v1',text='Allergen declaration',
                      scope={'purpose':'test'},valid_from='2026-01-01',valid_until='2026-05-01')
    c=e.register_coverage(coverage_id='dated-c',universe_basis='Supplied 2026 source',
                          expected_source_refs=[s['id']],retrieved_source_refs=[s['id']])
    b=e.register_bundle(bundle_id='dated-b',coverage_ref=c['id'],assertion_refs=[],context_scope=PRODUCT)
    assert e.replay(b['id'],relevant_date='2026-04-01')['retrieval_complete']
    expired=e.replay(b['id'],relevant_date='2026-10-09')
    assert expired['retrieval_complete'] is False
    assert s['id'] in expired['withdrawn_sources']


def test_unknown_identity_cannot_be_promoted_by_positive_review_flags(env):
    _,e,_=env;s=make_source(e)
    e.propose_assertion(assertion_id='unknown',source_ref=s['id'],start=16,end=31,
                        quoted_text='contains sesame',proposition='identity:unknown',polarity='positive',
                        scope=SCOPE,interpretation='unknown')
    with pytest.raises(GovernanceError,match='unresolved or contested'):
        e.review_assertion('unknown',decisions=all_confirmed(),reason='Cannot claim to know an unknown')


def test_untrusted_direct_engine_does_not_mark_source_custody_verified():
    from bahar.assessment import AssessmentEngine
    case=load_case('demo_ready_case.json')
    case['source_records']=[{'id':'fictional','version':'7','digest':'ff'*32,
                             'source_ref':'fictional-ref','verified_content_sha256':'aa'*32}]
    result=AssessmentEngine().assess(case)
    assert result['manifest']['source_custody_verified'] is False


def test_exact_input_bindings_reject_forged_declaration(env):
    _,e,_=env
    recipe=e.retain_source(source_id='recipe',version='1',text='tahini',scope={'purpose':'recipe'})
    label_text='Ingredients: tahini; sesame'
    label=e.retain_source(source_id='label',version='1',text=label_text,scope={'purpose':'label'})
    a=e.propose_assertion(assertion_id='identity',source_ref=recipe['id'],start=0,end=6,
                          quoted_text='tahini',proposition='ingredient_identity:i1:tahini',
                          polarity='positive',scope=PRODUCT)
    e.review_assertion('identity',decisions=all_confirmed(),reason='Qualified demo name review')
    b=e.propose_assertion(assertion_id='labeldecl',source_ref=label['id'],start=label_text.index('sesame'),end=label_text.index('sesame')+6,
                          quoted_text='sesame',proposition='label_declares:sesame',
                          polarity='positive',scope=PRODUCT)
    e.review_assertion('labeldecl',decisions=all_confirmed(),reason='Qualified demo declaration review')
    coverage=e.register_coverage(coverage_id='scope-c',universe_basis='Exact two documents',
                                 expected_source_refs=[recipe['id'],label['id']],
                                 retrieved_source_refs=[recipe['id'],label['id']])
    bundle=e.register_bundle(bundle_id='scope-b',coverage_ref=coverage['id'],
                             assertion_refs=[a['id'],b['id']],context_scope=PRODUCT)
    replay=e.replay(bundle['id'],required_scope=PRODUCT)
    case={'formulation':{'ingredients':[{'id':'i1','name':'tahini','accepted_identity':'tahini'}]},
          'label':{'ingredient_text':label_text,'declared_allergens':['sesame']},
          'source_bindings':{'label':{'source_ref':label['id'],'start':0,'end':len(label_text)},
                             'ingredients':{'i1':{'source_ref':recipe['id'],'start':0,'end':6,
                                                  'identity_assertion_ref':a['id']}},
                             'declarations':{'sesame':{'source_ref':label['id'],'start':label_text.index('sesame'),'end':label_text.index('sesame')+6,
                                                        'quoted_text':'sesame','assertion_ref':b['id']}}}}
    assert e.validate_input_bindings(case,replay)['complete'] is True
    altered=deepcopy(case)
    altered['label']['declared_allergens']=['sesame','peanuts']
    failed=e.validate_input_bindings(altered,replay)
    assert failed['complete'] is False
    assert 'peanuts' in str(failed['issues'])
