"""F39-F48: deliberately conservative operational and regulatory assurance controls.

No value in a client-submitted document is treated as an approved legal opinion,
lab verification, physical observation, external system acknowledgement or
production release decision. These evaluators are claim-limited, and never
assert legal compliance or actual food safety.
"""
from __future__ import annotations

from datetime import date, datetime
from decimal import Decimal, InvalidOperation
from typing import Any
from .assessment import digest


class OperationalScopeError(ValueError):
    """Invalid or insufficiently scoped operational evidence."""


POLICY_ROLES = {
    'legal_interpretation': 'regulatory_approver',
    'legal_transition': 'regulatory_approver',
    'pal_risk_assessment': 'reviewer',
    'external_connector_receipt': 'analyst',
    'camera_qualification': 'reviewer',
    'physical_inspection': 'reviewer',
    'lab_sample_custody': 'reviewer',
    'lab_method_qualification': 'reviewer',
    'incident': 'incident_manager',
    'incident_transition': 'incident_manager',
    'external_notification_receipt': 'incident_manager',
    'market_package_configuration': 'reviewer',
    'batch_conformity': 'reviewer',
}
MATERIAL_KINDS = {'legal_interpretation','legal_transition','pal_risk_assessment',
                  'camera_qualification','physical_inspection','lab_sample_custody',
                  'lab_method_qualification','incident','incident_transition',
                  'market_package_configuration','batch_conformity'}
AUTHORITATIVE_KINDS = {'legal_interpretation','legal_transition','pal_risk_assessment',
                       'camera_qualification','physical_inspection','lab_method_qualification',
                       'incident_transition','external_notification_receipt','batch_conformity'}


def _str(body: dict, key: str) -> str:
    value = body.get(key)
    if not isinstance(value, str) or not value.strip():
        raise OperationalScopeError(f'{key} must be a non-empty string')
    return value.strip()


def _date(value: Any, name: str) -> date:
    if not isinstance(value, str):
        raise OperationalScopeError(f'{name} requires an ISO date')
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise OperationalScopeError(f'{name} must be YYYY-MM-DD') from exc


def _number(value: Any, name: str, *, allow_zero: bool = False) -> Decimal:
    if isinstance(value, bool) or value is None:
        raise OperationalScopeError(f'{name} must be a decimal number')
    try:
        number = Decimal(str(value))
    except (InvalidOperation, TypeError, ValueError) as exc:
        raise OperationalScopeError(f'{name} must be a decimal number') from exc
    if not number.is_finite() or number < 0 or (number == 0 and not allow_zero):
        raise OperationalScopeError(f'{name} must be finite and {"nonnegative" if allow_zero else "positive"}')
    return number


def _missing(body: dict, fields: tuple[str,...]) -> list[str]:
    return [name for name in fields if body.get(name) in (None,'',[],{})]


def context_identity(body: dict) -> dict:
    """F47 exact immutable assessment identity; values alone do not verify the records."""
    keys = ('product_id','formulation_version','market','jurisdiction','package_configuration_id',
            'artwork_version','label_version','language','site_id','legally_relevant_event',
            'event_date','assessment_purpose')
    missing = _missing(body, keys)
    if missing:
        return {'state':'indeterminate','missing':missing,'claim':'NOT_EVALUATED'}
    _date(body['event_date'],'event_date')
    if body['assessment_purpose'] not in {'recipe_label','artwork','batch','cross_contact','lab','release_review'}:
        raise OperationalScopeError('invalid assessment_purpose')
    if not isinstance(body.get('legal_profile_ref'),str) or not body['legal_profile_ref'].strip():
        return {'state':'indeterminate','missing':['legal_profile_ref'],'claim':'NOT_EVALUATED'}
    snapshot = {name:body[name] for name in keys}
    snapshot['legal_profile_ref'] = body['legal_profile_ref']
    return {'state':'identity_defined_not_verified','configuration_digest':digest(snapshot),
            'configuration':snapshot,'claim':'NOT_EVALUATED'}


def legal_applicability(profile: dict, event_dates: dict[str,str], *, qualified: bool = False) -> dict:
    """F39/F40: temporal evidence. No qualified source => no legal verdict.

    Each obligation specifies its own relevant event and effective interval;
    unknown legal sources and exceptions are never implicitly absent.
    """
    if not qualified or profile.get('approval_state') != 'qualified' or not profile.get('source_artifact_ref'):
        return {'state':'indeterminate','reasons':['unqualified_legal_interpretation'],
                'legal_verdict':'NOT_EVALUATED'}
    obligations = profile.get('obligations')
    if not isinstance(obligations,list) or not obligations:
        return {'state':'indeterminate','reasons':['authoritative_obligation_universe_not_established'],
                'legal_verdict':'NOT_EVALUATED'}
    result=[]
    unresolved=[]
    for item in obligations:
        needed = _missing(item, ('id','source_provision','event_type','effective_from','applicability_approved'))
        if needed or item.get('applicability_approved') is not True:
            unresolved.append({'id':item.get('id'),'reason':'unreviewed_obligation','missing':needed})
            continue
        event = item['event_type']
        if event not in event_dates:
            unresolved.append({'id':item['id'],'reason':'relevant_event_missing','event':event})
            continue
        event_date = _date(event_dates[event],event)
        starts=_date(item['effective_from'],'effective_from')
        ends=_date(item['effective_to'],'effective_to') if item.get('effective_to') else None
        if ends and ends < starts:
            raise OperationalScopeError('effective_to precedes effective_from')
        if item.get('exceptions_unresolved',True):
            unresolved.append({'id':item['id'],'reason':'exception_applicability_not_resolved'})
            continue
        result.append({'id':item['id'],'event':event,'event_date':event_date.isoformat(),
                       'applicable':event_date>=starts and (ends is None or event_date<=ends),
                       'source_provision':item['source_provision']})
    return {'state':'indeterminate' if unresolved else 'qualified_temporal_selection',
            'selected_obligations':result,'unresolved':unresolved,
            'legal_verdict':'NOT_EVALUATED',
            'note':'Temporal applicability is not proof of food-label compliance.'}


def cross_contact_risk(record: dict, *, qualified: bool = False) -> dict:
    """F41: quantitative evidence calculation, never automatic PAL authorization.

    Measured concentration mg/kg, upper uncertainty mg/kg, reference dose mg
    and exposure grams must all be grounded in *qualified* records. No default
    Codex threshold, substitute units, or self-attested qualification.
    """
    if not qualified or record.get('risk_profile_state') != 'approved':
        return {'state':'indeterminate','reasons':['unqualified_risk_profile'],
                'pal_decision':'NOT_AUTHORIZED'}
    required=('allergen','sample_evidence_ref','method_qualification_ref','approved_reference_dose_ref',
              'controls_verification_ref','product_configuration_ref','concentration_mg_kg',
              'upper_uncertainty_mg_kg','reference_dose_mg','consumption_g')
    missing=_missing(record,required)
    if missing:
        return {'state':'indeterminate','missing':missing,'pal_decision':'NOT_AUTHORIZED'}
    concentration=_number(record['concentration_mg_kg'],'concentration_mg_kg',allow_zero=True)
    uncertainty=_number(record['upper_uncertainty_mg_kg'],'upper_uncertainty_mg_kg',allow_zero=True)
    reference=_number(record['reference_dose_mg'],'reference_dose_mg')
    consumption=_number(record['consumption_g'],'consumption_g')
    if record.get('mitigation_evaluated') is not True or record.get('sampling_representative') is not True:
        return {'state':'indeterminate','reasons':['mitigation_or_sampling_not_qualified'],
                'pal_decision':'NOT_AUTHORIZED'}
    exposure=(concentration+uncertainty)*consumption/Decimal(1000)
    return {'state':'quantitative_screen_complete','estimated_upper_exposure_mg':str(exposure),
            'reference_dose_mg':str(reference),'screen':'above_reference' if exposure>reference else 'not_above_reference',
            'pal_decision':'HUMAN_RISK_REVIEW_REQUIRED',
            'note':'A numeric screen is not a labeling recommendation or universal assurance.'}


def external_connector_state(record: dict) -> dict:
    """F42: transport success never upgrades a source assertion to verified truth."""
    mandatory=('system_kind','system_instance','external_object_id','external_version','mapping_version',
               'source_digest','received_at','ingestion_id')
    missing=_missing(record,mandatory)
    if missing:
        return {'state':'indeterminate','missing':missing,'external_truth':'NOT_VERIFIED'}
    allowed={'supplier','ERP','MES','LIMS','packaging'}
    if record['system_kind'] not in allowed:
        raise OperationalScopeError('unsupported system_kind')
    if not (isinstance(record['source_digest'],str) and len(record['source_digest'])==64 and
            all(ch in '0123456789abcdef' for ch in record['source_digest'])):
        raise OperationalScopeError('source_digest must be SHA256 hex')
    states=('transport_acknowledged','schema_validated','semantic_validated','source_committed')
    return {'state':'verification_pending' if not all(record.get(k) is True for k in states) else 'transport_and_mapping_reported_only',
            'external_truth':'NOT_VERIFIED', 'lineage_digest':digest({k:record[k] for k in mandatory}),
            'missing_validation':[k for k in states if record.get(k) is not True]}


def physical_package_scope(record: dict, *, qualified: bool = False) -> dict:
    """F43: sample observation is never a lot-wide conclusion without a qualified plan."""
    required=('sample_id','batch_id','packaging_lot_id','artwork_version','camera_qualification_ref',
              'calibration_evidence_ref','capture_artifact_ref','sampling_plan_ref','captured_at',
              'product_identity_state','package_identity_state','artwork_match_state',
              'legibility_state','emphasis_state')
    missing=_missing(record,required)
    if missing:
        return {'state':'indeterminate','missing':missing,'conclusion_scope':'NONE'}
    if not qualified or record.get('camera_current') is not True or record.get('sample_verified') is not True:
        return {'state':'indeterminate','reasons':['physical_device_or_sample_not_qualified'],
                'conclusion_scope':'NONE'}
    failed=[k for k in ('product_identity_state','package_identity_state','artwork_match_state',
                        'legibility_state','emphasis_state') if record[k]!='match']
    return {'state':'sample_discrepancy' if failed else 'sample_checked',
            'failed_dimensions':failed,
            'conclusion_scope':'batch' if record.get('representative_batch_plan_approved') is True and not failed else 'sample_only',
            'claim':'PHYSICAL_OBSERVATION_ONLY'}


def laboratory_custody(record: dict, *, qualified: bool = False) -> dict:
    """F44: complete event chain and matrix/method evidence are required."""
    required=('sample_id','material_lot_id','sampled_at','sampling_plan_ref','lab_id',
              'method_id','method_version','matrix','method_validation_ref','calibration_ref',
              'reported_at','lod_mg_kg','loq_mg_kg','custody_events','result_evidence_ref')
    missing=_missing(record,required)
    if missing:
        return {'state':'indeterminate','missing':missing,'analytical_claim':'NOT_QUALIFIED'}
    events=record['custody_events']
    if not isinstance(events,list) or len(events)<2:
        return {'state':'indeterminate','reasons':['incomplete_custody_chain'],
                'analytical_claim':'NOT_QUALIFIED'}
    previous=None
    for index,event in enumerate(events):
        if _missing(event,('event_id','actor_ref','timestamp','action','evidence_ref')):
            return {'state':'indeterminate','reasons':[f'incomplete_custody_event_{index}'],
                    'analytical_claim':'NOT_QUALIFIED'}
        timestamp=datetime.fromisoformat(event['timestamp'].replace('Z','+00:00'))
        if timestamp.tzinfo is None:
            raise OperationalScopeError('custody timestamps must be timezone aware')
        if previous and timestamp<previous:
            return {'state':'indeterminate','reasons':['nonchronological_custody'],
                    'analytical_claim':'NOT_QUALIFIED'}
        previous=timestamp
    lod=_number(record['lod_mg_kg'],'lod_mg_kg',allow_zero=True)
    loq=_number(record['loq_mg_kg'],'loq_mg_kg',allow_zero=True)
    if lod>loq:
        raise OperationalScopeError('LOD cannot exceed LOQ')
    if not qualified or record.get('method_valid_for_matrix') is not True or record.get('independent_lab_verification') is not True:
        return {'state':'indeterminate','reasons':['method_or_lab_not_qualified'],
                'analytical_claim':'NOT_QUALIFIED'}
    return {'state':'qualified_record_available','analytical_claim':'RECORD_QUALIFIED_ONLY',
            'note':'A below-LOD report does not prove universal allergen absence.'}


INCIDENT_TRANSITIONS={
    'reported':{'triaged'}, 'triaged':{'contained','closed_no_action'},
    'contained':{'assessing_affected_lots'},'assessing_affected_lots':{'action_pending','closed_no_action'},
    'action_pending':{'withdrawal_in_progress','recall_in_progress','closed_no_action'},
    'withdrawal_in_progress':{'verification_pending'},'recall_in_progress':{'verification_pending'},
    'verification_pending':{'closed_verified'}, 'closed_no_action':set(), 'closed_verified':set(),
}


def incident_transition(previous: dict, next_state: str, *, evidence_refs: list[str],
                        affected_lots: list[str], rationale: str) -> dict:
    """F45: evidence-bound workflow; never asserts that a notification was sent."""
    current=previous.get('state')
    if current not in INCIDENT_TRANSITIONS or next_state not in INCIDENT_TRANSITIONS[current]:
        raise OperationalScopeError(f'forbidden incident transition: {current} -> {next_state}')
    if not rationale.strip() or not evidence_refs:
        raise OperationalScopeError('incident transition needs rationale and evidence')
    if next_state in {'action_pending','withdrawal_in_progress','recall_in_progress','verification_pending','closed_verified'} and not affected_lots:
        raise OperationalScopeError('affected lot list required, or record an explicit unresolved scope')
    return {'incident_id':_str(previous,'incident_id'),'previous_state':current,'state':next_state,
            'evidence_refs':list(evidence_refs),'affected_lots':list(affected_lots),
            'reason':rationale,'external_notification_state':'NOT_SENT_BY_BAHAR'}


def batch_conformity(record: dict, *, qualified: bool = False) -> dict:
    """F48: planned recipe alone never establishes physically consumed materials."""
    required=('batch_id','product_configuration_ref','planned_formulation_ref','planned_lots',
              'consumed_lots','consumption_record_refs','packaging_lot_ref',
              'operator_verification_ref','line_clearance_ref')
    missing=_missing(record,required)
    if missing:
        return {'state':'indeterminate','missing':missing,'batch_claim':'NOT_VERIFIED'}
    if not isinstance(record['planned_lots'],list) or not isinstance(record['consumed_lots'],list) or not isinstance(record.get('rework_records'),list):
        raise OperationalScopeError('lot lists and rework_records must be arrays')
    if not qualified or record.get('independent_physical_check') is not True or record.get('source_records_verified') is not True:
        return {'state':'indeterminate','reasons':['actual_material_or_physical_verification_missing'],
                'batch_claim':'NOT_VERIFIED'}
    planned={str(x) for x in record['planned_lots']}
    actual={str(x) for x in record['consumed_lots']}
    if planned != actual:
        return {'state':'deviation','unplanned_lots':sorted(actual-planned),
                'unused_planned_lots':sorted(planned-actual),'batch_claim':'REQUIRES_REVIEW'}
    return {'state':'documentary_reconciliation_only','batch_claim':'PHYSICAL_CONFORMITY_NOT_CERTIFIED'}


def operational_assurance(kind: str, body: dict, *, qualified: bool=False) -> dict:
    """Pure evidence assessment, safe for untrusted preview; qualified cannot be set via HTTP."""
    if kind=='legal_interpretation':
        return legal_applicability(body,body.get('event_dates',{}),qualified=qualified)
    if kind=='pal_risk_assessment':
        return cross_contact_risk(body,qualified=qualified)
    if kind=='external_connector_receipt':
        return external_connector_state(body)
    if kind=='physical_inspection':
        return physical_package_scope(body,qualified=qualified)
    if kind=='lab_sample_custody':
        return laboratory_custody(body,qualified=qualified)
    if kind=='market_package_configuration':
        return context_identity(body)
    if kind=='batch_conformity':
        return batch_conformity(body,qualified=qualified)
    return {'state':'review_required','claim':'NOT_EVALUATED'}
