"""F18-F27: source custody and scoped, adjudicated evidence.

A verified hash proves the retained bytes match the retained digest, NOT that the
source is authentic or factually correct. Reviewer decisions are attributable
judgments, not guarantees of scientific or legal truth. No browser identity is
considered sufficient authority for privileged production mutations.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
from copy import deepcopy
from datetime import date
from typing import Any

from .assessment import digest
from .evidence import scopes_compatible
from .governed_workflow import GovernanceError, _principal, _put_once, _require_role

MAX_INLINE_ARTIFACT = 1_048_576
DIMENSIONS = ('authenticity', 'integrity', 'relevance', 'applicability',
              'substantive_verification', 'approval')
DECISIONS = ('confirmed', 'refuted', 'unknown')


def _need(value: Any, message: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise GovernanceError(message)
    return value


def _record(store: Any, ref: str, kind: str) -> dict[str, Any]:
    found = store.get_object(_need(ref, 'record reference is required'))
    if not found or found.get('type') != kind or digest(found['body']) != found['digest']:
        raise GovernanceError(f'missing, mismatched or corrupted {kind}: {ref}')
    return found


class EvidenceCustody:
    def __init__(self, store: Any):
        self.store = store

    def retain_source(self, *, source_id: str, version: str, text: str,
                      media_type: str = 'text/plain', scope: dict | None = None,
                      valid_from: str | None = None, valid_until: str | None = None) -> dict:
        """Copy exact UTF-8 bytes into a versioned immutable store record.

        Bounded text custody complements, but does not substitute for, large
        binary ingestions and object-store custody validation.
        """
        _require_role(self.store, 'reviewer')
        _need(source_id, 'source_id required'); _need(version, 'version required')
        if not isinstance(text, str) or not isinstance(scope or {}, dict):
            raise GovernanceError('UTF-8 source text and an object scope required')
        raw = text.encode('utf-8')
        try:
            beginning = date.fromisoformat(valid_from) if valid_from else None
            ending = date.fromisoformat(valid_until) if valid_until else None
        except (TypeError, ValueError) as exc:
            raise GovernanceError('source validity dates must be ISO YYYY-MM-DD') from exc
        if beginning and ending and beginning >= ending:
            raise GovernanceError('source validity interval must be increasing')
        if len(raw) > MAX_INLINE_ARTIFACT:
            raise GovernanceError('inline source exceeds 1 MiB; use governed binary ingestion')
        sha = hashlib.sha256(raw).hexdigest()
        key = f'evidence-source:{source_id}:{version}'
        body = {'source_id': source_id, 'version': version,
                'media_type': media_type, 'scope': deepcopy(scope or {}),
                'valid_from': valid_from, 'valid_until': valid_until,
                'content_b64': base64.b64encode(raw).decode('ascii'),
                'content_sha256': sha, 'byte_length': len(raw),
                'custody_type': 'immutable_inline_copy', 'registered_by': _principal(self.store)}
        return _put_once(self.store, key, 'evidence_source', body)

    def resolve_source(self, ref: str) -> dict:
        record = _record(self.store, ref, 'evidence_source')
        body = record['body']
        try:
            raw = base64.b64decode(body['content_b64'], validate=True)
        except (binascii.Error, ValueError, KeyError) as exc:
            raise GovernanceError('retained source bytes are unavailable') from exc
        if len(raw) != body['byte_length'] or hashlib.sha256(raw).hexdigest() != body['content_sha256']:
            raise GovernanceError('source content digest mismatch')
        try:
            text = raw.decode('utf-8')
        except UnicodeError as exc:
            raise GovernanceError('retained source is not valid UTF-8') from exc
        return {'record': record, 'text': text, 'bytes': raw}

    def withdraw_source(self, source_ref: str, *, reason: str) -> dict:
        _require_role(self.store, 'reviewer')
        self.resolve_source(source_ref)
        _need(reason, 'withdrawal reason required')
        return _put_once(self.store, f'evidence-withdrawal:{source_ref}', 'evidence_withdrawal',
                         {'source_ref': source_ref, 'reason': reason,
                          'withdrawn_by': _principal(self.store)})

    def propose_assertion(self, *, assertion_id: str, source_ref: str,
                          start: int, end: int, quoted_text: str, proposition: str,
                          polarity: str, scope: dict, interpretation: str = 'candidate',
                          reference_kind: str = 'source_claim') -> dict:
        _require_role(self.store, 'reviewer')
        _need(assertion_id, 'assertion_id required')
        _need(proposition, 'proposition required')
        if not isinstance(scope, dict) or not scope:
            raise GovernanceError('claim requires explicit material or document scope')
        if polarity not in ('positive', 'negative', 'qualifying'):
            raise GovernanceError('invalid evidence polarity')
        if reference_kind not in ('source_claim', 'generic_knowledge', 'material_lot_claim'):
            raise GovernanceError('invalid reference kind')
        if polarity == 'negative' or reference_kind == 'material_lot_claim':
            required = ('material_id', 'supplier_id', 'material_lot_id', 'specification_version')
            if not all(isinstance(scope.get(key), str) and scope[key].strip() for key in required):
                raise GovernanceError('negative and lot-specific claims need exact material, supplier, lot and specification scope')
            if reference_kind == 'generic_knowledge':
                raise GovernanceError('generic knowledge cannot support universal material-lot absence')
        observed = self.resolve_source(source_ref)
        source_text = observed['text']
        if not isinstance(start, int) or not isinstance(end, int) or not 0 <= start < end <= len(source_text):
            raise GovernanceError('source character range invalid')
        if source_text[start:end] != quoted_text:
            raise GovernanceError('assertion quote does not match retained immutable source span')
        if interpretation not in ('candidate', 'unknown', 'contested'):
            raise GovernanceError('proposed interpretation must not assert accepted truth')
        body = {'assertion_id': assertion_id, 'source_ref': source_ref,
                'source_record_digest': observed['record']['digest'],
                'source_sha256': observed['record']['body']['content_sha256'],
                'source_region': {'start': start, 'end': end, 'text': quoted_text},
                'proposition': proposition, 'polarity': polarity, 'scope': deepcopy(scope),
                'reference_kind': reference_kind, 'interpretation_state': interpretation,
                'proposed_by': _principal(self.store)}
        return _put_once(self.store, f'evidence-assertion:{assertion_id}', 'evidence_assertion', body)

    def review_assertion(self, assertion_id: str, *, decisions: dict,
                         reason: str, basis_refs: list[str] | None = None) -> dict:
        _require_role(self.store, 'reviewer')
        base = _record(self.store, f'evidence-assertion:{assertion_id}', 'evidence_assertion')
        _need(reason, 'review reasoning required')
        if not isinstance(decisions, dict) or set(decisions) != set(DIMENSIONS):
            raise GovernanceError('all six independent qualification dimensions must be adjudicated')
        if any(value not in DECISIONS for value in decisions.values()):
            raise GovernanceError('dimension decisions must be confirmed/refuted/unknown')
        if base['body']['interpretation_state'] in ('unknown', 'contested') and (
            decisions['substantive_verification'] == 'confirmed' or decisions['approval'] == 'confirmed'
        ):
            raise GovernanceError('an unresolved or contested interpretation cannot be promoted into qualified truth')
        basis_refs = basis_refs or []
        if not isinstance(basis_refs, list):
            raise GovernanceError('basis_refs must be an array')
        for ref in basis_refs:
            self.resolve_source(ref)
        if decisions['approval'] == 'confirmed' and any(decisions[key] != 'confirmed' for key in DIMENSIONS if key != 'approval'):
            raise GovernanceError('approval cannot promote unresolved or refuted evidence')
        body = {'assertion_ref': base['id'], 'assertion_digest': base['digest'],
                'decisions': deepcopy(decisions), 'reason': reason,
                'basis_refs': sorted(set(basis_refs)), 'reviewed_by': _principal(self.store),
                'authority_scope': 'production_authenticated_role' if hasattr(self.store, 'context') else 'demonstration_only'}
        return _put_once(self.store, f'evidence-review:{assertion_id}', 'evidence_review', body)

    def resolve_assertion(self, assertion_ref: str) -> dict:
        assertion = _record(self.store, assertion_ref, 'evidence_assertion')
        body = assertion['body']
        source = self.resolve_source(body['source_ref'])
        if source['record']['digest'] != body['source_record_digest'] or source['record']['body']['content_sha256'] != body['source_sha256']:
            raise GovernanceError('assertion source custody changed')
        region = body['source_region']
        if source['text'][region['start']:region['end']] != region['text']:
            raise GovernanceError('assertion source span no longer verifies')
        rid = body['assertion_id']
        review = self.store.get_object(f'evidence-review:{rid}')
        if review:
            review = _record(self.store, review['id'], 'evidence_review')
            if review['body']['assertion_digest'] != assertion['digest']:
                raise GovernanceError('review does not bind to current assertion')
            for ref in review['body']['basis_refs']:
                self.resolve_source(ref)
        return {'assertion': assertion, 'review': review}

    def register_coverage(self, *, coverage_id: str, universe_basis: str,
                          expected_source_refs: list[str], retrieved_source_refs: list[str],
                          unresolved_source_refs: list[str] | None = None) -> dict:
        _require_role(self.store, 'reviewer')
        _need(coverage_id, 'coverage_id required'); _need(universe_basis, 'documented universe basis required')
        unresolved_source_refs = unresolved_source_refs or []
        arrays = (expected_source_refs, retrieved_source_refs, unresolved_source_refs)
        if any(not isinstance(x, list) or len(x) != len(set(x)) for x in arrays):
            raise GovernanceError('coverage sets must be unique arrays')
        expected, retrieved, unresolved = map(set, arrays)
        if not retrieved <= expected or not unresolved <= expected or retrieved & unresolved:
            raise GovernanceError('retrieval coverage references are inconsistent')
        for ref in retrieved:
            self.resolve_source(ref)
        complete = bool(expected) and retrieved == expected and not unresolved
        body = {'coverage_id': coverage_id, 'universe_basis': universe_basis,
                'expected_source_refs': sorted(expected), 'retrieved_source_refs': sorted(retrieved),
                'unresolved_source_refs': sorted(unresolved),
                'retrieval_state': 'complete_within_declared_universe' if complete else 'incomplete',
                'global_exhaustiveness_claimed': False, 'reviewed_by': _principal(self.store)}
        return _put_once(self.store, f'evidence-coverage:{coverage_id}', 'evidence_coverage', body)

    def register_bundle(self, *, bundle_id: str, coverage_ref: str,
                        assertion_refs: list[str], context_scope: dict) -> dict:
        _require_role(self.store, 'reviewer')
        _need(bundle_id, 'bundle_id required')
        if not isinstance(context_scope, dict) or not context_scope:
            raise GovernanceError('assessment evidence bundle requires explicit scope')
        coverage = _record(self.store, coverage_ref, 'evidence_coverage')
        if not isinstance(assertion_refs, list) or len(assertion_refs) != len(set(assertion_refs)):
            raise GovernanceError('assertion_refs must be a unique list')
        asserted = [self.resolve_assertion(ref) for ref in assertion_refs]
        inventory = set(coverage['body']['retrieved_source_refs'])
        if any(item['assertion']['body']['source_ref'] not in inventory for item in asserted):
            raise GovernanceError('assertion cites a source missing from retrieval inventory')
        body = {'bundle_id': bundle_id, 'coverage_ref': coverage_ref,
                'coverage_digest': coverage['digest'], 'assertion_refs': sorted(assertion_refs),
                'assertion_digests': {item['assertion']['id']: item['assertion']['digest'] for item in asserted},
                'review_digests': {item['assertion']['id']: item['review']['digest'] if item['review'] else None for item in asserted},
                'scope': deepcopy(context_scope), 'registered_by': _principal(self.store)}
        return _put_once(self.store, f'evidence-bundle:{bundle_id}', 'evidence_bundle', body)

    def replay(self, bundle_ref: str, *, required_scope: dict | None = None,
               relevant_date: str | None = None) -> dict:
        bundle = _record(self.store, bundle_ref, 'evidence_bundle')
        b = bundle['body']
        coverage = _record(self.store, b['coverage_ref'], 'evidence_coverage')
        if b['coverage_digest'] != coverage['digest']:
            raise GovernanceError('coverage version has changed')
        if required_scope and any(required_scope.get(key) != value for key, value in b['scope'].items()):
            raise GovernanceError('bundle and assessment scope are incompatible')
        sources = [self.resolve_source(ref) for ref in coverage['body']['retrieved_source_refs']]
        obsolete = []
        try:
            assessment_day = date.fromisoformat(relevant_date[:10]) if relevant_date else None
        except (TypeError, ValueError) as exc:
            raise GovernanceError('relevant date must be ISO format') from exc
        for item in sources:
            ref = item['record']['id']
            if self.store.get_object(f'evidence-withdrawal:{ref}'):
                _record(self.store, f'evidence-withdrawal:{ref}', 'evidence_withdrawal')
                obsolete.append(ref)
            meta = item['record']['body']
            if assessment_day and (
                (meta.get('valid_from') and assessment_day < date.fromisoformat(meta['valid_from'])) or
                (meta.get('valid_until') and assessment_day >= date.fromisoformat(meta['valid_until']))
            ):
                obsolete.append(ref)
        resolved = [self.resolve_assertion(ref) for ref in b['assertion_refs']]
        for item in resolved:
            ref = item['assertion']['id']
            if b['assertion_digests'].get(ref) != item['assertion']['digest'] or b['review_digests'].get(ref) != (item['review']['digest'] if item['review'] else None):
                raise GovernanceError('bundle assertion or adjudication has changed')
        assertions = []
        for item in resolved:
            a, r = item['assertion'], item['review']
            d = r['body']['decisions'] if r else {}
            scope = a['body']['scope']
            relevant = scopes_compatible(scope, required_scope or b['scope'])
            if a['body']['source_ref'] in obsolete:
                relevant = False
            if a['body']['reference_kind'] == 'generic_knowledge' and any(k in (required_scope or b['scope']) for k in
                     ('material_id', 'supplier_id', 'material_lot_id', 'specification_version')):
                relevant = False
            if a['body']['reference_kind'] == 'material_lot_claim':
                relevant = relevant and all((required_scope or b['scope']).get(key) == scope.get(key)
                                            for key in ('material_id','supplier_id','material_lot_id','specification_version'))
            if a['body']['polarity'] == 'negative':
                # A negative finding cannot establish universal absence or silently
                # apply to a different material lot/specification.
                relevant = relevant and all((required_scope or b['scope']).get(k) == scope.get(k) for k in
                                            ('material_id', 'supplier_id', 'material_lot_id', 'specification_version'))
            assertions.append({'id': a['id'], 'source_id': a['body']['source_ref'],
                               'proposition': a['body']['proposition'], 'polarity': a['body']['polarity'],
                               'scope': deepcopy(scope),
                               'source_identity_verified': d.get('authenticity') == 'confirmed',
                               'integrity_verified': d.get('integrity') == 'confirmed',
                               'relevant': d.get('relevance') == 'confirmed' and relevant,
                               'applicable': d.get('applicability') == 'confirmed' and relevant,
                               'substantively_qualified': d.get('substantive_verification') == 'confirmed' and d.get('approval') == 'confirmed',
                               'provenance': {'source_ref': a['body']['source_ref'], 'source_span': a['body']['source_region'],
                                              'assertion_ref': a['id'], 'review_ref': r['id'] if r else None,
                                              'decision_status': deepcopy(d)}})
        covered = coverage['body']['retrieval_state'] == 'complete_within_declared_universe' and not obsolete
        return {'bundle': bundle, 'coverage': coverage, 'sources': sources,
                'assertions': assertions, 'retrieval_complete': covered,
                'withdrawn_sources': obsolete,
                'claim_scope': b['scope'], 'global_exhaustiveness': False}

    def validate_input_bindings(self, case: dict, replay: dict) -> dict:
        """Require literal source regions AND independently reviewed meaning.

        A mere character match does not qualify an ingredient identity or prove
        that caller-supplied declared-allergen metadata reflects the label.
        """
        bindings = case.get('source_bindings')
        if not isinstance(bindings, dict):
            return {'complete': False, 'issues': ['source_bindings are absent']}
        sources = {s['record']['id']: s['text'] for s in replay['sources']}
        assertions = {a['id']: a for a in replay['assertions']}
        issues = []

        def exact_region(spec: Any, expected: str) -> bool:
            if not isinstance(spec, dict) or spec.get('source_ref') not in sources:
                return False
            start, end = spec.get('start'), spec.get('end')
            return isinstance(start, int) and isinstance(end, int) and 0 <= start < end <= len(sources[spec['source_ref']]) and sources[spec['source_ref']][start:end] == expected

        label = (case.get('label') or {})
        label_text = label.get('ingredient_text')
        if not isinstance(label_text, str) or not exact_region(bindings.get('label'), label_text):
            issues.append('label ingredient text not bound to a retained exact source span')

        ingredient_bindings = bindings.get('ingredients', {})
        for ingredient in (case.get('formulation') or {}).get('ingredients', []):
            ident = str(ingredient.get('id', ''))
            item = ingredient_bindings.get(ident) if isinstance(ingredient_bindings, dict) else None
            if not exact_region(item, str(ingredient.get('name', ''))):
                issues.append(f'ingredient {ident} source span is not validated')
                continue
            accepted = ingredient.get('accepted_identity')
            if accepted:
                assertion = assertions.get(str(item.get('identity_assertion_ref')))
                if not assertion or assertion['proposition'] != f'ingredient_identity:{ident}:{accepted}' or (
                    not assertion['provenance']['source_ref'] == item['source_ref'] or
                    assertion['provenance']['source_span']['start'] != item['start'] or
                    assertion['provenance']['source_span']['end'] != item['end'] or
                    not all(assertion[k] for k in ('source_identity_verified','integrity_verified',
                                                   'relevant','applicable','substantively_qualified'))
                ):
                    issues.append(f'ingredient {ident} accepted identity is not supported by a scoped reviewed assertion')

        declaration_bindings = bindings.get('declarations', {})
        for allergen in (label.get('declared_allergens') or []):
            item = declaration_bindings.get(allergen) if isinstance(declaration_bindings, dict) else None
            assertion = assertions.get(str(item.get('assertion_ref'))) if isinstance(item, dict) else None
            if (not assertion or assertion['proposition'] != f'label_declares:{allergen}' or
                not isinstance(item.get('quoted_text'), str) or not exact_region(item, item['quoted_text']) or
                assertion['provenance']['source_ref'] != item['source_ref'] or
                assertion['provenance']['source_span']['start'] != item['start'] or
                assertion['provenance']['source_span']['end'] != item['end'] or
                not all(assertion[k] for k in ('source_identity_verified','integrity_verified',
                                               'relevant','applicable','substantively_qualified'))):
                issues.append(f'label declaration {allergen} has no independently reviewed text binding')
        return {'complete': not issues, 'issues': issues}

    def propose_correction(self, *, correction_id: str, source_ref: str,
                           start: int, end: int, observed_text: str, replacement_text: str,
                           reason: str, supersedes_correction_ref: str | None = None) -> dict:
        _require_role(self.store, 'reviewer')
        _need(correction_id, 'correction_id required'); _need(reason, 'correction reason required')
        source = self.resolve_source(source_ref)
        if not isinstance(start, int) or not isinstance(end, int) or not 0 <= start < end <= len(source['text']):
            raise GovernanceError('invalid correction span')
        if source['text'][start:end] != observed_text or not isinstance(replacement_text, str):
            raise GovernanceError('correction must bind to exact original source text')
        if supersedes_correction_ref:
            prev = _record(self.store, supersedes_correction_ref, 'evidence_correction')
            if prev['body']['source_ref'] != source_ref:
                raise GovernanceError('superseded correction must target the same immutable source')
        body = {'correction_id': correction_id, 'source_ref': source_ref, 'source_digest': source['record']['digest'],
                'start': start, 'end': end, 'observed_text': observed_text,
                'replacement_text': replacement_text, 'reason': reason,
                'supersedes_correction_ref': supersedes_correction_ref,
                'proposed_by': _principal(self.store), 'state': 'proposed'}
        return _put_once(self.store, f'evidence-correction:{correction_id}', 'evidence_correction', body)

    def decide_correction(self, correction_ref: str, *, decision: str, reason: str) -> dict:
        _require_role(self.store, 'reviewer')
        if decision not in ('accepted', 'rejected'):
            raise GovernanceError('correction decision must be accepted/rejected')
        _need(reason, 'decision reasoning required')
        correction = _record(self.store, correction_ref, 'evidence_correction')
        self.resolve_source(correction['body']['source_ref'])
        if hasattr(self.store, 'context') and correction['body']['proposed_by'] == _principal(self.store):
            raise GovernanceError('production correction reviewer must be independent of the proposer')
        body = {'correction_ref': correction_ref, 'correction_digest': correction['digest'],
                'decision': decision, 'reason': reason, 'reviewer_id': _principal(self.store),
                'authority_scope': 'production_authenticated_role' if hasattr(self.store, 'context') else 'demonstration_only'}
        return _put_once(self.store, f'evidence-correction-decision:{correction_ref}', 'evidence_correction_decision', body)

    def correction_history(self, source_ref: str, correction_refs: list[str] | None = None) -> dict:
        source = self.resolve_source(source_ref)
        auto_discovered = correction_refs is None
        if correction_refs is None:
            # Query the authoritative ledger, not a caller-supplied list that
            # could conceal an inconvenient rejected or superseded revision.
            if hasattr(self.store, 'connection'):
                rows = self.store.connection.execute(
                    "SELECT object_id FROM objects WHERE object_type='evidence_correction' ORDER BY created_at,object_id"
                ).fetchall()
                correction_refs = [str(row['object_id']) for row in rows]
            else:
                from sqlalchemy import text
                with self.store.transaction() as connection:
                    rows = connection.execute(text("""
                        SELECT external_key FROM governed_entities
                        WHERE organization_id = :org AND entity_type = 'evidence_correction'
                        ORDER BY external_key
                    """), {'org': str(self.store.context.organization_id)}).mappings().all()
                correction_refs = [str(row['external_key']) for row in rows]
        events = []
        for ref in correction_refs:
            record = _record(self.store, ref, 'evidence_correction')
            if record['body']['source_ref'] != source_ref:
                if auto_discovered:
                    continue
                raise GovernanceError('explicit correction belongs to another source')
            if record['body']['source_digest'] != source['record']['digest']:
                raise GovernanceError('correction references a changed source identity')
            decision = self.store.get_object(f'evidence-correction-decision:{ref}')
            if decision:
                decision = _record(self.store, decision['id'], 'evidence_correction_decision')
                if decision['body']['correction_digest'] != record['digest']:
                    raise GovernanceError('correction decision has invalid linkage')
            events.append({'proposal': record, 'decision': decision})
        return {'source_ref': source_ref, 'source_sha256': source['record']['body']['content_sha256'],
                'original_text': source['text'], 'corrections': events,
                'event_count': len(events),
                'note': 'Corrections do not mutate original source bytes. Accepted interpretations require a separately controlled derivative.'}

    def materialize_corrected_source(self, *, source_ref: str, correction_refs: list[str],
                                     derivative_version: str) -> dict:
        """Create a new immutable text artifact; never rewrite the underlying original."""
        _require_role(self.store, 'reviewer')
        _need(derivative_version, 'derivative version required')
        history = self.correction_history(source_ref, correction_refs)
        if not correction_refs or len(set(correction_refs)) != len(correction_refs):
            raise GovernanceError('derivative requires unique accepted corrections')
        spans: list[tuple[int, int, str]] = []
        for item in history['corrections']:
            decision = item['decision']
            if not decision or decision['body']['decision'] != 'accepted':
                raise GovernanceError('derivative cannot apply unaccepted corrections')
            correction = item['proposal']['body']
            spans.append((correction['start'], correction['end'], correction['replacement_text']))
        spans.sort()
        if any(spans[i][1] > spans[i + 1][0] for i in range(len(spans) - 1)):
            raise GovernanceError('overlapping corrections require a separate adjudication')
        output = history['original_text']
        for start, end, replacement in reversed(spans):
            output = output[:start] + replacement + output[end:]
        origin = self.resolve_source(source_ref)['record']
        created = self.retain_source(source_id=origin['body']['source_id'], version=derivative_version,
                                     text=output, media_type=origin['body']['media_type'],
                                     scope=origin['body']['scope'],
                                     valid_from=origin['body'].get('valid_from'),
                                     valid_until=origin['body'].get('valid_until'))
        lineage = {'original_source_ref': source_ref, 'original_digest': origin['digest'],
                   'corrected_source_ref': created['id'], 'corrected_digest': created['digest'],
                   'accepted_correction_refs': sorted(correction_refs),
                   'reviewed_by': _principal(self.store)}
        _put_once(self.store, f'evidence-derivation:{created["id"]}', 'evidence_derivation', lineage)
        return lineage


def finding_provenance(result: dict, replay: dict, rule_refs: dict[str, str],
                       rule_source_refs: dict[str, str] | None = None) -> dict:
    """Construct only edges that can be linked to exact stored identifiers.

    Unlinked findings remain explicitly unresolved, never silently attributed
    to all available sources or approved regulatory rules.
    """
    nodes: dict[str, dict] = {}
    edges: list[dict] = []
    for source in replay['sources']:
        rec = source['record']
        nodes[rec['id']] = {'kind': 'retained_source', 'digest': rec['digest'],
                            'content_sha256': rec['body']['content_sha256']}
    for assertion in replay['assertions']:
        ident = assertion['id']
        nodes[ident] = {'kind': 'scoped_assertion', 'proposition': assertion['proposition'],
                        'qualification': {k: assertion[k] for k in (
                            'source_identity_verified', 'integrity_verified', 'relevant',
                            'applicable', 'substantively_qualified')}}
        edges.append({'from': assertion['provenance']['source_ref'], 'to': ident,
                      'type': 'literal_source_span', 'span': assertion['provenance']['source_span']})
        if assertion['provenance']['review_ref']:
            review_id = assertion['provenance']['review_ref']
            nodes[review_id] = {'kind': 'attributed_adjudication',
                                'decisions': assertion['provenance']['decision_status']}
            edges.append({'from': ident, 'to': review_id, 'type': 'reviewed_assertion'})
    for rule_id, ref in rule_refs.items():
        nodes[ref] = {'kind': 'governed_rule', 'rule_id': rule_id}
        source_ref = (rule_source_refs or {}).get(rule_id)
        if source_ref:
            nodes.setdefault(source_ref, {'kind':'registered_regulatory_source',
                                          'legal_accuracy_independently_proven': False})
            edges.append({'from': source_ref, 'to': ref,
                          'type': 'governed_interpretation_of_source'})
    uncovered = []
    for index, finding in enumerate(result.get('findings', [])):
        f_id = f'finding:{result["assessment_id"]}:{index}'
        finding['provenance_id'] = f_id
        nodes[f_id] = {'kind': 'assessment_finding', 'code': finding['code']}
        linked_evidence = []
        for eid in finding.get('evidence_ids', []):
            # Evidence records can be referenced by either the assertion object
            # ID or its stable public assertion_id.
            candidates = [a for a in replay['assertions'] if
                          (a['id'] == eid or a['id'].removeprefix('evidence-assertion:') == eid)
                          and all(a[key] for key in ('source_identity_verified',
                             'integrity_verified','relevant','applicable','substantively_qualified'))]
            for a in candidates:
                ref = a['provenance']['review_ref'] or a['id']
                edges.append({'from': ref, 'to': f_id, 'type': 'explicit_evidentiary_basis'})
                linked_evidence.append(a['id'])
        linked_rules = []
        for rid in finding.get('rule_ids', []):
            if rid in rule_refs:
                edges.append({'from': rule_refs[rid], 'to': f_id, 'type': 'applicable_rule_basis'})
                linked_rules.append(rid)
        if not linked_evidence:
            uncovered.append({'finding_id': f_id, 'reason': 'no directly referenced qualified evidence'})
        if finding.get('rule_ids') and len(linked_rules) != len(finding['rule_ids']):
            uncovered.append({'finding_id': f_id, 'reason': 'missing governed rule lineage'})
    return {'nodes': nodes, 'edges': edges, 'unresolved_findings': uncovered,
            'traversable': True, 'fully_evidence_grounded': not uncovered,
            'global_exhaustiveness_claimed': False}
