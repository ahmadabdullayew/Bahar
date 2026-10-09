"""Evaluation harness for third-party adjudicated multilingual reference corpora.

A filled schema is not evidence of genuine independent review. Results always
retain provenance limitations and must never be labeled production-validated by
this program. No ground-truth data is bundled or fabricated.
"""
from __future__ import annotations
from collections import defaultdict
from hashlib import sha256
from pathlib import Path
from .engine import Input, run
from .knowledge import KNOWLEDGE
import json

LANGUAGES = frozenset({'az', 'en', 'ru', 'mixed', 'other'})
DOCUMENT_TYPES = frozenset({'supplier_specification', 'recipe', 'ingredient_label', 'other'})

class BenchmarkError(ValueError):
    pass


def _ratio(n: int, denominator: int) -> float | None:
    return None if denominator == 0 else n / denominator


def _summary(rows: list[dict]) -> dict:
    count = len(rows)
    tp = sum(x['tp'] for x in rows)
    fp = sum(x['fp'] for x in rows)
    fn = sum(x['fn'] for x in rows)
    unknown = sum(x['unknown'] for x in rows)
    failed = sum(x['failed'] for x in rows)
    return {'documents': count, 'tp': tp, 'fp': fp, 'fn': fn,
            'unknown_identity_occurrences': unknown, 'failed_extractions': failed,
            'precision': _ratio(tp, tp+fp), 'recall': _ratio(tp, tp+fn),
            'false_negative_rate': _ratio(fn, tp+fn),
            'document_failure_rate': _ratio(failed, count)}


def validate_case(case: dict) -> dict:
    required = {'document_id','source_text','sha256','language','document_type',
                'reviewed_by','adjudicated_by','ingredient_spans'}
    if not isinstance(case, dict) or not required.issubset(case):
        raise BenchmarkError('Benchmark case missing fields')
    if not all(isinstance(case[x], str) and case[x].strip() for x in required-{'ingredient_spans'}):
        raise BenchmarkError('Missing text, provenance, or reviewer identity')
    if case['reviewed_by'] == case['adjudicated_by']:
        raise BenchmarkError('Benchmark requires a separate declared adjudicator')
    if case['language'] not in LANGUAGES or case['document_type'] not in DOCUMENT_TYPES:
        raise BenchmarkError('Unrecognized language or source type')
    if not isinstance(case['source_text'], str) or not case['source_text'].strip() or len(case['source_text']) > 16000:
        raise BenchmarkError('Source cannot be empty or oversized')
    if sha256(case['source_text'].encode('utf-8')).hexdigest() != case['sha256']:
        raise BenchmarkError('Source SHA-256 mismatch')
    spans = case['ingredient_spans']
    if not isinstance(spans, list) or not spans:
        raise BenchmarkError('Independent ingredient labels are mandatory')
    positions = []
    for span in spans:
        if not isinstance(span, dict) or set(span) != {'start', 'end', 'text', 'allergen_categories', 'reference_concept_id', 'identity_state'}:
            raise BenchmarkError('Each gold occurrence needs exact offsets, concept adjudication, and annotated categories')
        start,end=span['start'],span['end']
        if type(start) is not int or type(end) is not int or not 0<=start<end<=len(case['source_text']):
            raise BenchmarkError('Invalid reference offsets')
        if case['source_text'][start:end] != span['text']:
            raise BenchmarkError('Ground truth must quote the actual source characters')
        concept = span['reference_concept_id']
        status = span['identity_state']
        if status not in {'IDENTIFIED', 'UNKNOWN', 'CONTESTED'}:
            raise BenchmarkError('Invalid gold identity state')
        if (status == 'IDENTIFIED' and concept not in KNOWLEDGE.concepts) or (
                status != 'IDENTIFIED' and concept is not None):
            raise BenchmarkError('Adjudicated concept identity must be known or explicitly unresolved')
        categories=span['allergen_categories']
        if (not isinstance(categories, list) or any(not isinstance(c,str) for c in categories)
                or len(categories)!=len(set(categories))
                or any(c not in KNOWLEDGE.raw_categories for c in categories)):
            raise BenchmarkError('Invalid reference-category labels')
        positions.append((start,end))
    if positions != sorted(positions) or any(a[1]>b[0] for a,b in zip(positions,positions[1:])):
        raise BenchmarkError('Gold offsets overlap or are out of order')
    return case


def evaluate_corpus(cases: list[dict], *, expected_snapshot: dict | None = None) -> dict:
    if not cases:
        raise BenchmarkError('No independently annotated cases supplied; accuracy is unavailable')
    ids=set()
    rows=[]
    category_rows=defaultdict(lambda:{'tp':0,'fn':0,'fp':0})
    for entry in cases:
        case=validate_case(entry)
        if case['document_id'] in ids:
            raise BenchmarkError('Duplicate document identity')
        ids.add(case['document_id'])
        result=run(Input(case['document_id'],'bench-v1',case['source_text'],'no-label',''),mode='lexical')
        failed=result['execution_status']!='COMPLETED'
        observed={} if failed else {(c['span'][0],c['span'][1]):c for c in result['candidates']}
        gold={(g['start'],g['end']):g for g in case['ingredient_spans']}
        # Span AND category matching: identical characters do not prove identity.
        matches=set()
        for location,g in gold.items():
            c=observed.get(location)
            if (c and g['identity_state']=='IDENTIFIED' and not c['unresolved']
                    and g['reference_concept_id'] in c['accepted_concepts']
                    and set(c['allergens'])==set(g['allergen_categories'])):
                matches.add(location)
        for location,g in gold.items():
            for allergen in g['allergen_categories']:
                if location in matches:
                    category_rows[allergen]['tp']+=1
                else:
                    category_rows[allergen]['fn']+=1
        for location,c in observed.items():
            g=gold.get(location)
            for allergen in c['allergens']:
                if location not in matches or not g or allergen not in g['allergen_categories']:
                    category_rows[allergen]['fp']+=1
        rows.append({'document_id':case['document_id'],'language':case['language'],
                     'document_type':case['document_type'],
                     'tp':len(matches), 'fp':len(set(observed)-matches),
                     'fn':len(set(gold)-matches),
                     'unknown':sum(c['unresolved'] for c in observed.values()),
                     'gold_unresolved_identity': sum(g['identity_state']!='IDENTIFIED' for g in gold.values()),
                     'failed':int(failed),
                     'expected_spans':len(gold),'candidate_spans':len(observed),
                     'unmatched_gold_spans': [list(v) for v in sorted(set(gold)-matches)],
                     'unmatched_candidate_spans': [list(v) for v in sorted(set(observed)-matches)],
                     'extraction_capability':result['extraction_capability']})
    def stratify(field):
        return {key:_summary([r for r in rows if r[field]==key]) for key in sorted({r[field] for r in rows})}
    current={'dataset_id': 'USER_SUPPLIED_REFERENCE_DATA',
             'assessment_scope':'SPAN_AND_REFERENCE_IDENTITY_AND_CATEGORY_MATCHING_NOT_LEGAL_COMPLIANCE',
             'reference_independence':'DECLARED_REVIEWERS_NOT_EXTERNALLY_AUTHENTICATED',
             'dataset_representativeness':'NOT_ESTABLISHED',
             'domain_validation':'NOT_ESTABLISHED',
             'benchmark_sha256':sha256(json.dumps(cases,ensure_ascii=False,sort_keys=True).encode()).hexdigest(),
             'overall':_summary(rows),'by_language':stratify('language'),
             'by_document_type':stratify('document_type'),
             'by_allergen': {cat:{**numbers,'recall':_ratio(numbers['tp'],numbers['tp']+numbers['fn']),
                             'false_negative_rate':_ratio(numbers['fn'],numbers['tp']+numbers['fn']),
                             'precision':_ratio(numbers['tp'],numbers['tp']+numbers['fp'])}
                             for cat,numbers in sorted(category_rows.items())},
             'cases':rows}
    if expected_snapshot is not None:
        if expected_snapshot.get('benchmark_sha256') != current['benchmark_sha256']:
            raise BenchmarkError('Drift baseline is from a different reference corpus')
        old={r['document_id']:r for r in expected_snapshot.get('cases', [])}
        current['drift']={'newly_unmatched_documents':[r['document_id'] for r in rows
                          if r['document_id'] in old and (r['fn']>old[r['document_id']]['fn']
                          or r['fp']>old[r['document_id']]['fp'])],
                          'comparison_scope':'STATIC_CORPUS_REGRESSION_ONLY'}
    return current


def load_jsonl(path: str | Path) -> list[dict]:
    path=Path(path)
    if path.stat().st_size>25_000_000:
        raise BenchmarkError('Evaluation corpus exceeds configured size')
    return [json.loads(line) for line in path.read_text(encoding='utf-8').splitlines() if line.strip()]
