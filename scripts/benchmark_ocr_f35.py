#!/usr/bin/env python3
"""Score independently transcribed OCR text, not OCR engine confidence."""
from __future__ import annotations
import argparse
import json
from hashlib import sha256
from pathlib import Path
from bahar.extraction import benchmark_text


def main():
    parser=argparse.ArgumentParser(description='Page-scoped OCR CER/WER: requires independently transcribed ground truth')
    parser.add_argument('jsonl', help='JSONL with document_id, page, language, truth, observed, transcribed_by, verified_by')
    parser.add_argument('--max-cer',type=float,default=0.05)
    parser.add_argument('--max-wer',type=float,default=0.15)
    parser.add_argument('--out')
    args=parser.parse_args()
    source=Path(args.jsonl)
    if source.stat().st_size>25_000_000:
        parser.error('Corpus exceeds size limit')
    rows=[]
    identities=set()
    for line in source.read_text(encoding='utf-8').splitlines():
        if not line.strip():continue
        obj=json.loads(line)
        fields=('document_id','page','language','truth','observed','transcribed_by','verified_by')
        if any(k not in obj for k in fields) or not isinstance(obj['page'],int) or obj['page']<1:
            parser.error('Invalid page ground-truth record')
        if not all(isinstance(obj[x],str) for x in fields if x!='page'):
            parser.error('Invalid page ground-truth field types')
        if not obj['truth'].strip() or not obj['transcribed_by'].strip() or not obj['verified_by'].strip():
            parser.error('Ground truth and reviewer identities required')
        if obj['transcribed_by']==obj['verified_by']:
            parser.error('Independent verification must be separately attributed')
        ident=(obj['document_id'],obj['page'])
        if ident in identities:
            parser.error('Duplicate page')
        identities.add(ident)
        result=benchmark_text(obj['truth'],obj['observed'],max_cer=args.max_cer,max_wer=args.max_wer)
        rows.append({'document_id':obj['document_id'],'page':obj['page'],'language':obj['language'],
                     'character_error_rate':result.character_error_rate,
                     'word_error_rate':result.word_error_rate,'meets_configured_thresholds':result.passed})
    if not rows: parser.error('Empty corpus: accuracy cannot be estimated')
    result={'kind':'USER_SUPPLIED_INDEPENDENTLY_TRANSCRIBED_OCR_REFERENCE',
            'external_reviewer_identity_verified':False,'population_representativeness_established':False,
            'corpus_sha256':sha256(source.read_bytes()).hexdigest(),
            'observed_pages':len(rows),
            'mean_page_cer':sum(r['character_error_rate'] for r in rows)/len(rows),
            'mean_page_wer':sum(r['word_error_rate'] for r in rows)/len(rows),
            'page_threshold_pass_rate':sum(r['meets_configured_thresholds'] for r in rows)/len(rows),
            'by_language': {language:{'pages':len(group),
                                      'mean_page_cer':sum(r['character_error_rate'] for r in group)/len(group),
                                      'mean_page_wer':sum(r['word_error_rate'] for r in group)/len(group)}
                           for language in sorted({r['language'] for r in rows})
                           for group in [[r for r in rows if r['language']==language]]},
            'pages':rows}
    encoded=json.dumps(result,ensure_ascii=False,indent=2)
    if args.out: Path(args.out).write_text(encoded+'\n',encoding='utf-8')
    else: print(encoded)
if __name__=='__main__':main()
