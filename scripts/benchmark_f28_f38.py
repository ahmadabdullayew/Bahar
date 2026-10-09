#!/usr/bin/env python3
"""Run on externally adjudicated JSONL; does NOT provide an evaluated corpus."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
from bahar_ai_core.benchmark import load_jsonl, evaluate_corpus


def main():
    parser=argparse.ArgumentParser(description='Adjudicated extraction benchmark; no certified accuracy claims')
    parser.add_argument('jsonl', help='User-supplied adjudicated cases')
    parser.add_argument('--baseline', help='Previous report on identical corpus for drift comparison')
    parser.add_argument('--out', help='Write report to this path')
    args=parser.parse_args()
    baseline=json.loads(Path(args.baseline).read_text()) if args.baseline else None
    result=evaluate_corpus(load_jsonl(args.jsonl),expected_snapshot=baseline)
    value=json.dumps(result,indent=2,ensure_ascii=False)
    if args.out:
        Path(args.out).write_text(value+'\n',encoding='utf-8')
    else:
        print(value)

if __name__=='__main__':main()
