"""Local CLI for scoped demonstrations only."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
from .engine import Input, run, compare
from .knowledge import KNOWLEDGE, DEFAULT_PROFILE, KnowledgeRepository
from .storage import SQLiteStore, StoreError
from .evaluation import evaluate

FIELDS = {"product_id", "recipe_version", "recipe_text", "label_version", "label_text", "evidence_assertions"}

def load(path: str) -> Input:
    if Path(path).stat().st_size > 500000:
        raise ValueError("Input file exceeds size limit")
    obj = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(obj, dict) or set(obj)-FIELDS:
        raise ValueError("Input must be an object with recognized fields only")
    for name in FIELDS-{"evidence_assertions"}:
        if not isinstance(obj.get(name), str):
            raise ValueError(f"Input field {name} must be a string")
    assertions = obj.get("evidence_assertions", [])
    if not isinstance(assertions, list):
        raise ValueError("evidence_assertions must be an array")
    return Input(**{**obj, "evidence_assertions": tuple(assertions)})


def main():
    parser = argparse.ArgumentParser(description="Bahar v0.4 dataset-backed local demo; NOT compliance, product safety, or release authorization")
    parser.add_argument("command", choices=("audit", "compare", "show", "list", "review", "evaluate", "knowledge-lookup", "knowledge-stats", "knowledge-verify"))
    parser.add_argument("input", nargs="?", help="Input file for audit/compare, assessment ID for show/review")
    parser.add_argument("after", nargs="?", help="Second JSON file for compare, or candidate ID for review")
    parser.add_argument("--mode", choices=("lexical", "llm"), default="lexical")
    parser.add_argument("--reference-profile", choices=tuple(KNOWLEDGE.profiles), default=DEFAULT_PROFILE,
        help="NONEXECUTABLE reference taxonomy, never an active legal rule")
    parser.add_argument("--db", help="Optional local SQLite demo store (unencrypted, single user)")
    parser.add_argument("--idempotency-key")
    parser.add_argument("--reviewer")
    parser.add_argument("--decision", choices=("ACCEPT_CANDIDATE", "REJECT_CANDIDATE", "REQUEST_EVIDENCE"))
    parser.add_argument("--concept-id")
    parser.add_argument("--rationale")
    args = parser.parse_args()
    if args.command in ("list", "show", "review") and not args.db:
        parser.error("--db required for stored results and reviews")
    try:
        if args.command == "knowledge-stats":
            repo = KnowledgeRepository(profile=args.reference_profile)
            result = {"dataset_id":repo.manifest["dataset_id"], "version":repo.manifest["version"],
                 "reference_profile":repo.profile, "profile_mode":repo.profiles[repo.profile]["mode"],
                 "counts":repo.manifest["counts"],"manifest_sha256":repo.manifest_sha256,
                 "production_approved":False}
        elif args.command == "knowledge-lookup":
            if not args.input:
                parser.error("knowledge-lookup requires ingredient text")
            result = KnowledgeRepository(profile=args.reference_profile).lookup(args.input)
        elif args.command == "knowledge-verify":
            repo = KnowledgeRepository(profile=args.reference_profile)
            result = {"manifest_sha256":repo.manifest_sha256, "integrity": "PASSED",
                  "counts":repo.manifest["counts"],"source":"bundled/editorial-seed", "domain_verified":False}
        elif args.command == "evaluate":
            result = evaluate(mode=args.mode)
        elif args.command == "compare":
            if not args.input or not args.after:
                parser.error("compare requires both input file paths")
            result = compare(load(args.input), load(args.after), mode=args.mode, reference_profile=args.reference_profile)
        elif args.command == "audit":
            if not args.input:
                parser.error("audit requires a JSON file")
            result = run(load(args.input), mode=args.mode, reference_profile=args.reference_profile)
            if args.db:
                with SQLiteStore(args.db) as store:
                    result = store.save(result, idempotency_key=args.idempotency_key)
        else:
            with SQLiteStore(args.db) as store:
                if args.command == "list":
                    result = [{"assessment_id": x["assessment_id"], "execution_status": x["execution_status"],
                               "technical_readiness": x["technical_readiness"], "created_at": x["created_at"]}
                              for x in store.list_assessments()]
                elif args.command == "show":
                    result = store.get(args.input)
                    result["separate_demo_reviews"] = store.reviews(args.input)
                else:
                    if not all((args.input, args.after, args.reviewer, args.decision, args.rationale)):
                        parser.error("review requires assessment ID, candidate ID, --reviewer, --decision and --rationale")
                    result = store.review(args.input, args.after, args.reviewer, args.decision,
                                          args.rationale, args.concept_id)
        print(json.dumps(result, indent=2, ensure_ascii=False))
    except (ValueError, OSError, json.JSONDecodeError, StoreError) as exc:
        parser.exit(2, f"Input or store error: {exc}\n")

if __name__ == "__main__":
    main()
