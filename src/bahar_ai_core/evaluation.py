"""Declared synthetic evaluation cases; not real-world reliability validation."""
from __future__ import annotations
from dataclasses import dataclass
from .engine import Input, run

@dataclass(frozen=True)
class Case:
    id: str
    recipe: str
    label: str
    expected_missing: tuple[str, ...]
    expected_indeterminate: bool = False

# Explicitly synthetic curated examples. No legal exceptions or quantified cross-contact claims.
CASES = (
    Case("simple_wheat_present", "wheat flour, water", "Ingredients: wheat flour, water", ()),
    Case("sesame_missing", "wheat flour, tahini", "Contains: wheat", ("sesame",)),
    Case("milk_missing", "milk powder, salt", "Contains: wheat", ("milk",)),
    Case("milk_present", "sodium caseinate, water", "Contains: milk", ()),
    Case("coconut_not_milk", "coconut milk, water", "Ingredients: coconut milk, water", ()),
    Case("oat_not_milk", "oat milk, water", "Ingredients: oat milk, water", ()),
    Case("e322_unknown", "E322, water", "Ingredients: E322", (), True),
    Case("unknown_mixture", "mystery compound, tahini", "Contains: sesame", (), True),
    Case("may_contain_not_disclosure", "tahini", "May contain sesame", ("sesame",)),
    Case("soy_mention", "soy flour, water", "Contains: soy", ()),
    Case("egg_missing", "egg white, sugar", "Ingredients: sugar", ("egg",), True),
    Case("milk_free_not_disclosure", "milk", "Milk-free", ("milk",), True),
    Case("rice_not_wheat", "rice flour, water", "Ingredients: rice flour, water", ()),
    Case("nested_compound_unresolved", "chocolate (sugar, milk powder)", "Contains: milk", (), True),
)


def evaluate(*, cases=CASES, mode="lexical") -> dict:
    counts = {"TP": 0, "FP": 0, "FN": 0, "TN": 0}
    results = []
    unknown_expected = 0
    unknown_detected = 0
    for case in cases:
        assessed = run(Input(case.id, "v1", case.recipe, "l1", case.label), mode=mode)
        if assessed["execution_status"] != "COMPLETED":
            results.append({"id": case.id, "execution_status": assessed["execution_status"]})
            continue
        found = {f["allergen"] for f in assessed["findings"] if f["code"] == "POTENTIAL_MISSING_DISCLOSURE"}
        truth = set(case.expected_missing)
        counts["TP"] += len(found & truth)
        counts["FP"] += len(found - truth)
        counts["FN"] += len(truth - found)
        if not found and not truth:
            counts["TN"] += 1  # case-level negatives, NOT pooled with class-level TP/FP/FN
        found_unknown = any(f["code"] == "INGREDIENT_ORIGIN_UNRESOLVED" for f in assessed["findings"])
        unknown_expected += int(case.expected_indeterminate)
        unknown_detected += int(found_unknown and case.expected_indeterminate)
        results.append({"id": case.id, "expected": sorted(truth), "observed": sorted(found),
                        "expected_indeterminate": case.expected_indeterminate,
                        "observed_indeterminate": found_unknown,
                        "meets_expectation": truth == found and case.expected_indeterminate == found_unknown})
    precision_d = counts["TP"]+counts["FP"]
    recall_d = counts["TP"]+counts["FN"]
    valid = [r for r in results if "meets_expectation" in r]
    return {"dataset_kind": "HAND_CURATED_SYNTHETIC_DEMO_ONLY", "cases": len(cases),
            "completed": len(valid), "full_case_passes": sum(r["meets_expectation"] for r in valid),
            "confusion_positive_categories": {k: counts[k] for k in ("TP", "FP", "FN")},
            "case_level_true_negatives": counts["TN"],
            "precision": None if not precision_d else counts["TP"]/precision_d,
            "recall": None if not recall_d else counts["TP"]/recall_d,
            "indeterminate_scenarios": unknown_expected,
            "indeterminate_correctly_detected": unknown_detected,
            "results": results,
            "limitations": ["Cases are synthetic and selected by developers", "No legal-compliance or physical safety ground truth", "Results do not estimate industrial generalization"]}
