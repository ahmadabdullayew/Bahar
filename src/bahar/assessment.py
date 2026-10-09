from __future__ import annotations

import hashlib
import json
import traceback
from copy import deepcopy
from datetime import datetime, timezone
from typing import Any, Callable

from .composition import CompositionError, resolve_formulation
from .evidence import support_for, verify_evidence
from .knowledge import AZERBAIJAN_14
from .models import (
    AssessmentMode,
    CheckState,
    ClaimType,
    ExecutionState,
    GateState,
    coverage,
)
from .rules import binding_rules, select_rules


ENGINE_VERSION = "1.0.0"
DEFAULT_REQUIRED_CHECKS = (
    "contract_validity",
    "evidence_integrity",
    "composition_resolution",
    "rule_applicability",
    "declaration_content",
)


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def finding(
    code: str,
    determination: str,
    consequence: str,
    message: str,
    **details: Any,
) -> dict[str, Any]:
    return {
        "code": code,
        "evidentiary_determination": determination,
        "potential_consequence": consequence,
        "review_state": "unreviewed",
        "message": message,
        **details,
    }


class AssessmentEngine:
    """Deterministic assessment core.

    AI text extraction is deliberately outside this trust boundary. Any proposed
    normalization enters as ``ai_candidate`` and does not become an accepted fact.
    """

    def __init__(self, clock: Callable[[], datetime] | None = None):
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    @staticmethod
    def _check(state: CheckState, message: str, **details: Any) -> dict[str, Any]:
        return {"state": state.value, "message": message, **details}

    def _validate_contract(self, contract: dict[str, Any]) -> list[str]:
        errors: list[str] = []
        for field in ("id", "version", "mode", "assessment_types", "scope", "permitted_claims"):
            if field not in contract or contract[field] in (None, "", []):
                errors.append(f"contract missing {field}")
        try:
            AssessmentMode(str(contract.get("mode")))
        except ValueError:
            errors.append("contract has invalid mode")
        permitted = set(contract.get("permitted_claims", []))
        for claim in permitted:
            try:
                ClaimType(claim)
            except ValueError:
                errors.append(f"contract contains unknown claim type: {claim}")
        requested = set(contract.get("assessment_types", []))
        for claim in requested:
            try:
                ClaimType(claim)
            except ValueError:
                errors.append(f"contract contains unknown assessment type: {claim}")
        excess = requested - permitted
        if excess:
            errors.append(
                "assessment types exceed permitted claims: " + ", ".join(sorted(excess))
            )
        return errors

    def _manifest(self, case: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
        sources = case.get("source_records", [])
        source_versions = [
            {"id": source.get("id"), "version": source.get("version"),
             "digest": source.get("digest"), "source_ref": source.get("source_ref"),
             "verified_content_sha256": source.get("verified_content_sha256")}
            for source in sources
        ]
        manifest = {
            "engine_version": ENGINE_VERSION,
            "assessment_contract": {
                "id": case["contract"].get("id"),
                "version": case["contract"].get("version"),
                "mode": case["contract"].get("mode"),
                "digest": digest(case["contract"]),
            },
            "source_versions": source_versions,
            # The pure engine has no persistence authority. This field is
            # intentionally FALSE even when caller fields look official.
            # Only the governed workflow may promote it after exact replay.
            "source_custody_verified": False,
            "rules": [
                {"id": rule.get("id"), "version": rule.get("version")}
                for rule in case.get("rules", [])
            ],
            "knowledge_base_version": case.get("knowledge_base_version", "builtin-az-en-1.0.0"),
            "ai_execution": deepcopy(case.get("ai_execution")),
            "input_digest": digest(case),
            "result_digest": digest(
                {
                    key: value
                    for key, value in result.items()
                    if key not in {"manifest", "started_at", "completed_at"}
                }
            ),
        }
        manifest["manifest_digest"] = digest(manifest)
        return manifest

    def assess(self, input_case: dict[str, Any]) -> dict[str, Any]:
        case = deepcopy(input_case)
        assessment_id = str(case.get("assessment_id", "assessment-unnamed"))
        started_at = self.clock().isoformat()
        result: dict[str, Any] = {
            "assessment_id": assessment_id,
            "execution_state": ExecutionState.RUNNING.value,
            "final_outcome": "not_issued",
            "technical_readiness": GateState.NOT_ISSUED.value,
            "started_at": started_at,
            "checks": {},
            "findings": [],
            "resolved_ingredients": [],
            "applicable_rules": [],
            "scope": deepcopy(case.get("contract", {}).get("scope", {})),
        }
        try:
            contract = case.get("contract")
            if not isinstance(contract, dict):
                raise ValueError("assessment contract is required")
            ai_execution = case.get("ai_execution") or {}
            if ai_execution.get("mode") == "external_model" and ai_execution.get("status") in {
                "failed",
                "cancelled",
                "unauthorized_tool_request",
            }:
                raise RuntimeError("external AI execution did not complete successfully")
            required = tuple(contract.get("required_checks") or DEFAULT_REQUIRED_CHECKS)
            contract_errors = self._validate_contract(contract)
            if contract_errors:
                result["checks"]["contract_validity"] = self._check(
                    CheckState.FAIL, "Assessment contract is invalid.", errors=contract_errors
                )
            else:
                result["checks"]["contract_validity"] = self._check(
                    CheckState.PASS, "Assessment contract is structurally valid."
                )

            evidence = list(case.get("evidence", []))
            evidence_errors = verify_evidence(evidence)
            result["checks"]["evidence_integrity"] = self._check(
                CheckState.FAIL if evidence_errors else CheckState.PASS,
                "Evidence records failed validation." if evidence_errors else "Evidence records passed structural validation.",
                errors=evidence_errors,
            )

            # Preserve same-scope contradictions; never select a winner by confidence.
            propositions = sorted({str(item.get("proposition")) for item in evidence if item.get("proposition")})
            for proposition in propositions:
                scopes = [dict(item.get("scope", {})) for item in evidence if item.get("proposition") == proposition]
                for scope in scopes or [{}]:
                    pair, matched = support_for(evidence, proposition, scope)
                    if pair.state.value == "conflicted_evidence":
                        conflict = finding(
                            "CONFLICTED_EVIDENCE",
                            "conflicted",
                            "review",
                            "Qualified evidence supports opposing propositions in the same scope.",
                            proposition=proposition,
                            scope=scope,
                            evidence_ids=sorted({str(item.get("id")) for item in matched}),
                        )
                        if conflict not in result["findings"]:
                            result["findings"].append(conflict)

            formulation = case.get("formulation") or {}
            try:
                ingredients, composition_issues = resolve_formulation(
                    formulation, dict(case.get("formulations", {}))
                )
                result["resolved_ingredients"] = [item.as_dict() for item in ingredients]
                if composition_issues:
                    result["checks"]["composition_resolution"] = self._check(
                        CheckState.INDETERMINATE,
                        "Composition was only partially resolved.",
                        issues=composition_issues,
                    )
                elif any(item.unresolved for item in ingredients):
                    unresolved = {
                        item.occurrence_id: list(item.unresolved)
                        for item in ingredients
                        if item.unresolved
                    }
                    result["checks"]["composition_resolution"] = self._check(
                        CheckState.INDETERMINATE,
                        "One or more ingredient facts remain unresolved.",
                        unresolved=unresolved,
                    )
                else:
                    result["checks"]["composition_resolution"] = self._check(
                        CheckState.PASS, "The configured formulation scope was resolved."
                    )
            except CompositionError as exc:
                ingredients = []
                result["checks"]["composition_resolution"] = self._check(
                    CheckState.FAIL, "Composition graph is invalid.", error=str(exc)
                )

            for item in ingredients:
                for unresolved in item.unresolved:
                    result["findings"].append(
                        finding(
                            "UNRESOLVED_INGREDIENT_FACT",
                            "indeterminate",
                            "potentially_material",
                            f"Ingredient {item.source_name!r} requires more evidence: {unresolved}.",
                            ingredient_occurrence_id=item.occurrence_id,
                            reason=unresolved,
                        )
                    )

            applicable, conflicts, rule_errors = select_rules(
                list(case.get("rules", [])), dict(case.get("context", {}))
            )
            result["applicable_rules"] = [
                {"id": item["id"], "version": item["version"], "source_id": item["source_id"]}
                for item in applicable
            ]
            if conflicts:
                result["checks"]["rule_applicability"] = self._check(
                    CheckState.INDETERMINATE,
                    "Applicable executable obligations conflict without approved reconciliation.",
                    conflicts=conflicts,
                )
                for conflict in conflicts:
                    result["findings"].append(
                        finding(
                            "NORMATIVE_CONFLICT",
                            "indeterminate",
                            "blocking",
                            "Conflicting applicable rules require qualified interpretation.",
                            **conflict,
                        )
                    )
            elif rule_errors:
                result["checks"]["rule_applicability"] = self._check(
                    CheckState.INDETERMINATE,
                    "At least one configured rule is not activatable.",
                    errors=rule_errors,
                )
            elif not binding_rules(applicable):
                result["checks"]["rule_applicability"] = self._check(
                    CheckState.INDETERMINATE,
                    "No approved binding rule applies to the selected legal context.",
                )
            else:
                result["checks"]["rule_applicability"] = self._check(
                    CheckState.PASS, "Approved binding rules were selected for the recorded legal context."
                )

            supported_allergens = sorted({a for item in ingredients for a in item.allergens})
            label = case.get("label") or {}
            declared_allergens = {str(item) for item in label.get("declared_allergens", [])}
            declaration_findings: list[dict[str, Any]] = []
            active_binding = binding_rules(applicable)
            rule_allergens = {
                allergen for rule in active_binding for allergen in rule.get("allergens", AZERBAIJAN_14)
            }
            approved_exceptions = {
                (item.get("rule_id"), item.get("allergen")): item
                for item in case.get("declaration_exceptions", [])
                if item.get("status") == "approved"
                and item.get("preconditions_satisfied") is True
                and item.get("evidence_ids")
            }
            result["evaluated_exceptions"] = []
            for allergen in supported_allergens:
                if allergen not in rule_allergens:
                    continue
                if allergen not in declared_allergens:
                    applicable_exception = next(
                        (
                            exception
                            for rule in active_binding
                            if (exception := approved_exceptions.get((rule["id"], allergen)))
                        ),
                        None,
                    )
                    if applicable_exception:
                        result["evaluated_exceptions"].append(
                            {
                                "rule_id": applicable_exception["rule_id"],
                                "allergen": allergen,
                                "exception_id": applicable_exception.get("id"),
                                "outcome": "applied",
                                "evidence_ids": applicable_exception["evidence_ids"],
                            }
                        )
                        continue
                    declaration_findings.append(
                        finding(
                            "REQUIRED_DECLARATION_NOT_ESTABLISHED",
                            "supported",
                            "blocking",
                            f"Required declaration evidence for {allergen} was not established.",
                            allergen=allergen,
                            rule_ids=[rule["id"] for rule in active_binding if allergen in rule.get("allergens", [])],
                        )
                    )
            for allergen in sorted(declared_allergens - set(supported_allergens)):
                declaration_findings.append(
                    finding(
                        "LABEL_STATEMENT_WITHOUT_QUALIFIED_FORMULATION_SUPPORT",
                        "candidate",
                        "review",
                        f"The label declares {allergen}, but qualified formulation support was not found in scope.",
                        allergen=allergen,
                    )
                )
            result["findings"].extend(declaration_findings)

            if conflicts or not active_binding:
                declaration_state = CheckState.INDETERMINATE
                declaration_message = "Declaration conclusion is indeterminate because legal applicability is unresolved."
            elif any(item["code"] == "REQUIRED_DECLARATION_NOT_ESTABLISHED" for item in declaration_findings):
                declaration_state = CheckState.FAIL
                declaration_message = "At least one applicable declaration obligation was not established."
            elif any(item.unresolved for item in ingredients):
                declaration_state = CheckState.INDETERMINATE
                declaration_message = "No favorable conclusion is issued while material ingredient facts remain unresolved."
            else:
                declaration_state = CheckState.PASS
                declaration_message = "No declaration discrepancy was detected within the completed declared scope."
            result["checks"]["declaration_content"] = self._check(
                declaration_state,
                declaration_message,
                supported_allergens=supported_allergens,
                declared_allergens=sorted(declared_allergens),
            )

            if "visual_presentation" in required:
                visual_required = any(rule.get("visual_emphasis_required") for rule in active_binding)
                artwork = case.get("artwork")
                if not visual_required:
                    visual_state = CheckState.PASS
                    visual_message = "No applicable visual-emphasis obligation is configured."
                elif not artwork or not artwork.get("visual_evidence_available"):
                    visual_state = CheckState.INDETERMINATE
                    visual_message = "Artwork evidence is insufficient to evaluate visual emphasis."
                else:
                    emphasized = set(artwork.get("emphasized_allergens", []))
                    missing = set(supported_allergens) - emphasized
                    visual_state = CheckState.FAIL if missing else CheckState.PASS
                    visual_message = (
                        "Required allergen emphasis is missing."
                        if missing
                        else "Required visual emphasis is present in the evaluated artwork."
                    )
                    if missing:
                        result["findings"].append(
                            finding(
                                "MISSING_VISUAL_ALLERGEN_EMPHASIS",
                                "supported",
                                "blocking",
                                visual_message,
                                allergens=sorted(missing),
                            )
                        )
                result["checks"]["visual_presentation"] = self._check(visual_state, visual_message)

            if "physical_packaging" in required:
                sample = case.get("physical_packaging_sample")
                artwork = case.get("artwork") or {}
                if not sample:
                    physical_state = CheckState.INDETERMINATE
                    physical_message = "No physical packaging sample was provided."
                elif sample.get("designated_artwork_id") != artwork.get("id"):
                    physical_state = CheckState.INDETERMINATE
                    physical_message = "The sample's designated artwork identity is unresolved."
                else:
                    expected_text = str((case.get("label") or {}).get("ingredient_text", "")).strip()
                    captured_text = str(sample.get("captured_ingredient_text", "")).strip()
                    differs = expected_text != captured_text
                    physical_state = CheckState.FAIL if differs else CheckState.PASS
                    physical_message = (
                        "The sampled physical label differs from the designated artwork text."
                        if differs
                        else "The sampled physical label text matches the designated artwork text."
                    )
                    if differs:
                        result["findings"].append(
                            finding(
                                "PHYSICAL_LABEL_DISCREPANCY",
                                "supported_for_sample",
                                "blocking",
                                physical_message,
                                sample_id=sample.get("id"),
                                generalization="sample_only",
                            )
                        )
                result["checks"]["physical_packaging"] = self._check(
                    physical_state, physical_message
                )

            if "laboratory_evidence" in required:
                laboratory_results = case.get("laboratory_results", [])
                if not laboratory_results:
                    laboratory_state = CheckState.INDETERMINATE
                    laboratory_message = "No laboratory result was available for the required check."
                else:
                    laboratory_state = CheckState.PASS
                    laboratory_message = "Laboratory records were interpreted within their sample and method scope."
                    for laboratory_result in laboratory_results:
                        if laboratory_result.get("outcome") == "not_detected":
                            result["findings"].append(
                                finding(
                                    "LAB_NONDETECT_NOT_ABSOLUTE_ABSENCE",
                                    "qualified",
                                    "review",
                                    "A nondetect applies to the identified sample and method; it is not proof of absolute absence.",
                                    sample_id=laboratory_result.get("sample_id"),
                                    method=laboratory_result.get("method"),
                                    limit_of_detection=laboratory_result.get("limit_of_detection"),
                                )
                            )
                        if not laboratory_result.get("method_applicable_to_matrix", False):
                            laboratory_state = CheckState.INDETERMINATE
                            laboratory_message = "At least one analytical method is not established as applicable to the matrix."
                result["checks"]["laboratory_evidence"] = self._check(
                    laboratory_state, laboratory_message
                )

            if "batch_traceability" in required:
                batch = case.get("batch")
                if not batch or not batch.get("actual_material_lots"):
                    result["checks"]["batch_traceability"] = self._check(
                        CheckState.INDETERMINATE,
                        "Mandatory actual-material records are absent."
                    )
                else:
                    planned = set(batch.get("planned_material_ids", []))
                    actual = {item.get("material_id") for item in batch["actual_material_lots"]}
                    deviations = sorted(str(item) for item in actual.symmetric_difference(planned))
                    result["checks"]["batch_traceability"] = self._check(
                        CheckState.FAIL if deviations else CheckState.PASS,
                        "Actual material use differs from the planned formulation." if deviations else "Recorded actual materials match the plan.",
                        deviations=deviations,
                    )

            # Required checks that were not configured or executed remain visible.
            for check_id in required:
                result["checks"].setdefault(
                    check_id,
                    self._check(CheckState.NOT_RUN, "Required check was not executed."),
                )

            result["execution_state"] = ExecutionState.COMPLETED.value
            result["coverage"] = coverage(required, result["checks"])
            states = {CheckState(item["state"]) for key, item in result["checks"].items() if key in required}
            contract_valid = result["checks"]["contract_validity"]["state"] == CheckState.PASS.value
            blocking = CheckState.FAIL in states or any(
                item.get("potential_consequence") == "blocking" and item.get("evidentiary_determination") != "candidate"
                for item in result["findings"]
            )
            unresolved = (
                CheckState.INDETERMINATE in states
                or CheckState.NOT_RUN in states
                or any(
                    item.get("evidentiary_determination") in {"conflicted", "indeterminate"}
                    or item.get("potential_consequence") == "review"
                    for item in result["findings"]
                )
            )
            prerequisites = contract_valid and result["coverage"] == 1.0 and states <= {
                CheckState.PASS,
                CheckState.FAIL,
                CheckState.INDETERMINATE,
            }
            if not contract_valid:
                gate = GateState.NOT_ISSUED
            elif blocking:
                gate = GateState.BLOCKED
            elif unresolved or not prerequisites:
                gate = GateState.NEEDS_REVIEW
            else:
                gate = GateState.READY_FOR_REVIEW
            result["technical_readiness"] = gate.value
            result["final_outcome"] = (
                "no_discrepancy_detected_within_declared_scope"
                if gate == GateState.READY_FOR_REVIEW
                else "assessment_requires_action"
            )
        except Exception as exc:  # fail closed at the application boundary
            result["execution_state"] = ExecutionState.FAILED.value
            result["final_outcome"] = "not_issued"
            result["technical_readiness"] = GateState.NOT_ISSUED.value
            result["failure"] = {
                "type": type(exc).__name__,
                "message": str(exc),
                "diagnostic": traceback.format_exc(limit=5),
            }

        result["completed_at"] = self.clock().isoformat()
        result["manifest"] = self._manifest(case, result)
        return result
