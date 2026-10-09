from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


AZERBAIJAN_14 = (
    "cereals_containing_gluten",
    "crustaceans",
    "eggs",
    "fish",
    "peanuts",
    "soybeans",
    "milk",
    "tree_nuts",
    "celery",
    "mustard",
    "sesame",
    "sulphur_dioxide_and_sulphites",
    "lupin",
    "molluscs",
)


ALIASES: dict[str, str] = {
    "wheat": "wheat",
    "buğda": "wheat",
    "bugda": "wheat",
    "flour": "wheat_flour",
    "wheat flour": "wheat_flour",
    "buğda unu": "wheat_flour",
    "barley": "barley",
    "arpa": "barley",
    "rye": "rye",
    "çovdar": "rye",
    "covdar": "rye",
    "oats": "oats",
    "yulaf": "oats",
    "milk": "milk",
    "süd": "milk",
    "sud": "milk",
    "casein": "casein",
    "sodium caseinate": "sodium_caseinate",
    "sodium-caseinate": "sodium_caseinate",
    "egg": "egg",
    "eggs": "egg",
    "yumurta": "egg",
    "peanut": "peanut",
    "peanuts": "peanut",
    "yer fındığı": "peanut",
    "soy": "soy",
    "soya": "soy",
    "soybean": "soy",
    "sesame": "sesame",
    "küncüt": "sesame",
    "kuncut": "sesame",
    "tahini": "tahini",
    "tahin": "tahini",
    "mustard": "mustard",
    "xardal": "mustard",
    "celery": "celery",
    "kərəviz": "celery",
    "kereviz": "celery",
    "fish": "fish",
    "balıq": "fish",
    "baliq": "fish",
    "crustacean": "crustacean",
    "crustaceans": "crustacean",
    "xərçəngkimilər": "crustacean",
    "mollusc": "mollusc",
    "molluscs": "mollusc",
    "molyusk": "mollusc",
    "lupin": "lupin",
    "acı paxla": "lupin",
    "sulphite": "sulphites",
    "sulfite": "sulphites",
    "sulphur dioxide": "sulphites",
    "sulfur dioxide": "sulphites",
    "almond": "almond",
    "badam": "almond",
    "hazelnut": "hazelnut",
    "fındıq": "hazelnut",
    "walnut": "walnut",
    "qoz": "walnut",
    "lecithin": "lecithin",
    "e322": "lecithin",
    "e-322": "lecithin",
}


ALLERGEN_RELATIONSHIPS: dict[str, tuple[str, ...]] = {
    "wheat": ("cereals_containing_gluten",),
    "wheat_flour": ("cereals_containing_gluten",),
    "barley": ("cereals_containing_gluten",),
    "rye": ("cereals_containing_gluten",),
    "oats": ("cereals_containing_gluten",),
    "milk": ("milk",),
    "casein": ("milk",),
    "sodium_caseinate": ("milk",),
    "egg": ("eggs",),
    "peanut": ("peanuts",),
    "soy": ("soybeans",),
    "sesame": ("sesame",),
    "tahini": ("sesame",),
    "mustard": ("mustard",),
    "celery": ("celery",),
    "fish": ("fish",),
    "crustacean": ("crustaceans",),
    "mollusc": ("molluscs",),
    "lupin": ("lupin",),
    "sulphites": ("sulphur_dioxide_and_sulphites",),
    "almond": ("tree_nuts",),
    "hazelnut": ("tree_nuts",),
    "walnut": ("tree_nuts",),
}


ORIGIN_ALLERGENS = {
    "soy": "soybeans",
    "soybean": "soybeans",
    "soya": "soybeans",
    "sunflower": None,
    "günəbaxan": None,
}


def canonical_text(value: str) -> str:
    value = value.casefold().strip()
    value = re.sub(r"[\s_]+", " ", value)
    return value


def normalize_candidate(name: str) -> str | None:
    return ALIASES.get(canonical_text(name))


@dataclass(frozen=True)
class IngredientResolution:
    occurrence_id: str
    source_name: str
    ai_candidate: str | None
    accepted_identity: str | None
    accepted_origin: str | None
    allergens: tuple[str, ...]
    unresolved: tuple[str, ...]
    role: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "occurrence_id": self.occurrence_id,
            "source_name": self.source_name,
            "ai_candidate": self.ai_candidate,
            "accepted_identity": self.accepted_identity,
            "accepted_origin": self.accepted_origin,
            "allergens": list(self.allergens),
            "unresolved": list(self.unresolved),
            "role": self.role,
        }


def resolve_ingredient(ingredient: dict[str, Any]) -> IngredientResolution:
    source_name = str(ingredient.get("name", "")).strip()
    candidate = normalize_candidate(source_name)
    accepted = ingredient.get("accepted_identity")
    if accepted is not None:
        accepted = normalize_candidate(str(accepted)) or canonical_text(str(accepted)).replace(" ", "_")
    origin = ingredient.get("verified_origin")
    if origin is not None:
        origin = canonical_text(str(origin))
    unresolved: list[str] = []
    allergens: list[str] = []
    if not accepted:
        unresolved.append("identity_not_accepted")
    elif accepted == "lecithin":
        if not origin:
            unresolved.append("material_origin_unknown")
        elif origin not in ORIGIN_ALLERGENS:
            unresolved.append("material_origin_unrecognized")
        elif ORIGIN_ALLERGENS[origin]:
            allergens.append(str(ORIGIN_ALLERGENS[origin]))
    else:
        allergens.extend(ALLERGEN_RELATIONSHIPS.get(accepted, ()))

    # Processing is never treated as proof of removal. A verified finished-product
    # determination must be a separate input, not a magic processing flag.
    if ingredient.get("processing") and ingredient.get("claimed_eliminated"):
        if not ingredient.get("finished_product_evidence_ids"):
            unresolved.append("unsupported_processing_elimination_claim")

    for constituent in ingredient.get("constituents", []):
        child = resolve_ingredient(constituent)
        allergens.extend(child.allergens)
        unresolved.extend(f"constituent:{item}" for item in child.unresolved)
    return IngredientResolution(
        occurrence_id=str(ingredient.get("id", source_name or "unknown")),
        source_name=source_name,
        ai_candidate=candidate,
        accepted_identity=accepted,
        accepted_origin=origin,
        allergens=tuple(sorted(set(allergens))),
        unresolved=tuple(sorted(set(unresolved))),
        role=str(ingredient.get("role", "intentional_ingredient")),
    )


class KnowledgeGovernanceError(RuntimeError):
    pass


@dataclass(frozen=True)
class KnowledgeSource:
    artifact_id: str
    artifact_version: int
    sha256: str
    locator: str

    def validate(self) -> None:
        if not self.artifact_id or self.artifact_version <= 0 or not self.locator:
            raise KnowledgeGovernanceError("a versioned source and locator are required")
        if not re.fullmatch(r"[0-9a-f]{64}", self.sha256):
            raise KnowledgeGovernanceError("source SHA-256 is invalid")


@dataclass(frozen=True)
class Concept:
    concept_id: str
    concept_kind: str
    public_identifier: str | None
    state: str


@dataclass(frozen=True)
class GovernedName:
    name_id: str
    concept_id: str
    lexical_value: str
    language_tag: str
    label_kind: str
    source: KnowledgeSource
    approval_state: str


@dataclass(frozen=True)
class AssertionRevision:
    assertion_id: str
    revision: int
    subject_id: str
    predicate: str
    object_id: str
    polarity: str
    scope_kind: str
    scope: dict[str, Any]
    source: KnowledgeSource
    valid_from: str | None
    valid_until: str | None
    approval_state: str
    approved_by: str | None
    decision_reason: str | None
    supersedes_revision: int | None
    created_at: str


@dataclass(frozen=True)
class ExpertResolutionCase:
    case_id: str
    occurrence_id: str
    candidate_identity: str
    missing_fields: tuple[str, ...]
    state: str
    created_at: str


@dataclass(frozen=True)
class KnowledgeEvaluation:
    state: str
    supporting_assertion_ids: tuple[str, ...]
    opposing_assertion_ids: tuple[str, ...]


class GovernedKnowledgeBase:
    """Versioned, provenance-bearing knowledge distinct from product evidence."""

    CONCEPT_KINDS = {
        "ingredient", "commercial_material", "biological_source", "chemical_substance",
        "additive", "allergen_class", "functional_class", "process",
        "laboratory_analyte", "legal_category",
    }
    SCOPE_KINDS = {"general", "supplier", "material", "lot", "product", "jurisdiction"}

    def __init__(self) -> None:
        self.concepts: dict[str, Concept] = {}
        self.names: dict[str, GovernedName] = {}
        self.assertions: dict[str, list[AssertionRevision]] = {}
        self.resolution_cases: dict[str, ExpertResolutionCase] = {}

    def create_concept(
        self, concept_kind: str, *, public_identifier: str | None = None, state: str = "draft"
    ) -> Concept:
        if concept_kind not in self.CONCEPT_KINDS:
            raise KnowledgeGovernanceError("invalid concept kind")
        if public_identifier and any(
            concept.public_identifier == public_identifier for concept in self.concepts.values()
        ):
            raise KnowledgeGovernanceError("public identifier is already governed")
        concept = Concept(str(uuid.uuid4()), concept_kind, public_identifier, state)
        self.concepts[concept.concept_id] = concept
        return concept

    def add_name(
        self,
        concept_id: str,
        lexical_value: str,
        language_tag: str,
        label_kind: str,
        source: KnowledgeSource,
        *,
        approval_state: str = "proposed",
    ) -> GovernedName:
        if concept_id not in self.concepts:
            raise KnowledgeGovernanceError("unknown concept")
        if label_kind not in {"preferred", "alternative", "hidden", "transliteration"}:
            raise KnowledgeGovernanceError("invalid label kind")
        if approval_state not in {"proposed", "accepted", "rejected"}:
            raise KnowledgeGovernanceError("invalid name approval state")
        if not lexical_value.strip() or not language_tag.strip():
            raise KnowledgeGovernanceError("lexical value and BCP-47 language tag are required")
        source.validate()
        if label_kind == "preferred" and approval_state == "accepted" and any(
            name.concept_id == concept_id and name.language_tag == language_tag
            and name.label_kind == "preferred" and name.approval_state == "accepted"
            for name in self.names.values()
        ):
            raise KnowledgeGovernanceError("only one accepted preferred name is allowed per language")
        name = GovernedName(
            str(uuid.uuid4()), concept_id, lexical_value, language_tag, label_kind, source, approval_state
        )
        self.names[name.name_id] = name
        return name

    def resolve_name(self, value: str, *, language_tag: str | None = None) -> str | None:
        normalized = canonical_text(value)
        candidates = {
            name.concept_id for name in self.names.values()
            if name.approval_state == "accepted"
            and canonical_text(name.lexical_value) == normalized
            and (language_tag is None or name.language_tag == language_tag)
        }
        return next(iter(candidates)) if len(candidates) == 1 else None

    def propose_assertion(
        self,
        *,
        subject_id: str,
        predicate: str,
        object_id: str,
        polarity: str,
        scope_kind: str,
        scope: dict[str, Any],
        source: KnowledgeSource,
        valid_from: str | None = None,
        valid_until: str | None = None,
    ) -> AssertionRevision:
        if subject_id not in self.concepts or object_id not in self.concepts:
            raise KnowledgeGovernanceError("assertion endpoints must be governed concepts")
        if not predicate.strip() or polarity not in {"positive", "negative"}:
            raise KnowledgeGovernanceError("assertion predicate or polarity is invalid")
        if scope_kind not in self.SCOPE_KINDS:
            raise KnowledgeGovernanceError("assertion scope kind is invalid")
        if scope_kind != "general" and not scope:
            raise KnowledgeGovernanceError("a non-general assertion requires an explicit scope")
        source.validate()
        identifier = str(uuid.uuid4())
        revision = AssertionRevision(
            identifier, 1, subject_id, predicate, object_id, polarity, scope_kind, dict(scope), source,
            valid_from, valid_until, "proposed", None, None, None,
            datetime.now(timezone.utc).isoformat(),
        )
        self.assertions[identifier] = [revision]
        return revision

    def decide_assertion(
        self,
        assertion_id: str,
        *,
        decision: str,
        reviewer_id: str,
        reason: str,
    ) -> AssertionRevision:
        if decision not in {"accepted", "rejected", "superseded"}:
            raise KnowledgeGovernanceError("invalid assertion decision")
        if not reviewer_id.strip() or not reason.strip():
            raise KnowledgeGovernanceError("reviewer and decision reason are required")
        current = self.assertions[assertion_id][-1]
        if current.approval_state in {"rejected", "superseded"}:
            raise KnowledgeGovernanceError("terminal assertion cannot be revised")
        if decision == "superseded" and current.approval_state != "accepted":
            raise KnowledgeGovernanceError("only an accepted assertion can be superseded")
        revision = AssertionRevision(
            current.assertion_id, current.revision + 1, current.subject_id, current.predicate,
            current.object_id, current.polarity, current.scope_kind, current.scope, current.source,
            current.valid_from, current.valid_until, decision, reviewer_id, reason, current.revision,
            datetime.now(timezone.utc).isoformat(),
        )
        self.assertions[assertion_id].append(revision)
        return revision

    @staticmethod
    def _scope_applies(assertion: AssertionRevision, requested: dict[str, Any]) -> bool:
        if assertion.scope_kind == "general":
            return True
        return all(requested.get(key) == value for key, value in assertion.scope.items())

    def evaluate(
        self,
        subject_id: str,
        predicate: str,
        object_id: str,
        *,
        scope: dict[str, Any],
        at: str | None = None,
    ) -> KnowledgeEvaluation:
        moment = at or datetime.now(timezone.utc).isoformat()
        active = [
            revisions[-1] for revisions in self.assertions.values()
            if revisions[-1].approval_state == "accepted"
            and revisions[-1].subject_id == subject_id
            and revisions[-1].predicate == predicate
            and revisions[-1].object_id == object_id
            and self._scope_applies(revisions[-1], scope)
            and (revisions[-1].valid_from is None or revisions[-1].valid_from <= moment)
            and (revisions[-1].valid_until is None or moment < revisions[-1].valid_until)
        ]
        positive = tuple(sorted(item.assertion_id for item in active if item.polarity == "positive"))
        negative = tuple(sorted(item.assertion_id for item in active if item.polarity == "negative"))
        if positive and negative:
            state = "conflicted"
        elif positive:
            state = "supported_positive"
        elif negative:
            state = "supported_negative"
        else:
            state = "unknown"
        return KnowledgeEvaluation(state, positive, negative)

    def open_unspecified_e322_case(self, occurrence_id: str) -> ExpertResolutionCase:
        case = ExpertResolutionCase(
            str(uuid.uuid4()), occurrence_id, "lecithin",
            ("accepted_identity", "verified_biological_origin", "applicable_lot_evidence"),
            "open", datetime.now(timezone.utc).isoformat(),
        )
        self.resolution_cases[case.case_id] = case
        return case
