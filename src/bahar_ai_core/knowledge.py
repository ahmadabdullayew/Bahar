"""Version-pinned, fail-closed ingredient knowledge adapter.

Identity and source-category associations are editorial REFERENCE CANDIDATES.
Never interprets national food-labeling law or material-lot truth.
"""
from __future__ import annotations
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
import json
import re
import unicodedata

DATA_DIR = Path(__file__).resolve().parent / 'resources' / 'ingredient_knowledge_v1'
REQUIRED_FILES = ('concepts.jsonl','aliases.jsonl','relations.jsonl','categories.jsonl',
                  'regulatory_profiles.jsonl','sources.jsonl','review_queue.jsonl')
DEFAULT_PROFILE = 'EU_ANNEX_II_REFERENCE'  # reference taxonomy, NOT a legal rule
# Release-pinned SHA-256. Dataset changes require a reviewed code release.
PINNED_MANIFEST_SHA256 = '8f19c3a6c7d58c718447cf2727122d3997ff72eabaa2a663cb30a6affd3e5efc'


def normalize(text: str) -> str:
    if not isinstance(text, str):
        raise TypeError('Ingredient text must be a string')
    return ' '.join(unicodedata.normalize('NFKC', text).casefold().replace('’', "'")
                    .replace('‐','-').replace('–','-').split())


class KnowledgeIntegrityError(ValueError):
    pass


@dataclass(frozen=True)
class Concept:
    id: str
    aliases: tuple[str, ...]
    allergens: tuple[str, ...] = ()
    origin_resolved: bool = True
    caveats: tuple[str, ...] = ()


class KnowledgeRepository:
    """Load only authenticated-to-a-trusted-manifest files; no fallback on corruption.

    Verification of a local digest is integrity checking, NOT cryptographic authenticity.
    Caller should distribute/trust a pinned digest of the manifest itself.
    """
    def __init__(self, data_dir: Path = DATA_DIR, *, profile: str = DEFAULT_PROFILE):
        self.data_dir = Path(data_dir)
        if self.data_dir.is_symlink():
            raise KnowledgeIntegrityError('Knowledge directory must not be a symbolic link')
        manifest_file = self.data_dir / 'manifest.json'
        manifest_raw = manifest_file.read_bytes()
        self.manifest_sha256 = sha256(manifest_raw).hexdigest()
        if self.manifest_sha256 != PINNED_MANIFEST_SHA256:
            raise KnowledgeIntegrityError('Dataset manifest differs from release-pinned identity')
        try:
            self.manifest = json.loads(manifest_raw)
        except (ValueError, UnicodeError) as exc:
            raise KnowledgeIntegrityError('Invalid knowledge manifest') from exc
        if self.manifest.get('dataset_id') != 'BAHAR_INGREDIENT_KNOWLEDGE' or self.manifest.get('version') != '1.0.0':
            raise KnowledgeIntegrityError('Incompatible knowledge dataset identity/version')
        expected = self.manifest.get('file_sha256')
        if not isinstance(expected, dict) or not set(REQUIRED_FILES).issubset(expected):
            raise KnowledgeIntegrityError('Knowledge manifest is incomplete')
        for name, digest in expected.items():
            if not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}', name) or name.startswith('.'):
                raise KnowledgeIntegrityError('Unsafe knowledge artifact filename')
            path = self.data_dir / name
            if path.is_symlink() or not path.is_file() or sha256(path.read_bytes()).hexdigest() != digest:
                raise KnowledgeIntegrityError(f'Knowledge integrity check failed: {name}')
        def load(name):
            return [json.loads(x) for x in (self.data_dir / name).read_text(encoding='utf-8').splitlines() if x.strip()]
        raw_concepts = load('concepts.jsonl')
        raw_aliases = load('aliases.jsonl')
        # Descriptive inventory, not a proof of language coverage or recall.
        self.alias_language_counts = {lang: sum(a.get('language') == lang for a in raw_aliases)
                                      for lang in ('az', 'en', 'ru')}
        self.alias_review_status = 'UNREVIEWED_EDITORIAL_SEED' 
        raw_relations = load('relations.jsonl')
        raw_categories = load('categories.jsonl')
        raw_profiles = load('regulatory_profiles.jsonl')
        self.raw_concepts = {c['concept_id']:c for c in raw_concepts}
        self.raw_categories = {c['category_id']:c for c in raw_categories}
        self.profiles = {p['profile_id']:p for p in raw_profiles}
        if (len(self.raw_concepts) != len(raw_concepts) or len(self.raw_categories) != len(raw_categories)
                or len(self.profiles) != len(raw_profiles)):
            raise KnowledgeIntegrityError('Duplicate knowledge identities')
        if profile not in self.profiles:
            raise KnowledgeIntegrityError('Unknown reference profile')
        if any(p['mode'] == 'EXECUTABLE' or 'NOT_EXECUTABLE' not in p['mode'] for p in self.profiles.values()):
            raise KnowledgeIntegrityError('Executable or unrecognized legal profile is forbidden')
        self.profile = profile
        allowed = set(self.profiles[profile]['categories'])
        self.alias_index = {}
        by_concept = {key: [] for key in self.raw_concepts}
        for a in raw_aliases:
            cid = a['concept_id']
            key = normalize(a['alias'])
            if (cid not in self.raw_concepts or key != a['normalized']
                    or key in self.alias_index or not key):
                raise KnowledgeIntegrityError('Ambiguous, unrecognized, or invalid alias')
            self.alias_index[key] = cid
            by_concept[cid].append(a['alias'])
        self.concepts = {}
        for cid, record in self.raw_concepts.items():
            categories = record['reference_category_ids']
            if (record.get('approved_for_production') is not False or record.get('material_lot_verified') is not False
                    or record.get('regulatory_status') != 'NOT_ASSESSED'):
                raise KnowledgeIntegrityError('Knowledge seed must not assert verified production status')
            if not set(categories) <= set(self.raw_categories):
                raise KnowledgeIntegrityError('Concept references unknown category')
            self.concepts[cid] = Concept(cid, tuple(by_concept[cid]), tuple(sorted(set(categories)&allowed)),
                record['identity_origin_status'] != 'UNKNOWN_ORIGIN', tuple(record['caveat_flags']))
        self.relations = {}
        relation_ids = set()
        for r in raw_relations:
            if r['relation_id'] in relation_ids or r['subject_concept_id'] not in self.concepts or r['object_category_id'] not in self.raw_categories:
                raise KnowledgeIntegrityError('Invalid relation identity or reference')
            relation_ids.add(r['relation_id'])
            self.relations.setdefault(r['subject_concept_id'], []).append(r)
        self.aliases = tuple(sorted(((a['alias'], self.concepts[a['concept_id']]) for a in raw_aliases),
                                  key=lambda pair:(-len(pair[0]), pair[0].casefold(), pair[1].id)))
        self.digest = sha256(json.dumps({'manifest':self.manifest_sha256, 'profile': profile},sort_keys=True).encode()).hexdigest()

    def lookup(self, text: str) -> dict:
        key = normalize(text)
        cid = self.alias_index.get(key)
        if cid is None:
            return {'lookup_status':'UNRESOLVED', 'concept_id':None, 'reference_category_candidates':[],
                    'candidate_only':True, 'legal_verdict':'NOT_EVALUATED'}
        c = self.concepts[cid]
        return {'lookup_status':'EXACT_ALIAS_CANDIDATE', 'concept_id':cid,
                'reference_category_candidates':list(c.allergens),
                'caveats': list(c.caveats), 'origin_resolved':c.origin_resolved,
                'candidate_only':True, 'legal_verdict':'NOT_EVALUATED',
                'material_lot_verified':False, 'approved_for_production':False,
                'dataset_version': self.manifest['version'], 'knowledge_sha256': self.digest,
                'reference_profile':self.profile}


KNOWLEDGE = KnowledgeRepository()
CONCEPTS = tuple(KNOWLEDGE.concepts.values())
BY_ID = KNOWLEDGE.concepts
ALIASES = KNOWLEDGE.aliases
VOCABULARY_DIGEST = KNOWLEDGE.digest
_NEGATIVE = re.compile(r'^\s*(?:may\s+contain|might\s+contain|free\s+from|free\s+of|without|contains\s+no|no\s+|non[- ]dairy|plant[- ]based|vegan)\b',re.I)
# These are broad textual category mentions, NOT accepted ingredient identities.
_CATEGORY_WORDS = {'milk':'milk','soy':'soy','soya':'soy','fish':'fish','wheat':'gluten_cereal',
                   'sesame':'sesame','peanut':'peanut','egg':'egg','mustard':'mustard',
                   'celery':'celery','lupin':'lupin', 'tree nuts':'tree_nut', 'rye':'gluten_cereal', 'barley':'gluten_cereal', 'oat':'gluten_cereal'}


def recognize_spans(fragment: str, repository: KnowledgeRepository | None = None) -> list[tuple[int,int,Concept]]:
    if not isinstance(fragment,str):
        raise TypeError('Ingredient text must be a string')
    active = repository or KNOWLEDGE
    found = []
    for alias,concept in active.aliases:
        for m in re.finditer(r'(?<!\w)'+re.escape(alias)+r'(?!\w)',fragment,re.I):
            if not any(m.start()<end and start<m.end() for start,end,_ in found):
                found.append((m.start(),m.end(),concept))
    return sorted(found,key=lambda x:(x[0],x[1]))


def recognize(fragment: str, repository: KnowledgeRepository | None = None) -> list[Concept]:
    return list(dict.fromkeys(c for _,_,c in recognize_spans(fragment, repository)))


def classify_fragment(fragment: str, repository: KnowledgeRepository | None = None) -> tuple[tuple[str,...],tuple[str,...],bool]:
    """Candidate-only classification. Incomplete semantic text always remains unresolved."""
    active = repository or KNOWLEDGE
    if not isinstance(fragment,str) or not fragment.strip():
        return (),(),True
    if _NEGATIVE.search(fragment):
        return (),(),True
    exact = active.lookup(fragment)
    if exact['concept_id']:
        cid=exact['concept_id']
        c=active.concepts[cid]
        # Processing/legal caveats do NOT imply unknown botanical origin.
        return (cid,), c.allergens, not c.origin_resolved
    # For a single category word, give a conservative possible category but no ingredient identity.
    k=normalize(fragment)
    if k in _CATEGORY_WORDS and _CATEGORY_WORDS[k] in active.profiles[active.profile]['categories']:
        return (),(_CATEGORY_WORDS[k],),True
    spans=recognize_spans(fragment, active)
    concepts=list(dict.fromkeys(c for _,_,c in spans))
    cats=tuple(sorted({a for c in concepts for a in c.allergens}))
    # Even if known subwords were found, partial compound descriptions remain unresolved.
    return tuple(c.id for c in concepts),cats,True


def cereal_source_for_concept(concept_id: str | None, repository: KnowledgeRepository | None = None) -> str | None:
    """Reference-only species grouping for distinguishing gluten-cereal sources."""
    active = repository or KNOWLEDGE
    if not concept_id or concept_id not in active.concepts or 'gluten_cereal' not in active.concepts[concept_id].allergens:
        return None
    name = concept_id.removeprefix('ING-')
    if name.startswith(('WHEAT', 'DURUM', 'SPELT', 'SEMOLINA', 'COUSCOUS-WHEAT', 'BULGUR')):
        return 'wheat'
    for source in ('RYE', 'BARLEY', 'OAT'):
        if name.startswith(source):
            return source.casefold()
    return None


def _category_mentions(text: str, section_kind: str, repository: KnowledgeRepository | None = None):
    """Conservative positive label category mentions; avoid substring/plant milk promotion."""
    # Generic category words are recognized ONLY as standalone declarations or
    # standalone ingredient-list items; never as substrings of unknown beverages.
    active = repository or KNOWLEDGE
    if section_kind not in ('contains','allergens','ingredient'):
        return
    for term,cat in _CATEGORY_WORDS.items():
        if cat not in active.profiles[active.profile]['categories']:
            continue
        # Only standalone comma/and-delimited labels: 'Contains: milk, soy' not 'rice milk'.
        pattern=r'(?:^|,|\band\b)\s*('+re.escape(term)+r')\s*(?=,|\band\b|$)'
        for match in re.finditer(pattern,text,re.I):
            yield match.start(1),match.end(1),cat


def label_mentions(label: str, repository: KnowledgeRepository | None = None) -> list[dict]:
    """Only limited positive text mentions. Not legal declaration, emphasis, or placement validation."""
    active = repository or KNOWLEDGE
    if not isinstance(label,str):
        raise TypeError('Label text must be a string')
    out=[]
    header_pattern=re.compile(
        r'\b(does\s+not\s+contain|do\s+not\s+contain|not\s+contain|free\s+of|may\s+contain|'
        r'might\s+contain|free\s+from|without|contains\s+no|no|ingredients?|contains|allergens?)\s*:?(?=\s|$)',re.I)
    for sentence in re.finditer(r'[^;.\n]+',label):
        content=sentence.group()
        headers=list(header_pattern.finditer(content))
        sections=[]
        if not headers:
            sections=[(0,len(content),'positive','other')]
        else:
            if content[:headers[0].start()].strip():
                sections.append((0,headers[0].start(),'positive','other'))
            for i,h in enumerate(headers):
                kind=h.group(1).casefold()
                state='excluded' if kind in ('may contain','might contain','free from','free of','without','contains no','not contain','do not contain','does not contain','no') else 'positive'
                section_kind = 'ingredient' if kind in ('ingredient','ingredients') else ('contains' if kind == 'contains' else 'allergens' if kind in ('allergen','allergens') else 'other')
                boundary=headers[i+1].start() if i+1<len(headers) else len(content)
                sections.append((h.end(),boundary,state,section_kind))
        for a,b,status,section_kind in sections:
            if status!='positive':
                continue
            statement=content[a:b]
            def push(start,end,cat,concept=None):
                if re.match(r'\s*[- ]free\b',statement[end:],re.I):return
                out.append({'allergen':cat,'text':statement[start:end],
                    'span':[sentence.start()+a+start,sentence.start()+a+end],
                    'concept':concept,'context':'reference_category_textual_candidate',
                    'reference_profile':active.profile,'legal_verdict':'NOT_EVALUATED',
                    'cereal_source': (cereal_source_for_concept(concept, active) if concept else (statement[start:end].casefold() if statement[start:end].casefold() in ('wheat','rye','barley','oat') else None))})
            recognized=recognize_spans(statement, active)
            for s,e,c in recognized:
                for category in c.allergens:
                    push(s,e,category,c.id)
            for start,end,cat in _category_mentions(statement,section_kind,active):
                if any(start>=s and end<=e for s,e,_ in recognized):
                    continue
                push(start,end,cat)
    return sorted(out,key=lambda m:(m['span'][0],m['allergen']))


def explicit_allergens_in_label(label: str, repository: KnowledgeRepository | None = None) -> set[str]:
    return {m['allergen'] for m in label_mentions(label, repository)}


def textual_label_conflicts(label: str, repository: KnowledgeRepository | None = None) -> list[dict]:
    """Detect incompatible positive and explicit negative textual mentions.

    This flags only obvious lexical contradictions, not regulatory or factual contradictions.
    """
    active = repository or KNOWLEDGE
    positives = label_mentions(label, active)
    positively_mentioned = {m['allergen'] for m in positives}
    negatives: set[str] = set()
    for term, category in _CATEGORY_WORDS.items():
        if category not in active.profiles[active.profile]['categories']:
            continue
        expression = re.escape(term)
        if (re.search(r'(?<!\w)' + expression + r'[- ]free\b', label, re.I)
                or re.search(r'\b(?:free\s+from|without|no|does\s+not\s+contain|contains\s+no)\s*:?[ \t]*' + expression + r'\b', label, re.I)):
            negatives.add(category)
    return [{'category': category, 'reason': 'POSITIVE_AND_NEGATIVE_TEXTUAL_MENTIONS',
             'legal_verdict': 'NOT_EVALUATED'}
            for category in sorted(negatives & positively_mentioned)]
