"""Deterministic semantic classification of Power BI field names."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import re
import unicodedata

from .policy import PrivacyLevel


class FieldSemanticCategory(str, Enum):
    """Sensitive semantic categories inferable from field names alone."""

    HEALTH = "health"
    BIOMETRIC = "biometric"
    GENETIC = "genetic"
    RELIGION = "religion"
    ETHNICITY = "ethnicity"
    POLITICAL = "political"
    TRADE_UNION = "trade_union"
    SEX_LIFE = "sex_life"
    PERSONAL_IDENTIFIER = "personal_identifier"


@dataclass(frozen=True, slots=True)
class FieldNameClassification:
    """A semantic classification without retaining the source field name."""

    category: FieldSemanticCategory
    level: PrivacyLevel


_CAMEL_ACRONYM_RE = re.compile(r"([A-Z]+)([A-Z][a-z])")
_CAMEL_BOUNDARY_RE = re.compile(r"([a-z0-9])([A-Z])")
_NON_ALNUM_RE = re.compile(r"[^a-z0-9]+")


_PHRASES: dict[FieldSemanticCategory, tuple[tuple[str, ...], ...]] = {
    FieldSemanticCategory.HEALTH: (
        ("patient",),
        ("paciente",),
        ("diagnosis",),
        ("diagnostico",),
        ("disease",),
        ("doenca",),
        ("medical",),
        ("medica",),
        ("medico",),
        ("medication",),
        ("medicacao",),
        ("prescription",),
        ("prescricao",),
        ("blood", "type"),
        ("tipo", "sanguineo"),
        ("health", "condition"),
        ("condicao", "saude"),
        ("condicao", "medica"),
    ),
    FieldSemanticCategory.BIOMETRIC: (
        ("biometric",),
        ("biometrica",),
        ("biometrico",),
        ("fingerprint", "template"),
        ("fingerprint", "scan"),
        ("facial", "recognition"),
        ("face", "template"),
        ("iris", "scan"),
        ("retina", "scan"),
        ("voiceprint",),
        ("identificacao", "biometrica"),
    ),
    FieldSemanticCategory.GENETIC: (
        ("dna",),
        ("genetic",),
        ("genetica",),
        ("genetico",),
        ("genotype",),
        ("genotipo",),
        ("genome",),
        ("genoma",),
        ("marcador", "genetico"),
        ("sequencia", "genetica"),
    ),
    FieldSemanticCategory.RELIGION: (
        ("religion",),
        ("religiao",),
        ("religious",),
        ("religiosa",),
        ("religioso",),
        ("faith",),
        ("denomination",),
        ("denominacao", "religiosa"),
        ("religious", "affiliation"),
        ("filiacao", "religiosa"),
    ),
    FieldSemanticCategory.ETHNICITY: (
        ("ethnicity",),
        ("ethnic",),
        ("etnia",),
        ("etnica",),
        ("etnico",),
        ("ethnic", "origin"),
        ("origem", "etnica"),
        ("race", "ethnicity"),
        ("racial", "origin"),
        ("raca", "cor"),
        ("cor", "raca"),
    ),
    FieldSemanticCategory.POLITICAL: (
        ("political",),
        ("politica",),
        ("politico",),
        ("political", "opinion"),
        ("opiniao", "politica"),
        ("political", "party"),
        ("partido", "politico"),
    ),
    FieldSemanticCategory.TRADE_UNION: (
        ("trade", "union"),
        ("labor", "union"),
        ("labour", "union"),
        ("union", "membership"),
        ("union", "member"),
        ("sindicato",),
        ("sindical",),
        ("sindicalizado",),
        ("filiacao", "sindical"),
    ),
    FieldSemanticCategory.SEX_LIFE: (
        ("sexual",),
        ("sexual", "orientation"),
        ("orientacao", "sexual"),
        ("sex", "life"),
        ("vida", "sexual"),
        ("sexual", "activity"),
        ("atividade", "sexual"),
    ),
}

_PERSONAL_DIRECT_PHRASES: tuple[tuple[str, ...], ...] = (
    ("cpf",),
    ("rg",),
    ("email",),
    ("e", "mail"),
    ("phone",),
    ("telephone",),
    ("telefone",),
    ("mobile",),
    ("celular",),
    ("passport",),
    ("passaporte",),
    ("national", "id"),
    ("documento", "identidade"),
    ("nome", "completo"),
    ("full", "name"),
)

_PERSON_CONTEXT = {
    "customer",
    "client",
    "cliente",
    "employee",
    "funcionario",
    "person",
    "pessoa",
    "user",
    "usuario",
    "patient",
    "paciente",
    "member",
    "membro",
}
_ID_TOKENS = {"id", "identifier", "identificador", "matricula"}
_NAME_TOKENS = {"name", "nome"}


def classify_field_name(name: str) -> tuple[FieldNameClassification, ...]:
    """Classify a field name locally without inspecting field values."""

    tokens = _tokenize(name)
    if not tokens:
        return ()

    categories: list[FieldSemanticCategory] = []

    for category in FieldSemanticCategory:
        if category is FieldSemanticCategory.PERSONAL_IDENTIFIER:
            if _is_personal_identifier(tokens):
                categories.append(category)
            continue

        phrases = _PHRASES[category]
        if any(_contains_phrase(tokens, phrase) for phrase in phrases):
            categories.append(category)

    return tuple(
        FieldNameClassification(category=category, level=PrivacyLevel.PERSONAL)
        for category in categories
    )


def _tokenize(name: str) -> tuple[str, ...]:
    ascii_text = "".join(
        character
        for character in unicodedata.normalize("NFKD", name)
        if not unicodedata.combining(character)
    )
    split = _CAMEL_ACRONYM_RE.sub(r"\1 \2", ascii_text)
    split = _CAMEL_BOUNDARY_RE.sub(r"\1 \2", split)
    normalized = _NON_ALNUM_RE.sub(" ", split.lower()).strip()
    return tuple(normalized.split()) if normalized else ()


def _contains_phrase(tokens: tuple[str, ...], phrase: tuple[str, ...]) -> bool:
    if len(phrase) > len(tokens):
        return False
    return any(
        tokens[index : index + len(phrase)] == phrase
        for index in range(len(tokens) - len(phrase) + 1)
    )


def _is_personal_identifier(tokens: tuple[str, ...]) -> bool:
    if any(_contains_phrase(tokens, phrase) for phrase in _PERSONAL_DIRECT_PHRASES):
        return True

    token_set = set(tokens)
    has_person_context = bool(token_set & _PERSON_CONTEXT)
    if not has_person_context:
        return False

    return bool(token_set & (_ID_TOKENS | _NAME_TOKENS))
