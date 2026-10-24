"""Privacy-minimizing cross-institution identity candidate rules.

This module produces review candidates only. It never declares an identity official,
merges records, or makes an automated fraud decision.
"""
from difflib import SequenceMatcher
import unicodedata

RULESET_VERSION = "cross-institution-identity-candidates-v1"


def normalize(value):
    return " ".join(unicodedata.normalize("NFKC", str(value or "")).casefold().split())


def mask_identifier(value):
    value = str(value or "").strip()
    if not value:
        return "Not provided"
    return "•••• " + value[-4:]


def reconcile_records(records, current_institution):
    """Return records in current institution with cross-institution review signals.

    Exact normalized APAAR identifier matches are the only cross-institution key.
    Names are compared only to flag a conflict for human review. No foreign names,
    emails, full identifiers, or notes are returned to the requesting institution.
    """
    active = [dict(row) for row in records if not row.get("archived_at")]
    by_identifier = {}
    for row in active:
        key = normalize(row.get("apaar_id"))
        if key:
            by_identifier.setdefault(key, []).append(row)

    results = []
    for local in active:
        if local.get("institution") != current_institution:
            continue
        key = normalize(local.get("apaar_id"))
        if not key:
            continue
        matches = [r for r in by_identifier.get(key, [])
                   if r.get("institution") != current_institution
                   and str(r.get("id")) != str(local.get("id"))]
        for other in matches:
            local_name, other_name = normalize(local.get("full_name")), normalize(other.get("full_name"))
            name_match = bool(local_name and other_name and local_name == other_name)
            results.append({
                "local_student_id": local.get("id"),
                "local_institution_student_id": local.get("institution_student_id", ""),
                "local_name": local.get("full_name", ""),
                "other_institution": other.get("institution", "Unknown institution"),
                "other_student_id_masked": mask_identifier(other.get("institution_student_id")),
                "signal": "IDENTIFIER_AND_NAME_MATCH" if name_match else "IDENTIFIER_MATCH_NAME_CONFLICT",
                "name_match": name_match,
                "explanation": (
                    "The same normalized identifier and name appear in both institutions; confirm authorized record provenance."
                    if name_match else
                    "The same normalized identifier appears with a different name; review source records before taking action."
                ),
                "ruleset_version": RULESET_VERSION,
            })
    return sorted(results, key=lambda item: (item["signal"] != "IDENTIFIER_MATCH_NAME_CONFLICT",
                                              str(item["local_name"]).casefold(),
                                              str(item["other_institution"]).casefold()))
