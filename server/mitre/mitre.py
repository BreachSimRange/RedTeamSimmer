import json
from pathlib import Path

_DATA_FILE = Path(__file__).resolve().parent / "attack_v19.json"
with open(_DATA_FILE, "r", encoding="utf-8") as _f:
    _DATA = json.load(_f)

VERSION = _DATA["version"]
RELEASED = _DATA["released"]

_TACTICS = _DATA["tactics"]
_ORDER = _DATA["tactics_order"]
_HIDDEN = set(_DATA.get("hidden_in_ui", []))

_STEALTH = set(_DATA["techniques_stealth"])
_DEFENSE_IMPAIRMENT = set(_DATA["techniques_defense_impairment"])


def techniques_for_tactic(short):
    """Return the v19 technique ID list for a given tactic short name,
    or an empty list if the tactic isn't tracked in the split."""
    s = (short or "").strip().lower()
    if s == "stealth":
        return list(_DATA["techniques_stealth"])
    if s == "defense-impairment":
        return list(_DATA["techniques_defense_impairment"])
    return []


def get_tactics(include_hidden=False):
    """Return tactics in canonical v19 order. By default hides Reconnaissance and
    Resource Development since no Windows atomics are mapped to them."""
    result = []
    for short in _ORDER:
        if not include_hidden and short in _HIDDEN:
            continue
        t = _TACTICS[short]
        result.append({
            "id": t["id"],
            "name": t["name"],
            "short": t["short"],
        })
    return result


def get_tactic_by_short(short):
    short = (short or "").strip().lower()
    return _TACTICS.get(short)


def canonical_tactic_order(include_hidden=False):
    if include_hidden:
        return list(_ORDER)
    return [s for s in _ORDER if s not in _HIDDEN]


def is_hidden_tactic(short):
    return (short or "").strip().lower() in _HIDDEN


def tactic_for_technique(tid):
    """Return the v19 short tactic key for a technique ID, or None if unknown.
    Only resolves Stealth and Defense Impairment (the v19 split). Other tactics
    are determined by the upstream Atomic Red Team markdown index."""
    if not tid:
        return None
    if tid in _DEFENSE_IMPAIRMENT:
        return "defense-impairment"
    if tid in _STEALTH:
        return "stealth"
    # Try parent technique
    parent = tid.split(".")[0]
    if parent in _DEFENSE_IMPAIRMENT:
        return "defense-impairment"
    if parent in _STEALTH:
        return "stealth"
    return None


def short_to_display(short):
    t = get_tactic_by_short(short)
    return t["name"] if t else None


def display_to_short(name):
    if not name:
        return None
    n = name.strip().lower().replace(" ", "-")
    if n in _TACTICS:
        return n
    return None
