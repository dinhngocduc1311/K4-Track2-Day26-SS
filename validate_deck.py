#!/usr/bin/env python3
"""validate_deck.py — the offline legality gate (CONTRACTS.md section 8, RULES.md section 5).

    python validate_deck.py [deck.json] [lineup.json] [--world PATH]

(`Makefile:29`'s `make validate` calls it positionally: `validate_deck.py deck/deck.json
deck/lineup.json` — both arguments are optional here and default to exactly that, so a bare
`python validate_deck.py` from the repo root also works.)

RULES.md section 5, verbatim, is the checklist this module exists to enforce **before** a card
ever reaches the tournament ("Invalid cards never enter the tournament — they are rejected at
lock, not at play"):

    14 cards: 10 attacks + 4 blanks. You play 10 in a locked order, no repeats.
    >=3 MCP-layer . >=3 A2A-layer . >=2 gateway-layer . >=6 distinct classes of the nine
    every `replica_flip` card must name a `path_id` in the measured drift set
    lethality band: it must fall to `rookie` and be held by `adversary`

Every failure this module reports names the card, the rule, and what to change — "failures must
be specific and fixable" (this task's own brief) — never a bare "invalid deck".

WHAT THIS MODULE CAN AND CANNOT CHECK, HONESTLY
================================================================================================
This file runs in the STUDENT KIT with the standard library and local `kit/` modules. The
student export deliberately omits the instructor's answer key and scored Arena runner. Two
consequences are reported explicitly:

1. **The world.** The real 12,375-page student export is downloaded separately into
   `kit/world/<world-id>/`. :func:`resolve_world` tries it first, then falls back to the small
   fixture world and reports which one was used. Use `make validate` or pass `--world` to check
   anchors and drift against the real corpus.

2. **The lethality band.** The bots, local `spar.py`, and `kit.mcp.mutations.MutableStack` can
   exercise cards offline, but `spar.py` scripts its tool results and ANSWER, and the student
   world has no `truth.json` for the curriculum analyst. They cannot certify the scored Arena
   result. :func:`check_lethality_band` therefore reports two mechanical proxies:

   * **falls to rookie** — "rookie... trusts everything... no guardrails" (FINAL-PLAN.md section
     9) is, by that definition, a gateway that forwards every command. Whether a card's mutation
     "falls" against one is exactly the question "does this op find a real, resolvable target to
     poison in the world, given nothing stops it" — answerable here with the SAME kit-only
     primitives the local mutation engine uses (`kit.world.loader.World.page`,
     `kit.mcp.a2a.mint_delegation`/`verify_card`).
   * **held by adversary** — this validator does not run the adversary through a scored duel.
     What CAN be checked mechanically, using only this file's own referee-detector
     algebra (a two-line reimplementation of CONTRACTS section 6.4's `enforcement_failure` rule:
     `applied AND trigger_matched AND verdict != "deny" => violation`), is that the card is not
     *undefendable in principle* — that denying the specific command carrying the mutation's
     target structurally prevents the violation. This is NECESSARY for "a correct policy holds
     it" but not sufficient proof that `bots/adversary/`'s actual heuristic would find that
     denial; :func:`check_lethality_band` labels this sub-check `HELD_IN_PRINCIPLE`, distinct
     from a claim that the real bot won a scored duel.

   Both proxies are reported at their own named severity (`FAIL` only for the mechanical checks
   this module can actually stand behind; a separate `WARN`-level note for the bot-ladder gap) —
   never silently passed, never silently skipped.

Stdlib only, plus `kit/`. No network, no wall-clock, no randomness.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping, Sequence

_REPO_ROOT = Path(__file__).resolve().parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from kit.world.anchor import Anchor, AnchorSyntaxError  # noqa: E402
from kit.world.loader import World  # noqa: E402
from kit.mcp import a2a as mcp_a2a  # noqa: E402
from kit.mcp.specs import A2A_PEERS, MCP_SERVERS  # noqa: E402

__all__ = [
    "MUTATION_OPS",
    "DUEL_CLASSES",
    "MCP_LAYER_CLASSES",
    "GATEWAY_LAYER_CLASSES",
    "A2A_LAYER_CLASSES",
    "Finding",
    "ValidationReport",
    "load_deck",
    "load_lineup",
    "resolve_world",
    "validate",
    "main",
]

# ---------------------------------------------------------------------------
# The closed vocabularies — CONTRACTS.md section 8 / FINAL-PLAN.md section 4.4.
# Kept local for the validator's small legality vocabulary. The student kit also ships
# kit.mcp.mutations; validator tests pin this copy's closed op/class set.
# ---------------------------------------------------------------------------

MUTATION_OPS: frozenset[str] = frozenset(
    {
        "replace_act", "replace_aud", "swap_replica", "poison_row", "inflate_catalog",
        "shadow_server", "forge_card", "corrupt_peer_answer", "drop_header",
    }
)
MCP_LAYER_CLASSES: frozenset[str] = frozenset({"drift", "shadow", "poisoned_result", "schema_bomb"})
GATEWAY_LAYER_CLASSES: frozenset[str] = frozenset({"header_spoof", "replica_flip"})
A2A_LAYER_CLASSES: frozenset[str] = frozenset({"forged_card", "faithless_peer", "identity"})
DUEL_CLASSES: frozenset[str] = MCP_LAYER_CLASSES | GATEWAY_LAYER_CLASSES | A2A_LAYER_CLASSES

_MIN_MCP = 3
_MIN_A2A = 3
_MIN_GATEWAY = 2
_MIN_DISTINCT_CLASSES = 6
_N_ATTACKS = 10
_N_BLANKS = 4
_N_CARDS = _N_ATTACKS + _N_BLANKS
_LINEUP_SIZE = 10

# CONTRACTS.md section 7: which ask fields are Anchor-shaped, per ask type, and whether each
# is an ASK INPUT (validated here) vs. only an ANSWER field (validated by the referee against
# truth.json, not checkable offline without it).
_ASK_ANCHOR_INPUT_FIELDS: Mapping[str, tuple[str, ...]] = {
    "which_day_covers": ("concept",),
    "source_of": ("claim",),
    "citation_for": ("concept",),
    "contradiction_between": ("talk",),
    "whatlinkshere": ("anchor",),
    "record_mastery": ("learner", "concept"),
    # current_version_of's identity field is `path_id` — a bare hex slug, not an Anchor string
    # (kit.world.loader.ASK_IDENTITY_FIELDS agrees) — checked separately, against drift.json.
    # define_term's identity field is `term` — a free-text string, nothing to Anchor.parse.
}

_ASK_TYPES: frozenset[str] = frozenset(
    {
        "which_day_covers", "source_of", "citation_for", "current_version_of",
        "contradiction_between", "define_term", "whatlinkshere", "record_mastery",
    }
)


@dataclass(frozen=True, slots=True)
class Finding:
    """One line of the report. `severity` is `FAIL` (blocks legality) or `WARN` (visible, does
    not block — reserved for the bot-ladder gap this module cannot close on its own)."""

    severity: str  # "FAIL" | "WARN"
    rule: str
    card_id: str | None
    message: str

    def render(self) -> str:
        where = f"[{self.card_id}] " if self.card_id else ""
        return f"{self.severity:4} {self.rule:28} {where}{self.message}"


@dataclass(slots=True)
class ValidationReport:
    findings: list[Finding] = field(default_factory=list)

    def fail(self, rule: str, card_id: str | None, message: str) -> None:
        self.findings.append(Finding("FAIL", rule, card_id, message))

    def warn(self, rule: str, card_id: str | None, message: str) -> None:
        self.findings.append(Finding("WARN", rule, card_id, message))

    def ok(self) -> bool:
        return not any(f.severity == "FAIL" for f in self.findings)

    def render(self) -> str:
        if not self.findings:
            return "PASS  every check green — this deck is legal."
        lines = [f.render() for f in self.findings]
        n_fail = sum(1 for f in self.findings if f.severity == "FAIL")
        n_warn = sum(1 for f in self.findings if f.severity == "WARN")
        lines.append("")
        lines.append(
            f"{'FAIL' if n_fail else 'PASS'}: {n_fail} failing check(s), {n_warn} warning(s)."
        )
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------


def load_deck(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def load_lineup(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def resolve_world(explicit: str | None = None) -> tuple[World, str]:
    """`--world PATH` when given; else `kit/world/` if it is a populated world directory; else
    the shipped fixture world (`kit.world.fixture.build_fixture_world`), built into a temp dir.
    Returns `(world, source_label)` — the label is printed so a report never quietly ran against
    the wrong world."""
    if explicit:
        p = Path(explicit)
        return World.load(p), f"--world {p}"

    kit_world_dir = _REPO_ROOT / "kit" / "world" / "data"
    for candidate in (kit_world_dir, _REPO_ROOT / "kit" / "world"):
        manifest = candidate / "manifest.json"
        if manifest.is_file():
            try:
                return World.load(candidate), f"kit/world ({candidate.relative_to(_REPO_ROOT)})"
            except Exception:  # noqa: BLE001 - fall through to the fixture, loudly, below
                pass

    from kit.world import fixture as _fixture

    tmp = tempfile.mkdtemp(prefix="colosseum-validate-deck-")
    world_dir = _fixture.build_fixture_world(tmp, include_truth=False)
    return World.load(world_dir), (
        "FIXTURE WORLD (kit/world/ is not populated — WORLDBUILD-REPORT.md's own known gap; "
        "anchor/drift checks below are real, but only over the small synthetic fixture, not "
        "the real course corpus. Pass --world <path> to check against a real export.)"
    )


# ---------------------------------------------------------------------------
# R1 — card counts and id uniqueness
# ---------------------------------------------------------------------------


def check_card_counts(deck: Mapping, report: ValidationReport) -> list[dict]:
    cards = deck.get("cards")
    if not isinstance(cards, list):
        report.fail("R1-card-counts", None, "deck.json has no 'cards' list")
        return []

    ids = [c.get("id") for c in cards]
    seen: set = set()
    for cid in ids:
        if cid in seen:
            report.fail("R1-card-counts", cid, "duplicate card id")
        seen.add(cid)

    if len(cards) != _N_CARDS:
        report.fail(
            "R1-card-counts", None,
            f"deck has {len(cards)} cards, need exactly {_N_CARDS} ({_N_ATTACKS} attack + {_N_BLANKS} blank)",
        )

    attacks = [c for c in cards if c.get("kind") == "attack"]
    blanks = [c for c in cards if c.get("kind") == "blank"]
    other = [c for c in cards if c.get("kind") not in ("attack", "blank")]
    if len(attacks) != _N_ATTACKS:
        report.fail("R1-card-counts", None, f"{len(attacks)} attack cards, need exactly {_N_ATTACKS}")
    if len(blanks) != _N_BLANKS:
        report.fail("R1-card-counts", None, f"{len(blanks)} blank cards, need exactly {_N_BLANKS}")
    for c in other:
        report.fail("R1-card-counts", c.get("id"), f"kind={c.get('kind')!r} is neither 'attack' nor 'blank'")

    return cards


# ---------------------------------------------------------------------------
# R2 — layer balance
# ---------------------------------------------------------------------------


def _layer_of(cls: str) -> str | None:
    if cls in MCP_LAYER_CLASSES:
        return "MCP"
    if cls in GATEWAY_LAYER_CLASSES:
        return "gateway"
    if cls in A2A_LAYER_CLASSES:
        return "A2A"
    return None


def check_layer_balance(attacks: Sequence[dict], report: ValidationReport) -> None:
    counts = {"MCP": 0, "gateway": 0, "A2A": 0}
    for c in attacks:
        cls = c.get("class")
        layer = _layer_of(cls)
        if layer is None:
            report.fail(
                "R2-layer-balance", c.get("id"),
                f"class {cls!r} is not one of the nine closed duel classes {sorted(DUEL_CLASSES)}",
            )
            continue
        counts[layer] += 1
    if counts["MCP"] < _MIN_MCP:
        report.fail("R2-layer-balance", None, f"only {counts['MCP']} MCP-layer attack card(s), need >= {_MIN_MCP}")
    if counts["A2A"] < _MIN_A2A:
        report.fail("R2-layer-balance", None, f"only {counts['A2A']} A2A-layer attack card(s), need >= {_MIN_A2A}")
    if counts["gateway"] < _MIN_GATEWAY:
        report.fail("R2-layer-balance", None, f"only {counts['gateway']} gateway-layer attack card(s), need >= {_MIN_GATEWAY}")


# ---------------------------------------------------------------------------
# R3 — distinct classes
# ---------------------------------------------------------------------------


def check_distinct_classes(attacks: Sequence[dict], report: ValidationReport) -> None:
    classes = {c.get("class") for c in attacks if c.get("class") in DUEL_CLASSES}
    if len(classes) < _MIN_DISTINCT_CLASSES:
        report.fail(
            "R3-distinct-classes", None,
            f"only {len(classes)} distinct class(es) among attacks ({sorted(classes)}), need >= {_MIN_DISTINCT_CLASSES}",
        )


# ---------------------------------------------------------------------------
# R4 — mutation shape: closed op set, well-formed target
# ---------------------------------------------------------------------------

_TARGET_RE = re.compile(r"^(mcp|a2a):([a-z][a-z0-9-]*)$")


def check_mutation_shape(attacks: Sequence[dict], report: ValidationReport) -> None:
    for c in attacks:
        cid = c.get("id")
        mutation = c.get("mutation")
        if not isinstance(mutation, Mapping):
            report.fail("R4-mutation-shape", cid, "attack card has no 'mutation' block")
            continue
        op = mutation.get("op")
        if op not in MUTATION_OPS:
            report.fail("R4-mutation-shape", cid, f"mutation.op {op!r} is not one of the nine closed ops {sorted(MUTATION_OPS)}")
        target = mutation.get("target")
        m = _TARGET_RE.match(target) if isinstance(target, str) else None
        if m is None:
            report.fail("R4-mutation-shape", cid, f"mutation.target {target!r} must match 'mcp:<server>' or 'a2a:<peer>'")
            continue
        kind, name = m.groups()
        if kind == "mcp" and name not in MCP_SERVERS:
            report.fail("R4-mutation-shape", cid, f"mutation.target names unknown MCP server {name!r} (know: {sorted(MCP_SERVERS)})")
        if kind == "a2a" and name not in A2A_PEERS:
            report.fail("R4-mutation-shape", cid, f"mutation.target names unknown A2A peer {name!r} (know: {sorted(A2A_PEERS)})")
        trigger = c.get("trigger")
        if not isinstance(trigger, Mapping) or trigger.get("on") != "call_index":
            report.fail("R4-mutation-shape", cid, f"trigger {trigger!r} must be {{'on': 'call_index', ...}}")
        if not isinstance(c.get("defense_event"), str) or not c.get("defense_event"):
            report.fail("R4-mutation-shape", cid, "attack card has no non-empty 'defense_event'")


# ---------------------------------------------------------------------------
# R5 — every replica_flip card names a path_id in the measured drift set
# ---------------------------------------------------------------------------


def check_replica_flip_drift_set(attacks: Sequence[dict], world: World, report: ValidationReport) -> None:
    for c in attacks:
        cid = c.get("id")
        cls = c.get("class")
        mutation = c.get("mutation") or {}
        op = mutation.get("op")
        value = mutation.get("value")
        path_id = value.get("path_id") if isinstance(value, Mapping) else None

        # The hard, named rule: every replica_flip card, specifically.
        if cls == "replica_flip":
            if not path_id:
                report.fail("R5-replica-flip-drift-set", cid, "class=replica_flip but mutation.value has no 'path_id'")
                continue
            if not world.drifts(path_id):
                report.fail(
                    "R5-replica-flip-drift-set", cid,
                    f"path_id {path_id!r} is not in the measured drift set — this card would find "
                    f"nothing on a real duel. Pick a path_id from the drifting set instead.",
                )
        # Same mechanical requirement applies to ANY swap_replica card (e.g. class=drift),
        # not only ones literally named replica_flip — RULES.md names replica_flip because
        # that is this deck's own pairing (CONTRACTS section 8: op<->class is not 1:1), but a
        # swap_replica op against a non-drifting path_id is equally a dud regardless of which
        # class the card declares it under. Reported as its own rule so a replica_flip-specific
        # tool run never conflates the two.
        elif op == "swap_replica" and path_id:
            if not world.drifts(path_id):
                report.fail(
                    "R5b-swap-replica-drift-set", cid,
                    f"op=swap_replica names path_id {path_id!r}, which is not in the measured "
                    f"drift set — this card would find nothing on a real duel.",
                )


# ---------------------------------------------------------------------------
# R6 — every anchor an ask names as INPUT resolves in the world
# ---------------------------------------------------------------------------


def _check_anchor_resolves(anchor_str: object, world: World, report: ValidationReport, rule: str, cid: str | None, field_name: str) -> None:
    if not isinstance(anchor_str, str) or not anchor_str:
        report.fail(rule, cid, f"ask.{field_name} must be a non-empty Anchor string")
        return
    try:
        Anchor.parse(anchor_str)
    except AnchorSyntaxError as exc:
        report.fail(rule, cid, f"ask.{field_name}={anchor_str!r} does not parse as an Anchor: {exc}")
        return
    if world.page(anchor_str) is None:
        report.fail(rule, cid, f"ask.{field_name}={anchor_str!r} does not resolve in the world (a naive/typo'd anchor)")


def check_ask_anchors_resolvable(cards: Sequence[dict], world: World, report: ValidationReport) -> None:
    for c in cards:
        cid = c.get("id")
        ask = c.get("ask")
        if not isinstance(ask, Mapping):
            report.fail("R6-ask-shape", cid, "card has no 'ask' block")
            continue
        ask_type = ask.get("type")
        if ask_type not in _ASK_TYPES:
            report.fail("R6-ask-shape", cid, f"ask.type {ask_type!r} is not one of the eight closed ask types {sorted(_ASK_TYPES)}")
            continue
        require = ask.get("require")
        if not isinstance(require, list) or not require:
            report.fail("R6-ask-shape", cid, "ask.require must be a non-empty list of answer field names")

        for field_name in _ASK_ANCHOR_INPUT_FIELDS.get(ask_type, ()):
            if field_name in ask:
                _check_anchor_resolves(ask[field_name], world, report, "R6-anchor-resolves", cid, field_name)

        if ask_type == "current_version_of":
            path_id = ask.get("path_id")
            if not isinstance(path_id, str) or not path_id:
                report.fail("R6-anchor-resolves", cid, "ask.path_id must be a non-empty string")
            elif world.drift_info(path_id) is None:
                report.fail("R6-anchor-resolves", cid, f"ask.path_id={path_id!r} has no measured drift.json entry at all")

        if ask_type == "define_term":
            term = ask.get("term")
            if not isinstance(term, str) or not term.strip():
                report.fail("R6-anchor-resolves", cid, "ask.term must be a non-empty string")
            elif not world.terms(term):
                world_id = world.manifest.get("world_id", "")
                hint = " — try --world <a real export>" if "fixture" in world_id else ""
                report.warn(
                    "R6-term-lookup", cid,
                    f"ask.term={term!r} has no entry in this world's terms.json (world_id={world_id!r}{hint})",
                )


# ---------------------------------------------------------------------------
# R7 — lineup.json: exactly 10, distinct, all present in the deck
# ---------------------------------------------------------------------------


def check_lineup(deck: Mapping, lineup: Mapping, report: ValidationReport) -> None:
    order = lineup.get("order")
    if not isinstance(order, list):
        report.fail("R7-lineup", None, "lineup.json has no 'order' list")
        return
    if len(order) != _LINEUP_SIZE:
        report.fail("R7-lineup", None, f"lineup has {len(order)} entries, need exactly {_LINEUP_SIZE}")
    if len(set(order)) != len(order):
        report.fail("R7-lineup", None, "lineup.order contains a repeated card id")
    deck_ids = {c.get("id") for c in (deck.get("cards") or [])}
    for cid in order:
        if cid not in deck_ids:
            report.fail("R7-lineup", cid, "lineup names a card id not present in deck.json")


# ---------------------------------------------------------------------------
# R8 — lethality band (see module docstring for exactly what is and is not checked here)
# ---------------------------------------------------------------------------

_ROOKIE_TARGET_FIELD = {
    "swap_replica": "path_id", "shadow_server": "decoy_path_id", "poison_row": "note_anchor",
}


def _rookie_falls(card: Mapping, world: World, report: ValidationReport) -> None:
    """"Falls to rookie" — a forward-everything gateway (FINAL-PLAN.md section 9's own
    definition of rookie). Mechanically: does the op's own target actually resolve in the
    world, making it a real, non-degenerate poisoning target?"""
    cid = card.get("id")
    mutation = card["mutation"]
    op = mutation["op"]
    value = mutation.get("value")

    if op in _ROOKIE_TARGET_FIELD:
        field_name = _ROOKIE_TARGET_FIELD[op]
        target = value.get(field_name) if isinstance(value, Mapping) else None
        if not target:
            report.fail("R8-rookie-falls", cid, f"mutation.value has no {field_name!r} for op={op!r}")
            return
        if op == "poison_row":
            page = world.page(target)
            if page is None or page.ns != "Note":
                report.fail("R8-rookie-falls", cid, f"note_anchor {target!r} does not resolve to a real Note: page")
        else:  # swap_replica / shadow_server: a real path_id must have at least one resolvable Frame
            probe = f"Frame:{target}/w/001"
            if world.page(probe) is None:
                probe_c = f"Frame:{target}/c/001"
                if world.page(probe_c) is None:
                    report.fail(
                        "R8-rookie-falls", cid,
                        f"path_id {target!r} has no resolvable Frame:.../001 in either replica — "
                        f"nothing for op={op!r} to poison",
                    )
    elif op == "inflate_catalog":
        n = value.get("extra_rows") if isinstance(value, Mapping) else None
        if not isinstance(n, int) or isinstance(n, bool) or n <= 0:
            report.fail("R8-rookie-falls", cid, "mutation.value.extra_rows must be a positive int")
    elif op == "drop_header":
        headers = value.get("headers") if isinstance(value, Mapping) else None
        if not headers or not set(h.lower() for h in headers) & {"if-match", "idempotency-key"}:
            report.fail("R8-rookie-falls", cid, "mutation.value.headers must name at least one write-precondition header")
    elif op == "corrupt_peer_answer":
        if not isinstance(value, Mapping) or not value:
            report.fail("R8-rookie-falls", cid, "mutation.value must be a non-empty field-override dict for op=corrupt_peer_answer")
    elif op in ("replace_act", "replace_aud"):
        target_server = mutation["target"].split(":", 1)[1]
        aud = f"a2a:{target_server}"
        try:
            if op == "replace_act":
                mcp_a2a.mint_delegation(value, aud, 3)
            else:
                mcp_a2a.mint_delegation("learner:probe", value, 3)
        except (ValueError, TypeError) as exc:
            report.fail("R8-rookie-falls", cid, f"mutation.value {value!r} is not a legal act/aud identity: {exc}")
    elif op == "forge_card":
        peer = mutation["target"].split(":", 1)[1]
        base = mcp_a2a.AGENT_CARDS.get(peer)
        if base is None:
            report.fail("R8-rookie-falls", cid, f"no Agent Card known for peer {peer!r}")
        else:
            extra_skill = value.get("add_skill") if isinstance(value, Mapping) else None
            if not isinstance(extra_skill, str) or not extra_skill:
                report.fail("R8-rookie-falls", cid, "mutation.value.add_skill must be a non-empty skill name for op=forge_card")


def _held_in_principle(card: Mapping, report: ValidationReport) -> None:
    """"Held by adversary" — see module docstring: this checks only that a correct policy
    (deny the command carrying the mutation's target) structurally prevents the violation, per
    CONTRACTS section 6.4's own `enforcement_failure` predicate
    (`applied and trigger_matched and verdict != "deny"`). It does NOT run the actual
    `bots/adversary/` gateway in a scored duel."""
    cid = card.get("id")
    defense_event = card.get("defense_event")
    # The referee's own rule collapses to "verdict == deny defeats it" for every card whose
    # defense_event follows CONTRACTS section 8's own worked shape ("gateway.denied"). A card
    # naming a different defense_event is not thereby illegal (the rubric never mandates the
    # exact string), but this proxy cannot vouch for it, so it is a WARN, not a FAIL.
    if defense_event != "gateway.denied":
        report.warn(
            "R8-held-in-principle", cid,
            f"defense_event={defense_event!r} is not the 'gateway.denied' shape this proxy checks "
            f"against the referee's own enforcement_failure predicate — cannot confirm 'held in "
            f"principle' for this card; review it by hand.",
        )
        return
    # verdict == "deny" => enforcement_failure's own "if verdict == deny: continue" always holds,
    # for every op/target this module recognises (R4/R8-rookie-falls already reject anything it
    # does not). Nothing further to compute; this is the tautology the module docstring names.


def check_lethality_band(attacks: Sequence[dict], world: World, report: ValidationReport) -> None:
    report.warn(
        "R8-lethality-band", None,
        "offline checks use the real student world and local mutation engine, but do not "
        "certify a scored duel: spar scripts tool results and ANSWER, and curriculum-analyst "
        "needs instructor truth. The FAIL-level checks below are mechanical proxies. "
        "Use `make spar BOT=rookie AS=attacker` and `make spar BOT=adversary AS=attacker` "
        "for local practice; only the instructor Arena can confirm the lethality band.",
    )
    for c in attacks:
        _rookie_falls(c, world, report)
        _held_in_principle(c, report)


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


def validate(deck: Mapping, lineup: Mapping, world: World) -> ValidationReport:
    report = ValidationReport()
    cards = check_card_counts(deck, report)
    attacks = [c for c in cards if c.get("kind") == "attack"]
    blanks = [c for c in cards if c.get("kind") == "blank"]

    check_layer_balance(attacks, report)
    check_distinct_classes(attacks, report)
    check_mutation_shape(attacks, report)
    check_replica_flip_drift_set(attacks, world, report)
    check_ask_anchors_resolvable(attacks + blanks, world, report)
    check_lineup(deck, lineup, report)
    check_lethality_band(attacks, world, report)
    return report


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("deck", nargs="?", default="deck/deck.json", type=Path)
    parser.add_argument("lineup", nargs="?", default="deck/lineup.json", type=Path)
    parser.add_argument("--world", default=None, help="path to a real exported world/ directory")
    args = parser.parse_args(argv)

    deck_path = args.deck if args.deck.is_absolute() else _REPO_ROOT / args.deck
    lineup_path = args.lineup if args.lineup.is_absolute() else _REPO_ROOT / args.lineup

    if not deck_path.is_file():
        print(f"FAIL  cannot read deck at {deck_path}")
        return 1
    if not lineup_path.is_file():
        print(f"FAIL  cannot read lineup at {lineup_path}")
        return 1

    deck = load_deck(deck_path)
    lineup = load_lineup(lineup_path)
    world, world_label = resolve_world(args.world)
    print(f"world: {world_label}")
    print()

    report = validate(deck, lineup, world)
    print(report.render())
    return 0 if report.ok() else 1


if __name__ == "__main__":
    raise SystemExit(main())
