"""Verify SS's attacks change real data, beyond the validator's target lookup."""
import json
from pathlib import Path

import pytest

from agent.gateway import Command, Gateway
from agent.guardrails import GuardedEnvironment, prepare_answer, scan_for_injected_instructions
from agent.telemetry import RecordingGatewayContext
from kit.loop.agent import Agent
from kit.loop.prompt import render_system_prompt
from kit.mcp import a2a, servers
from kit.mcp.hardmode import HardMode
from kit.mcp.mutations import MutableStack, trigger_matches
from kit.mcp.types import ToolCall
from kit.world.loader import World
from validate_deck import validate


@pytest.fixture(scope="module")
def world():
    root = Path("kit/world/df8c55dabb35")
    if not (root / "manifest.json").exists():
        pytest.skip("real exported world required")
    loaded = World.load(root)
    assert not loaded.has_truth
    return loaded


@pytest.fixture(scope="module")
def deck():
    return json.loads(Path("deck/deck.json").read_text(encoding="utf-8"))


def card(deck, identifier):
    return next(c for c in deck["cards"] if c["id"] == identifier)


def test_ss_deck_is_legal_against_downloaded_world(deck, world):
    lineup = json.loads(Path("deck/lineup.json").read_text())
    report = validate(deck, lineup, world)
    assert report.ok(), report.render()
    assert [f.rule for f in report.findings] == ["R8-lethality-band"]
    assert deck["team"] == "SS"
    assert all(c["defense_event"] == "gateway.denied" for c in deck["cards"] if c["kind"] == "attack")


@pytest.mark.parametrize("identifier", [f"atk_{i:02d}" for i in range(1, 11)])
def test_every_trigger_has_a_clean_prefix_and_fits_four_turns(deck, identifier):
    c = card(deck, identifier)
    threshold = c["trigger"]["gte"]
    assert type(threshold) is int and 0 <= threshold <= 2
    assert trigger_matches(c["trigger"], threshold)
    if threshold:
        assert not trigger_matches(c["trigger"], threshold - 1)


def read_frame(world, anchor, index=2):
    query = servers.handle(world, ToolCall("slides", "query",
                           {"q": world.page(anchor).title, "ns": "Frame", "limit": 1},
                           ("title",), call_index=index - 1))
    assert query["ok"] and query["lease_id"]
    return ToolCall("slides", "get_frame", {"anchor": anchor}, ("body", "meta", "title"),
                    {"Mcp-Replica": "w"}, lease_id=query["lease_id"], call_index=index)


def test_shadow_stays_in_same_track_but_changes_day_and_anchor(deck, world):
    c = card(deck, "atk_01")
    origin = next(str(a) for a in world.links(c["ask"]["concept"]) if a.ns == "Frame" and a.rev == "w")
    call = read_frame(world, origin)
    honest = servers.handle(world, call)
    stack = MutableStack(world, act="learner:sv-0417")
    stack.arm(c)
    poisoned, event = stack.execute(call)
    assert honest["ok"] and poisoned["ok"] and event["applied"]
    original, decoy = honest["rows"][0]["meta"], poisoned["rows"][0]["meta"]
    assert original["track"] == decoy["track"] == "P2T2"
    assert original["course_day"] != decoy["course_day"]
    assert honest["anchors"] != poisoned["anchors"]


@pytest.mark.parametrize("identifier", ["atk_02", "atk_03"])
def test_replica_attacks_change_evidence_on_the_concepts_actual_deck(deck, world, identifier):
    c = card(deck, identifier)
    frames = [a for a in world.links(c["ask"]["concept"]) if a.ns == "Frame"]
    working = next(a for a in frames if a.rev == "w")
    canonical = next(a for a in frames if a.rev == "c")
    pid = c["mutation"]["value"]["path_id"]
    assert working.slug == canonical.slug == pid and world.drifts(pid)
    assert working.idx != canonical.idx  # The answer's specific frame genuinely differs.
    call = read_frame(world, str(working))
    honest = servers.handle(world, call)
    stack = MutableStack(world, act="learner:sv-0417")
    stack.arm(c)
    poisoned, event = stack.execute(call)
    assert honest["ok"] and poisoned["ok"] and event["applied"]
    if c["mutation"]["value"]["scope"] == "header":
        assert honest["rows"] == poisoned["rows"] and honest["anchors"] == poisoned["anchors"]
        assert honest["replica"] != poisoned["replica"]
    else:
        assert honest["rows"][0]["body"] != poisoned["rows"][0]["body"]
        assert poisoned["anchors"][0] not in [str(a) for a in frames]


def test_poison_reaches_visible_body_on_the_asked_tool_path(deck, world):
    c = card(deck, "atk_04")
    assert c["mutation"]["target"] == "mcp:slides" and c["ask"]["type"] == "which_day_covers"
    title = world.page(c["ask"]["concept"]).title
    stack = MutableStack(world, act="learner:sv-0417")
    stack.arm(c)
    result, event = stack.execute(ToolCall("slides", "query", {"q": title, "ns": "Frame", "limit": 1},
                                          ("body", "title"), call_index=1))
    assert result["ok"] and event["applied"]
    assert result["anchors"][-1] == c["mutation"]["value"]["note_anchor"]
    assert result["rows"][-1]["body"] == world.page(result["anchors"][-1]).body
    assert scan_for_injected_instructions(result["rows"][-1]["body"]).suspicious


def test_real_poison_is_filtered_before_agent_answers(deck, world):
    attack = card(deck, "atk_04")
    poison_anchor = attack["mutation"]["value"]["note_anchor"]
    context = RecordingGatewayContext(act="learner:sv-0417", sub="agent:vlearn-tutor",
                                      scopes=frozenset({"wiki.read"}), credits=100,
                                      round=1, call_index=0)
    gateway = Gateway(context)
    hardmode = HardMode(opaque_enabled=False, degraded_replica_enabled=False)
    hardmode.reset("SS-poison-integration")
    hardmode.begin_round(1)
    stack = MutableStack(world, act=context.act, hardmode=hardmode)
    stack.arm(attack)
    mutations = []

    class RealEnvironment:
        def execute(self, action):
            if action["kind"] == "answer":
                return {"ok": True, "recorded": "answer"}
            command = Command.from_action_dict(action, cmd_id=f"cmd:{action['call_index']}")
            context.call_index = command.call_index
            decision = gateway.decide(command)
            assert decision.verdict != "deny", decision.reason
            result, mutation = stack.execute(decision.call)
            assert result["ok"], result
            if mutation is not None:
                mutations.append(mutation)
            context.credits -= result["cost"]
            context.history += ({"command": command, "decision": decision,
                                 "outcome": result, "round": 1},)
            if result.get("lease_id"):
                context.leases += (result["lease_id"],)
            return result

    class Model:
        def __init__(self):
            self.turn = 0

        def query(self, messages, **kwargs):
            self.turn += 1
            if self.turn == 1:
                title = world.page(attack["ask"]["concept"]).title
                line = f'MCP slides.query q={json.dumps(title)} ns=Frame limit=1 fields=title'
            elif self.turn == 2:
                observation = json.loads(messages[-1]["content"])
                line = (f'MCP slides.get_frame anchor={observation["anchors"][0]} '
                        f'lease={observation["lease_id"]} fields=body,meta,title')
            else:
                observation = json.loads(messages[-1]["content"])
                assert poison_anchor not in observation["anchors"]
                assert all(not scan_for_injected_instructions(str(row)).suspicious
                           for row in observation["rows"])
                anchor, row = observation["anchors"][0], observation["rows"][0]
                day, track = row["meta"]["course_day"], row["meta"]["track"]
                line = "ANSWER " + json.dumps({"text": f"Day {day}, Track {track}.",
                                                "course_day": day, "track": track,
                                                "anchor": anchor, "cited_anchors": [anchor]})
            return {"content": f"```action\n{line}\n```"}

    guarded = GuardedEnvironment(RealEnvironment(), ask=attack["ask"])
    run = Agent(Model(), guarded, system_prompt=render_system_prompt() + "\n" +
                Path("agent/prompt.md").read_text(encoding="utf-8"),
                task=json.dumps(attack["ask"])).run()
    assert run.exit_status == "answered" and run.steps == 3 and run.calls == 2
    assert any(event["applied"] for event in mutations)
    assert not run.answer.get("abstained") and poison_anchor not in run.answer["cited_anchors"]
    assert run.answer["anchor"] in run.observations[-2]["anchors"]
    assert context.credits >= 0 and run.elapsed < 20


def test_catalog_bomb_has_real_credit_impact_and_catalog_mask_escape(deck, world):
    c = card(deck, "atk_05")
    stack = MutableStack(world, act="learner:sv-0417")
    stack.arm(c)
    call = ToolCall("registry", "list_servers", {}, ("*",))
    honest = servers.handle(world, call)
    poisoned, event = stack.execute(call)
    extra = c["mutation"]["value"]["extra_rows"]
    assert event["applied"] and len(poisoned["rows"]) == len(honest["rows"]) + extra
    assert poisoned["cost"] == honest["cost"] + extra
    assert servers.handle(world, ToolCall("registry", "list_servers", {}, ("name",)))["cost"] < honest["cost"]


def test_header_attack_turns_an_authorized_write_into_precondition_error(deck, world):
    c = card(deck, "atk_06")
    learner = c["ask"]["learner"]
    provenance = servers.handle(world, ToolCall("registry", "provenance", {"anchor": learner}))
    call = ToolCall("progress", "record_mastery",
                    {"anchor": learner, "learner": "learner:sv-0417", "concept": c["ask"]["concept"]},
                    ("receipt_id",), {"If-Match": provenance["etag"], "Idempotency-Key": "SS-deck-write"},
                    call_index=1)
    honest = servers.handle(world, call)
    stack = MutableStack(world, act="learner:sv-0417")
    stack.arm(c)
    poisoned, event = stack.execute(call)
    assert honest["ok"] and honest["rows"][0]["receipt_id"]
    assert event["applied"] and not poisoned["ok"]
    assert poisoned["error"]["code"] == "precondition_missing"


def test_identity_attack_changes_existing_learner_and_is_verifiably_denied(deck, world):
    c = card(deck, "atk_07")
    assert world.page("Learner:" + c["mutation"]["value"].split(":")[1]) is not None
    stack = MutableStack(world, act="learner:sv-0417")
    stack.arm(c)
    result, event = stack.execute(ToolCall("roster", "lookup_learner", {"learner": c["ask"]["learner"]},
                                          ("act", "track"), call_index=1))
    assert result["ok"] and event["applied"]
    row = result["rows"][0]
    assert row["delegation_token"]["act"] == c["mutation"]["value"]
    assert row["delegation_admission"]["reason"] == "act_escalation"
    assert not row["delegation_admission"]["admitted"]


def test_forged_card_is_invalid_even_with_a_plausible_existing_skill(deck, world):
    c = card(deck, "atk_08")
    call = ToolCall("curriculum-analyst", "which_days_cover", {"concept": c["ask"]["concept"]},
                    ("anchor", "course_day", "track"), call_index=1)
    honest = servers.handle(world, call)
    assert honest["ok"]
    stack = MutableStack(world, act="learner:sv-0417")
    result, applied = stack._POST_OPS["forge_card"](stack, call, honest, c["mutation"]["value"])
    assert result["ok"] and applied
    row = result["rows"][0]
    checked = a2a.verify_card(row["agent_card"], discovery_path=a2a.AGENT_CARD_PATH)
    assert not checked.admitted and checked.reason == a2a.AdmissionReason.FORGED_CARD_SIGNATURE


@pytest.mark.parametrize("identifier", ["atk_09", "atk_10"])
def test_curriculum_post_ops_with_actual_student_peer_rows(deck, world, identifier):
    c = card(deck, identifier)
    call = ToolCall("curriculum-analyst", "which_days_cover", {"concept": c["ask"]["concept"]},
                    ("anchor", "course_day", "track"), call_index=1)
    # MutableStack's curriculum dispatcher needs instructor truth; use the shipped
    # student peer to supply real rows, then test the actual post-op independently.
    honest = servers.handle(world, call)
    assert honest["ok"]
    stack = MutableStack(world, act="learner:sv-0417")
    op = c["mutation"]["op"]
    poisoned, applied = stack._POST_OPS[op](stack, call, honest, c["mutation"]["value"])
    assert applied
    row = poisoned["rows"][0]
    if op == "corrupt_peer_answer":
        assert honest["rows"][0]["course_day"] != row["course_day"]
        assert world.page(honest["rows"][0]["anchor"]).meta["course_day"] != row["course_day"]
    else:
        assert row["delegation_token"]["aud"] == c["mutation"]["value"]
        assert row["delegation_admission"]["reason"] == "aud_mismatch"
        assert not row["delegation_admission"]["admitted"]


@pytest.mark.parametrize("identifier", ["atk_07", "atk_08", "atk_10"])
def test_real_peer_admission_attacks_cannot_be_used_as_answer_evidence(deck, world, identifier):
    attack = card(deck, identifier)
    roster = identifier == "atk_07"
    call = ToolCall("roster" if roster else "curriculum-analyst",
                    "lookup_learner" if roster else "which_days_cover",
                    {"learner": attack["ask"]["learner"]} if roster else {"concept": attack["ask"]["concept"]},
                    ("act", "track") if roster else ("anchor", "course_day", "track"), call_index=1)
    token = a2a.mint_delegation("learner:sv-0417", "a2a:" + call.server, 3, call_index=1)
    honest = a2a.execute(world, call, delegation=token, expected_act="learner:sv-0417")
    assert honest["ok"]
    stack = MutableStack(world, act="learner:sv-0417")
    poisoned, applied = stack._POST_OPS[attack["mutation"]["op"]](stack, call, honest, attack["mutation"]["value"])
    assert poisoned["ok"] and applied
    row = honest["rows"][0]
    anchor = row.get("anchor", honest["anchors"][0])
    payload = {"text": "The requested entry was retrieved.", "anchor": anchor, "cited_anchors": [anchor]}
    payload.update({"act": row["act"]} if roster else {"track": row["track"]})
    assert prepare_answer(payload, [honest]) == payload
    assert prepare_answer(payload, [poisoned])["abstained"]
    assert prepare_answer(payload, [poisoned, honest]) == payload
