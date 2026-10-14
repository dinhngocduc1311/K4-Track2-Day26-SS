"""Security and protocol checks for SS's four gateway jobs."""
from dataclasses import replace

import pytest

from agent.gateway import Command, Gateway
from agent.telemetry import RecordingGatewayContext
from kit.mcp.a2a import AGENT_CARDS, mint_delegation
from kit.mcp.servers import handle
from kit.mcp.specs import cost
from kit.mcp.types import ToolCall
from kit.world.fixture import FIXTURE_PATH_IDS, build_fixture_world
from kit.world.loader import World

FRAME = "Frame:d8f95a7b/w/041"
LEARNER = "Learner:sv-0417"


def context(**overrides):
    values = dict(act="learner:sv-0417", sub="agent:vlearn-tutor",
                  scopes=frozenset({"wiki.read", "wiki.write:progress"}),
                  credits=100, round=1, call_index=0)
    return RecordingGatewayContext(**(values | overrides))


def command(server="glossary", tool="define", **overrides):
    values = dict(cmd_id="cmd:0001", kind="mcp", raw=f"{server}.{tool}",
                  server=server, tool=tool, args={"term": "agent card"},
                  fields=(), headers={}, lease_id=None, call_index=1)
    return Command(**(values | overrides))


def provenance(etag="etag-1", round=1, anchor=LEARNER, **extra):
    return {"command": command("registry", "provenance", args={"anchor": anchor}),
            "outcome": {"ok": True, "etag": etag, "partial": False, "anchors": [anchor], "rows": [], **extra}, "round": round}


def write(**overrides):
    return command("progress", "record_mastery", args={"anchor": LEARNER, "learner": "learner:sv-0417", "concept": "Concept:stategraph/w/055"},
                   headers={"If-Match": "etag-1", "Idempotency-Key": "write-1"}, **overrides)


def test_clean_read_forwards_without_mutating_input():
    cmd = command()
    before = cmd.to_dict()
    result = Gateway(context()).decide(cmd)
    assert result.verdict == "forward"
    assert result.call.to_dict()["args"] == cmd.args
    assert cmd.to_dict() == before


@pytest.mark.parametrize("code,attempts,allowed", [
    ("bad_request", 1, False), ("not_found", 1, False),
    ("unauthorized", 1, False), ("rate_limited", 1, False),
    ("unavailable", 1, True), ("unavailable", 2, False),
])
def test_identical_failed_read_obeys_retry_tolerance(code, attempts, allowed):
    cmd = command()
    history = tuple({"command": replace(cmd, call_index=i), "round": 1,
                     "outcome": {"ok": False, "error": {"code": code}}}
                    for i in range(attempts))
    assert (Gateway(context(history=history)).decide(cmd).verdict != "deny") is allowed
    changed = replace(cmd, args={"term": "delegation"})
    assert Gateway(context(history=history)).decide(changed).verdict != "deny"
    assert Gateway(context(history=history, round=2)).decide(cmd).verdict != "deny"


def test_retry_uses_effective_rewritten_call_and_accepts_recovery():
    cmd = command("slides", "search", args={"q": "MCP"}, fields=("title",))
    decision = Gateway(context()).decide(cmd)
    failed = {"command": cmd, "decision": decision, "round": 1,
              "outcome": {"ok": False, "error": {"code": "bad_request"}}}
    assert Gateway(context(history=(failed,))).decide(cmd).verdict == "deny"
    recovered = failed | {"outcome": {"ok": True}}
    assert Gateway(context(history=(failed, recovered))).decide(cmd).verdict != "deny"


@pytest.mark.parametrize("args,headers", [({"route": "c"}, {}), ({}, {"x-server-fingerprint": "unvouched"}),
                                         ({}, {"If-Match": "a", "if-match": "b"})])
def test_untrusted_route_identity_and_ambiguous_headers_are_denied(args, headers):
    assert Gateway(context()).decide(command(args=args, headers=headers)).verdict == "deny"


def test_replica_uses_real_provenance_envelope_instead_of_model_header(tmp_path):
    world = World.load(build_fixture_world(tmp_path / "world", include_truth=False))
    anchor = f"Frame:{FIXTURE_PATH_IDS['alpha']}/c/001"
    result_from_server = handle(world, ToolCall("registry", "provenance", {"anchor": anchor}))
    assert result_from_server["replica"] == "c"
    assert "fresher" not in result_from_server["rows"][0]
    ctx = context(history=(provenance(anchor=anchor, **result_from_server),))
    cmd = command("slides", "query", args={"q": "StateGraph", "anchor": anchor}, headers={"Mcp-Replica": "w"})
    result = Gateway(ctx).decide(cmd)
    assert result.verdict == "rewrite" and result.call.headers["mcp-replica"] == "c"
    assert cmd.headers == {"Mcp-Replica": "w"}


@pytest.mark.parametrize("untrusted", [
    {"ok": True, "replica": "c", "partial": True, "anchors": [FRAME]},
    {"ok": True, "replica": "c", "partial": False, "anchors": ["Frame:deadbeef/c/001"]},
    {"ok": True, "replica": "c", "partial": False, "anchors": [FRAME]},
    {"ok": True, "replica": "c", "partial": False, "anchors": None},
])
def test_replica_does_not_trust_incomplete_mismatched_or_unverified_history(untrusted):
    ctx = context(history=(provenance(anchor=FRAME, **untrusted),))
    cmd = command("slides", "query", args={"q": "StateGraph", "anchor": FRAME}, headers={"mcp-replica": "c"})
    assert Gateway(ctx).decide(cmd).call.headers["mcp-replica"] == "w"


@pytest.mark.parametrize("lease,live", [(None, ()), ("old", ()), ("old", ("new",))])
def test_missing_or_nonlive_lease_is_denied(lease, live):
    cmd = command("slides", "get_frame", args={"anchor": FRAME}, lease_id=lease)
    assert Gateway(context(leases=live)).decide(cmd).verdict == "deny"


@pytest.mark.parametrize("index,round,allowed", [(4, 1, True), (5, 1, False), (1, 1, False), (2, 0, False)])
def test_lease_three_call_boundary_and_round_isolation(index, round, allowed):
    history = ({"command": command("slides", "query", call_index=1),
                "outcome": {"ok": True, "lease_id": "lease-1"}, "round": round},)
    cmd = command("slides", "get_frame", args={"anchor": FRAME}, lease_id="lease-1", call_index=index)
    result = Gateway(context(leases=("lease-1",), history=history)).decide(cmd)
    assert (result.verdict != "deny") is allowed
    if allowed:
        assert result.call.args["anchor"] == FRAME
        assert result.call.headers["mcp-replica"] == "w"


@pytest.mark.parametrize("history", [(), (provenance("other"),), (provenance(round=0),),
                                      (provenance(partial=True),), (provenance(ok=False),)])
def test_write_requires_complete_fresh_matching_provenance(history):
    assert Gateway(context(history=history)).decide(write()).verdict == "deny"


def test_malformed_provenance_rows_are_denied_without_integrity_exception():
    assert Gateway(context(history=(provenance(etag=None, rows=None),))).decide(write()).verdict == "deny"


@pytest.mark.parametrize("change", [{"rows": 42}, {"rows": {}}, {"rows": ["invalid"]}, {"anchors": None},
    {"anchors": ["Learner:sv-0392"]}, {"partial": None}, {"partial": 0}, {"etag": []}])
def test_write_provenance_requires_valid_shape_and_the_actual_target(change):
    ctx = context(history=(provenance(**change),))
    assert Gateway(ctx).decide(write()).verdict == "deny"
    ctx.history += (provenance(),)
    assert Gateway(ctx).decide(write()).verdict != "deny"


def test_same_learner_write_with_scope_and_etag_is_admitted():
    ctx = context(history=(provenance(),))
    result = Gateway(ctx).decide(write())
    assert result.verdict == "rewrite"
    assert result.call.headers == {"if-match": "etag-1", "idempotency-key": "write-1"}


@pytest.mark.parametrize("scope,target", [(frozenset({"wiki.read"}), "learner:sv-0417"),
                                        (frozenset({"wiki.read", "wiki.write:progress"}), "Learner:sv-0392")])
def test_privileged_sub_cannot_override_scope_or_learner(scope, target):
    ctx = context(scopes=scope, history=(provenance(),))
    cmd = replace(write(), args=write().args | {"learner": target})
    assert Gateway(ctx).decide(cmd).verdict == "deny"


def test_write_cannot_hide_cross_learner_anchor_behind_own_learner_argument():
    other = "Learner:sv-0392"
    ctx = context(history=(provenance(anchor=other),))
    cmd = replace(write(), args=write().args | {"anchor": other})
    assert Gateway(ctx).decide(cmd).verdict == "deny"


def test_conflict_requires_reread_and_replay_key_is_never_reused():
    attempted = {"command": write(), "outcome": {"ok": False, "error": {"code": "conflict"}}, "round": 1}
    fresh_key = replace(write(), headers={"if-match": "etag-1", "idempotency-key": "write-2"})
    ctx = context(history=(provenance(), attempted))
    assert Gateway(ctx).decide(fresh_key).verdict == "deny"
    ctx.history += (provenance(),)
    assert Gateway(ctx).decide(fresh_key).verdict != "deny"
    assert Gateway(ctx).decide(write()).verdict == "deny"


def peer_command(token=None, **overrides):
    args = {"concept": "Concept:stategraph/w/055", "learner": "learner:sv-0417"}
    if token is not None:
        args["delegation_token"] = token
    return command("curriculum-analyst", "which_days_cover", kind="a2a", args=args, **overrides)


def admitted_gateway(ctx=None):
    gw = Gateway(ctx or context())
    gw.note_card("curriculum-analyst", AGENT_CARDS["curriculum-analyst"].to_dict())
    return gw


def test_declared_peer_with_valid_signed_delegation_is_admitted():
    token = mint_delegation("learner:sv-0417", "a2a:curriculum-analyst", 3).to_dict()
    assert admitted_gateway().decide(peer_command(token)).verdict != "deny"


def test_conflicting_header_and_argument_delegation_cannot_bypass_verification():
    token = mint_delegation("learner:sv-0417", "a2a:curriculum-analyst", 3).to_dict()
    assert admitted_gateway().decide(peer_command(token, headers={"delegation-token": token})).verdict != "deny"
    forged = token | {"act": "learner:sv-0392"}
    assert admitted_gateway().decide(peer_command(forged, headers={"delegation-token": token})).verdict == "deny"


@pytest.mark.parametrize("signature", ["é" * 64, "0" * 63, None, ["invalid"]])
def test_malformed_signatures_are_denied_without_gateway_exception(signature):
    token = mint_delegation("learner:sv-0417", "a2a:curriculum-analyst", 3).to_dict()
    assert admitted_gateway().decide(peer_command(token | {"signature": signature})).verdict == "deny"
    card = AGENT_CARDS["curriculum-analyst"].to_dict() | {"signature": signature}
    cmd = peer_command()
    assert admitted_gateway().decide(replace(cmd, args=cmd.args | {"agent_card": card})).verdict == "deny"


@pytest.mark.parametrize("skill", ["delete_all_learners", "role_of", None, {}, False])
def test_explicit_undeclared_or_wrong_peer_skill_is_denied(skill):
    cmd = peer_command()
    assert admitted_gateway().decide(replace(cmd, args=cmd.args | {"skill": skill})).verdict == "deny"
    assert admitted_gateway().decide(replace(cmd, args=cmd.args | {"skill": "which_days_cover"})).verdict != "deny"


@pytest.mark.parametrize("act,aud,ttl,minted,index", [
    ("learner:sv-0392", "a2a:curriculum-analyst", 3, 0, 1),
    ("learner:sv-0417", "a2a:roster", 3, 0, 1),
    ("learner:sv-0417", "a2a:curriculum-analyst", 1, 0, 2),
    ("learner:sv-0417", "a2a:curriculum-analyst", 3, 4, 1),
])
def test_signed_but_wrong_act_aud_expired_or_future_tokens_denied(act, aud, ttl, minted, index):
    token = mint_delegation(act, aud, ttl, call_index=minted).to_dict()
    assert admitted_gateway().decide(peer_command(token, call_index=index)).verdict == "deny"


def test_forged_token_and_replayed_token_are_denied():
    token = mint_delegation("learner:sv-0417", "a2a:curriculum-analyst", 3).to_dict()
    assert admitted_gateway().decide(peer_command(token | {"signature": "0" * 64})).verdict == "deny"
    gw = admitted_gateway(context(round=10))
    assert gw.decide(peer_command(token)).verdict != "deny"
    assert gw.decide(peer_command(token)).verdict == "deny"


@pytest.mark.parametrize("token", [None, {}, [], "", False])
def test_explicit_malformed_token_is_not_treated_as_absent(token):
    cmd = replace(peer_command(), args={"delegation_token": token})
    assert Gateway(context()).decide(cmd).verdict == "deny"


def test_unknown_peer_or_forged_card_is_denied():
    assert Gateway(context()).decide(command("unknown-peer", "extract", kind="a2a")).verdict == "deny"
    gw = Gateway(context())
    card = AGENT_CARDS["curriculum-analyst"].to_dict()
    forged = replace(peer_command(), args=peer_command().args | {
        "agent_card": card | {"skills": ["extract_all_context"]}})
    assert gw.decide(forged).verdict == "deny"
    assert gw.decide(peer_command()).verdict != "deny"


def test_registry_known_clean_peer_is_not_denied_without_a_callback():
    assert Gateway(context()).decide(peer_command()).verdict == "forward"
    cmd = replace(peer_command(), args={"agent_card": {"verified": True, "skills": ["which_days_cover"]}})
    assert Gateway(context()).decide(cmd).verdict == "deny"


def test_duplicate_write_is_denied_even_before_history_is_updated():
    gw = Gateway(context(round=10, history=(provenance(round=10),)))
    assert gw.decide(write()).verdict != "deny"
    assert gw.decide(write()).verdict == "deny"


@pytest.mark.parametrize("server,tool,mask", [("registry", "list_servers", ("name",)),
                                           ("glossary", "list_terms", ("term",))])
def test_catalog_dump_rewritten_to_cheap_useful_fields(server, tool, mask):
    result = Gateway(context()).decide(command(server, tool, fields=("*",)))
    assert result.verdict == "rewrite" and result.call.fields == mask
    assert cost(server, tool, fields=mask) == 2


def test_deprecated_search_rewrites_arguments_and_fields_to_successor():
    result = Gateway(context()).decide(command("slides", "search", args={"q": "MCP"}, fields=("anchor", "snippet", "title")))
    assert result.verdict == "rewrite" and result.call.tool == "query"
    assert result.call.fields == ("body", "title")


def test_dynamic_rows_fit_budget_without_removing_explicit_body_field():
    result = Gateway(context(round=10, credits=5)).decide(command("slides", "query", args={"q": "MCP", "limit": 1000}, fields=("body",)))
    assert result.call.fields == ("body",) and result.call.args["limit"] == 2
    assert cost("slides", "query", fields=result.call.fields, n_rows=2) == 5
    assert Gateway(context(credits=0)).decide(command()).verdict == "deny"


def test_saved_credits_do_not_allow_wasteful_last_round():
    ctx = context(round=10, credits=40)
    gw = Gateway(ctx)
    query = command("slides", "query", args={"q": "MCP", "limit": 1000}, fields=("body",))
    result = gw.decide(query)
    assert result.verdict == "rewrite"
    charged = cost("slides", "query", fields=result.call.fields, n_rows=result.call.args["limit"])
    assert charged == 11
    ctx.credits -= charged
    assert gw.decide(command()).verdict == "deny"


def test_rate_limit_sliding_window_and_live_credit_reduction():
    previous = command("citation-checker", "verify_source", kind="a2a")
    history = tuple({"command": previous, "outcome": {"ok": True}, "round": r} for r in (1, 2))
    cmd = replace(previous, args={"anchor": FRAME})
    for round, allowed in ((3, False), (4, True)):
        gw = Gateway(context(round=round, history=history))
        gw.note_card("citation-checker", AGENT_CARDS["citation-checker"].to_dict())
        assert (gw.decide(cmd).verdict != "deny") is allowed
    ctx = context()
    gw = Gateway(ctx)
    assert gw.decide(command()).verdict == "forward"
    ctx.credits = 0
    assert gw.decide(command()).verdict == "deny"


@pytest.mark.parametrize("code,allowed", [("unavailable", True), ("unauthorized", True),
                                          ("rate_limited", True), ("not_found", False)])
def test_rate_limit_does_not_count_calls_rejected_before_slot_consumption(code, allowed):
    previous = command("citation-checker", "verify_source", kind="a2a", args={"anchor": FRAME})
    history = tuple({"command": previous, "outcome": {"ok": False, "error": {"code": code}},
                     "round": 1} for _ in range(2))
    cmd = replace(previous, args={"anchor": FRAME.replace("041", "042")})
    assert (Gateway(context(history=history)).decide(cmd).verdict != "deny") is allowed


def test_ten_clean_rounds_finish_inside_shared_hundred_credit_budget():
    ctx = context()
    gw = Gateway(ctx)
    for round in range(1, 11):
        ctx.round = round
        for _ in range(3):
            result = gw.decide(command())
            assert result.verdict == "forward"
            ctx.credits -= cost(result.call.server, result.call.tool, fields=result.call.fields)
    assert ctx.credits == 70


def test_actual_charge_replaces_query_row_estimate():
    ctx = context()
    gw = Gateway(ctx)
    assert gw.decide(command("slides", "query", args={"q": "MCP"})).verdict != "deny"
    ctx.credits = 98  # The query returned one row instead of its allowed five.
    assert gw.decide(peer_command()).verdict != "deny"


def test_query_limit_from_real_action_grammar_is_admitted():
    from kit.loop.agent import canonicalise_action

    action = canonicalise_action('MCP slides.query q="MCP" limit=1 fields=title', call_index=0)
    cmd = Command.from_action_dict(action, cmd_id="cmd:0000")
    result = Gateway(context()).decide(cmd)
    assert result.verdict == "rewrite" and result.call.args["limit"] == 1


def test_query_lease_frame_flow_with_real_servers_and_hardmode(tmp_path):
    from kit.mcp.hardmode import HardMode
    from kit.mcp.servers import handle
    from kit.world.fixture import build_fixture_world
    from kit.world.loader import World

    world = World.load(build_fixture_world(tmp_path / "world", include_truth=False))
    # Isolate lease enforcement from the unrelated seeded outage/partial mechanics.
    hm = HardMode(opaque_enabled=False, degraded_replica_enabled=False)
    hm.reset("SS-gateway-test")
    ctx = context()
    gw = Gateway(ctx)
    query = command("slides", "query", args={"q": "MCP", "ns": "Frame", "limit": 1})
    decision = gw.decide(query)
    result = handle(world, decision.call, hardmode=hm)
    assert result["ok"] and result["anchors"] and result["lease_id"], result
    ctx.credits -= result["cost"]
    ctx.history = ({"command": query, "decision": decision, "outcome": result, "round": 1},)
    ctx.leases = (result["lease_id"],)
    frame = command("slides", "get_frame", args={"anchor": result["anchors"][0]},
                    lease_id=result["lease_id"], call_index=2)
    decision = gw.decide(frame)
    assert decision.verdict != "deny"
    fetched = handle(world, decision.call, hardmode=hm)
    assert fetched["ok"] and fetched["anchors"] == [frame.args["anchor"]]
    assert "body" in fetched["rows"][0]
    ctx.round = 2
    ctx.leases = ()
    hm.begin_round(2)
    assert gw.decide(frame).verdict == "deny"


def test_decide_performs_no_io_and_stays_within_deadline(monkeypatch):
    import builtins
    import io
    import time

    def forbidden(*args, **kwargs):
        raise AssertionError("decide attempted I/O or sleep")

    gw = Gateway(context())
    started = time.perf_counter()
    with monkeypatch.context() as patch:
        patch.setattr(builtins, "open", forbidden)
        patch.setattr(io, "open", forbidden)
        patch.setattr(time, "sleep", forbidden)
        result = gw.decide(command())
    assert time.perf_counter() - started < 0.250
    assert result.verdict == "forward"


def test_authorised_write_executes_once_against_real_server(tmp_path):
    from agent.guardrails import prepare_answer
    from kit.mcp.hardmode import HardMode
    from kit.mcp.servers import handle
    from kit.world.fixture import build_fixture_world
    from kit.world.loader import World

    world = World.load(build_fixture_world(tmp_path / "world", include_truth=False))
    hm = HardMode(opaque_enabled=False, degraded_replica_enabled=False)
    hm.reset("SS-write-test")
    ctx = context()
    gw = Gateway(ctx)
    read = command("registry", "provenance", args={"anchor": LEARNER}, call_index=0)
    read_decision = gw.decide(read)
    result = handle(world, read_decision.call, hardmode=hm)
    assert result["ok"] and result["etag"]
    ctx.history = ({"command": read, "decision": read_decision, "outcome": result, "round": 1},)
    ctx.credits -= result["cost"]
    concept = world.search("MCP", ns="Concept", limit=1)[0].anchor
    cmd = replace(write(), args=write().args | {"concept": concept},
                  headers={"if-match": result["etag"], "idempotency-key": "real-write-1"})
    decision = gw.decide(cmd)
    assert decision.verdict != "deny"
    receipt = handle(world, decision.call, hardmode=hm)
    assert receipt["ok"] and receipt["rows"][0]["receipt_id"]
    payload = {"text": "Recorded mastery.", "cited_anchors": receipt["anchors"],
               "receipt_id": receipt["rows"][0]["receipt_id"]}
    ask = {"type": "record_mastery", "require": ["receipt_id"]}
    assert prepare_answer(payload, [receipt], ask=ask) == payload
    assert prepare_answer(payload | {"receipt_id": "receipt-forged"}, [receipt], ask=ask)["abstained"]
    assert gw.decide(cmd).verdict == "deny"
