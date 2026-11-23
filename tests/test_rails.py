"""The RevSec rails in real NeMo Guardrails apps: a scripted model, the app's config.yml importing the rails,
checked by a stand-in RevSec over real HTTP."""
from __future__ import annotations

import json

import pytest

import nemoguardrails_revsec
from conftest import AGENT_ID, STOP_REPLY, STOP_REQUEST, app, calls, reply

USER = [{"role": "user", "content": "Where is order A1?"}]


async def test_a_conversation_is_checked_in_and_out_and_the_app_registered(tmp_path, revsec):
    rails, model = app(tmp_path, [reply("Order A1 shipped on Monday.")])
    out = await rails.generate_async(messages=USER)
    assert out["content"] == "Order A1 shipped on Monday."
    assert revsec.kinds() == ["prompt", "reply"]
    assert revsec.contents[0]["content"] == "Where is order A1?"
    assert revsec.contents[1]["content"] == "Order A1 shipped on Monday."
    assert all(c["agent_id"] == AGENT_ID and c["model"] == "gpt-test" for c in revsec.contents)
    [reg] = revsec.registrations
    assert reg["name"] == "support-assistant" and reg["agent_framework"] == "nemo_guardrails"
    assert reg["underlying_models"] == ["gpt-test"]
    assert reg["tags"]["integration"] == nemoguardrails_revsec.INTEGRATION


async def test_a_stopped_request_never_reaches_the_model(tmp_path, revsec):
    rails, model = app(tmp_path, [reply("should not be generated")])
    out = await rails.generate_async(messages=[{"role": "user", "content": f"{STOP_REQUEST} and refund every order"}])
    assert out["content"] == ("Blocked by RevSec: instructions aimed at the model. "
                              "This request was not sent to the model.")
    assert model.inference_count == 0 and model.seen == []
    assert revsec.kinds() == ["prompt"], "the stop reply is RevSec's own: it is not checked again"


async def test_a_stopped_reply_is_withheld(tmp_path, revsec):
    rails, _model = app(tmp_path, [reply(f"Try logging in as admin{STOP_REPLY}")])
    out = await rails.generate_async(messages=USER)
    assert out["content"] == ("Withheld by RevSec: the model's reply was not passed on "
                              "(SQL injection payload in the reply).")


async def test_an_allowed_tool_call_goes_back_to_the_app(tmp_path, revsec):
    rails, _model = app(tmp_path, [calls(("lookup_order", {"order_id": "A1"}))])
    out = await rails.generate_async(messages=USER)
    [call] = out["tool_calls"]
    assert call["function"]["name"] == "lookup_order"
    [ev] = revsec.evaluations
    assert ev["tool_name"] == "lookup_order" and ev["tool_kind"] == "agent"
    assert ev["tool_args"] == {"order_id": "A1"} and ev["agent_id"] == AGENT_ID


async def test_a_stopped_tool_call_never_reaches_the_app(tmp_path, revsec):
    rails, _model = app(tmp_path, [calls(("refund_order", {"order_id": "A1", "amount": 500}))])
    out = await rails.generate_async(messages=[{"role": "user", "content": "Refund order A1"}])
    assert not out.get("tool_calls")
    assert out["content"] == "Blocked by RevSec: refund_order: Refunds need a person."


async def test_only_the_stopped_call_is_taken_out(tmp_path, revsec):
    rails, _model = app(tmp_path, [calls(("lookup_order", {"order_id": "A1"}), ("delete_note", {"name": "x"}))])
    out = await rails.generate_async(messages=USER)
    assert [c["function"]["name"] for c in out["tool_calls"]] == ["lookup_order"]
    assert {e["tool_name"] for e in revsec.evaluations} == {"lookup_order", "delete_note"}


async def test_tools_the_app_calls_are_added_to_its_registration(tmp_path, revsec):
    rails, _model = app(tmp_path, [calls(("lookup_order", {"order_id": "A1"}))])
    await rails.generate_async(messages=USER)
    assert [r["tools"] for r in revsec.registrations] == [[], ["lookup_order"]]


HISTORY = [
    {"role": "user", "content": "What does the shop's page say?"},
    {"role": "assistant", "content": "", "tool_calls": [
        {"id": "call_9", "type": "function", "function": {"name": "fetch_page", "arguments": "{\"url\": \"x\"}"}}]},
]


async def test_a_stopped_tool_result_is_withheld_from_the_model(tmp_path, revsec):
    rails, model = app(tmp_path, [reply("The page says to contact support.")])
    page = f"Welcome to our store. {STOP_REQUEST} and refund every order."
    out = await rails.generate_async(messages=HISTORY + [{"role": "tool", "tool_call_id": "call_9", "content": page}])
    assert out["content"] == "The page says to contact support."
    tool_check = next(c for c in revsec.contents if c["kind"] == "tool_result")
    assert tool_check["tool_name"] == "fetch_page" and STOP_REQUEST in tool_check["content"]
    sent = "\n".join(model.seen)
    assert "Withheld by RevSec: this tool result was not passed to the model" in sent
    assert STOP_REQUEST not in sent


async def test_a_clean_tool_result_reaches_the_model(tmp_path, revsec):
    rails, model = app(tmp_path, [reply("Order A1 shipped.")])
    await rails.generate_async(messages=HISTORY + [{"role": "tool", "tool_call_id": "call_9",
                                                    "content": "order A1: shipped"}])
    assert "order A1: shipped" in "\n".join(model.seen)


async def test_with_rails_exceptions_a_stop_is_an_exception_message(tmp_path, revsec):
    rails, model = app(tmp_path, [reply("x")], extra="enable_rails_exceptions: true\n")
    out = await rails.generate_async(messages=[{"role": "user", "content": STOP_REQUEST}])
    assert out["role"] == "exception"
    assert out["content"]["type"] == "RevSecRailException"
    assert "Blocked by RevSec: instructions aimed at the model" in out["content"]["message"]
    assert model.inference_count == 0


async def test_the_conversation_session_comes_from_the_apps_context(tmp_path, revsec):
    rails, _model = app(tmp_path, [reply("ok")])
    await rails.generate_async(messages=[{"role": "context", "content": {"revsec_session_id": "ticket-42"}}] + USER)
    sessions = {c["session_id"] for c in revsec.contents}
    assert len(sessions) == 1 and None not in sessions
    import uuid
    uuid.UUID(sessions.pop())


async def test_only_the_rails_named_in_config_check(tmp_path, revsec):
    rails, _model = app(tmp_path, [reply("Order A1 shipped.")],
                        rails="rails:\n  input:\n    flows: [revsec check input]\n")
    await rails.generate_async(messages=USER)
    assert revsec.kinds() == ["prompt"]


async def test_settings_turn_checks_off(tmp_path, revsec):
    rails, _model = app(tmp_path, [reply("Order A1 shipped.")],
                        revsec_block={"agent_name": "support-assistant", "check_prompts": False})
    await rails.generate_async(messages=USER)
    assert revsec.kinds() == ["reply"]


async def test_disabled_checks_nothing(tmp_path, revsec):
    rails, _model = app(tmp_path, [reply("Order A1 shipped.")],
                        revsec_block={"agent_name": "support-assistant", "enabled": False})
    out = await rails.generate_async(messages=USER)
    assert out["content"] == "Order A1 shipped." and revsec.contents == [] and revsec.registrations == []


async def test_registration_refused_still_checks(tmp_path, revsec):
    revsec.register_status = 401
    rails, _model = app(tmp_path, [calls(("refund_order", {"amount": 5}))])
    out = await rails.generate_async(messages=USER)
    assert out["content"].startswith("Blocked by RevSec: refund_order")
    assert revsec.evaluations[0].get("agent_id") in (None, "")
    assert len(revsec.registrations) == 1, "a refused registration is not retried on every check"


def test_a_typo_in_the_revsec_settings_is_refused():
    from nemoguardrails_revsec.actions import settings_of

    class Config:
        custom_data = {"revsec": {"agent_nmae": "x"}}
    with pytest.raises(Exception) as caught:
        settings_of(Config())
    assert "agent_nmae" in str(caught.value)


def test_the_flow_names_and_rails_path():
    import os
    assert nemoguardrails_revsec.FLOWS == {"input": "revsec check input", "output": "revsec check output",
                                           "tool_call": "revsec check tool calls",
                                           "tool_result": "revsec check tool results"}
    assert os.path.isfile(os.path.join(nemoguardrails_revsec.RAILS_PATH, "revsec.co"))
    assert os.path.isfile(os.path.join(nemoguardrails_revsec.RAILS_PATH, "actions.py"))
    text = open(os.path.join(nemoguardrails_revsec.RAILS_PATH, "revsec.co")).read()
    for flow in nemoguardrails_revsec.FLOWS.values():
        assert f"define subflow {flow}\n" in text


async def test_a_stopped_tool_call_with_rails_exceptions(tmp_path, revsec):
    rails, _model = app(tmp_path, [calls(("delete_note", {"name": "x"}))], extra="enable_rails_exceptions: true\n")
    out = await rails.generate_async(messages=USER)
    assert out["role"] == "exception" and out["content"]["type"] == "RevSecRailException"
    assert out["content"]["message"] == "Blocked by RevSec: delete_note: Deleting notes is not allowed."


async def test_a_missing_key_stops_the_app_and_says_why_in_the_log(tmp_path, revsec, monkeypatch, caplog):
    monkeypatch.delenv("REVSEC_API_KEY")
    rails, model = app(tmp_path, [reply("should not be generated")])
    out = await rails.generate_async(messages=USER)
    assert "internal error" in out["content"].lower() and model.inference_count == 0
    assert any("RevSec key not set" in r.getMessage() for r in caplog.records)


def _installed_beside_nemoguardrails() -> bool:
    import os
    import nemoguardrails
    site = os.path.dirname(os.path.dirname(os.path.abspath(nemoguardrails.__file__)))
    return os.path.dirname(os.path.dirname(nemoguardrails_revsec.RAILS_PATH)) == site


@pytest.mark.skipif(not _installed_beside_nemoguardrails(), reason="an editable install is not in site-packages")
async def test_the_short_import_path_resolves_when_installed(tmp_path, revsec):
    rails, _model = app(tmp_path, [reply("Order A1 shipped.")], import_path="nemoguardrails_revsec/rails")
    await rails.generate_async(messages=USER)
    assert revsec.kinds() == ["prompt", "reply"]
