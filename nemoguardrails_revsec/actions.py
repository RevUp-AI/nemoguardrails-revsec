"""RevSec rails for NVIDIA NeMo Guardrails: the actions behind the four flows.

Import the rails and name the flows in the app's ``config.yml``::

    import_paths:
      - nemoguardrails_revsec/rails

    rails:
      input:
        flows: [revsec check input]
      output:
        flows: [revsec check output]
      tool_call:
        flows: [revsec check tool calls]
      tool_result:
        flows: [revsec check tool results]

    custom_data:
      revsec:
        agent_name: support-assistant

What each flow does, with the organisation's policies in RevSec deciding:

  * ``revsec check input``: the user's message is checked with RevSec's Model
    Security check before the model sees it. A stopped message never reaches
    the model; the user gets a reply saying why.
  * ``revsec check tool calls``: each tool call the model asks for is checked
    against the app's tool-call policies before the app runs it. A stopped call
    is taken out of the reply, so the app never runs it; when every call is
    stopped, the reply says why instead.
  * ``revsec check tool results``: what a tool handed back is checked before
    the model reads it; a stopped result is replaced with one saying it was
    withheld.
  * ``revsec check output``: the model's reply is checked before the app uses
    it; a stopped reply is replaced with one saying it was withheld.

The app is put in RevSec's agent registry on its first check, with its model and
the tools it has called, so it shows in the console with its decisions.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import uuid
from typing import Any, Dict, List, Literal, Optional, Tuple

from pydantic import BaseModel, ConfigDict, Field, SecretStr

from nemoguardrails.actions import action
from revsec import agent as _agent
from revsec import checks as _checks
from revsec import mcp as _mcp
from revsec import tools as _tools

from nemoguardrails_revsec._version import __version__

logger = logging.getLogger("nemoguardrails_revsec")

INTEGRATION = f"nemoguardrails-revsec/{__version__}"
FRAMEWORK = "nemo_guardrails"            # RevSec's name for NeMo Guardrails apps in its framework registry
DEFAULT_AGENT_NAME = "nemo-guardrails-app"
SESSION_VARIABLE = "revsec_session_id"   # a context variable the app may set to tie one conversation's checks together
_SESSION_NAMESPACE = uuid.UUID("6b1f2c3d-8e4a-4f5b-9c6d-2a7e8f9b0c14")
_ALLOW: Dict[str, Any] = {"allowed": True, "message": ""}


class RevSecRailsSettings(BaseModel):
    """The ``custom_data: revsec:`` block of the app's config.yml. Every key is optional."""

    model_config = ConfigDict(extra="forbid")

    agent_name: Optional[str] = Field(
        default=None, description="The app's name in RevSec (one per app; registering again updates the same "
        "agent). Default: 'nemo-guardrails-app'.")
    api_key: Optional[SecretStr] = Field(
        default=None, description="A RevSec SDK key. Default: the REVSEC_API_KEY environment variable.")
    base_url: Optional[str] = Field(
        default=None, description="Your RevSec address ending in /fcc. Default: REVSEC_BASE_URL.")
    register_agent: bool = Field(default=True, description="Put the app in RevSec's registry on its first check.")
    description: Optional[str] = Field(default=None, description="Shown on the app in RevSec.")
    owner_email: Optional[str] = Field(default=None, description="Shown on the app in RevSec.")
    environment: Optional[str] = Field(default=None, description="Shown on the app in RevSec, e.g. production.")
    customer_facing: Optional[bool] = Field(
        default=None, description="Shown on the app in RevSec; also feeds its setup rating.")
    failure_mode: Optional[Literal["fail_open", "fail_closed"]] = Field(
        default=None, description="When RevSec can't be reached: 'fail_open' (the default) lets the app go on, "
        "'fail_closed' stops it.")
    check_prompts: Optional[bool] = Field(default=None, description="'revsec check input' checks (on by default).")
    check_replies: Optional[bool] = Field(default=None, description="'revsec check output' checks (on by default).")
    check_tool_results: Optional[bool] = Field(
        default=None, description="'revsec check tool results' checks (on by default).")
    dlp: Optional[bool] = Field(
        default=None, description="Also scan each tool call's arguments for sensitive data (off by default).")
    enabled: bool = Field(default=True, description="Whether the RevSec flows check anything.")


def settings_of(config: Any) -> RevSecRailsSettings:
    """The app's RevSec settings, from its RailsConfig's ``custom_data``."""
    custom = getattr(config, "custom_data", None) or {}
    return RevSecRailsSettings.model_validate(custom.get("revsec") or {})


def _main_model(config: Any) -> Optional[str]:
    """The name of the app's main model, as its config.yml gives it."""
    for model in getattr(config, "models", None) or []:
        if getattr(model, "type", None) != "main":
            continue
        name = getattr(model, "model", None)
        params = getattr(model, "parameters", None) or {}
        name = name or params.get("model_name") or params.get("model")
        return str(name) if name else None
    return None


class _App:
    """One NeMo Guardrails app (one RevSec agent): its settings and its registration."""

    def __init__(self, settings: RevSecRailsSettings, model: Optional[str]) -> None:
        self.settings = settings
        self.name = (settings.agent_name or "").strip() or DEFAULT_AGENT_NAME
        self.model = model
        self.agent_id: Optional[str] = None
        self.tools: List[str] = []
        self._registered = not settings.register_agent
        self._registered_tools: List[str] = []
        self._lock = asyncio.Lock()

    async def ensure_registered(self, tools: Optional[List[str]] = None) -> None:
        """Register the app on its first check, and again when it calls a tool RevSec has not been told about."""
        for tool in tools or []:
            if tool and tool not in self.tools:
                self.tools.append(tool)
        if self._registered and (self.agent_id is None or self.tools == self._registered_tools):
            return
        async with self._lock:
            if self._registered and (self.agent_id is None or self.tools == self._registered_tools):
                return
            self._registered = True
            tools_now = list(self.tools)
            s = self.settings
            try:
                me = await _agent.aregister(
                    name=self.name, framework=FRAMEWORK, models=[self.model] if self.model else [],
                    tools=tools_now, tags={"integration": INTEGRATION}, customer_facing=s.customer_facing,
                    **{k: v for k, v in (("description", s.description), ("owner_email", s.owner_email),
                                         ("environment", s.environment)) if v})
            except _agent.RegistrationFailed as e:
                logger.error("RevSec did not register app %r: %s. Its checks still run, but agent-level rules "
                             "can't apply to it.", self.name, e)
                return
            self.agent_id = me.agent_id
            self._registered_tools = tools_now


_APPS: Dict[str, _App] = {}


def app_for(config: Any) -> _App:
    """The app a RailsConfig describes, configuring the RevSec SDK the first time it is seen."""
    settings = settings_of(config)
    name = (settings.agent_name or "").strip() or DEFAULT_AGENT_NAME
    app = _APPS.get(name)
    if app is not None and app.settings == settings:
        return app
    key = settings.api_key.get_secret_value() if settings.api_key else None
    key = key or _mcp._config.api_key or os.environ.get("REVSEC_API_KEY")
    if not key:
        # Logged here as well: NeMo Guardrails reports a failed action without its message.
        message = ("RevSec key not set: set REVSEC_API_KEY, or api_key under custom_data: revsec: in config.yml "
                   "(Customer accounts → New key, or Settings → SDK, in the RevSec console issues one)")
        logger.error(message)
        raise ValueError(message)
    _mcp.configure(api_key=key, base_url=settings.base_url, failure_mode=settings.failure_mode,
                   check_prompts=settings.check_prompts, check_tool_results=settings.check_tool_results,
                   check_replies=settings.check_replies, dlp=settings.dlp)
    app = _App(settings, _main_model(config))
    _APPS[name] = app
    return app


def _session(context: Dict[str, Any]) -> Optional[str]:
    """The conversation's RevSec session: the app's ``revsec_session_id`` context variable, as a UUID."""
    value = context.get(SESSION_VARIABLE)
    if not value:
        return None
    try:
        return str(uuid.UUID(str(value)))
    except ValueError:
        return str(uuid.uuid5(_SESSION_NAMESPACE, str(value)))


def _why(verdict: Any) -> str:
    return (verdict.reason or verdict.rule_name or verdict.threat_type or "a RevSec policy").rstrip(". ")


def _tool_call(call: Any) -> Tuple[str, Dict[str, Any], Any]:
    """(tool name, arguments, the call as the rail holds it) for one tool call: an OpenAI-style dict or a
    NeMo Guardrails ToolCall."""
    # A dict first: the rail's context hands calls over as a dict type that answers any attribute (with None).
    if isinstance(call, dict):
        raw = call
    else:
        to_dict = getattr(call, "to_dict", None)
        raw = to_dict() if callable(to_dict) else {}
    raw = raw if isinstance(raw, dict) else {}
    function = raw.get("function") if isinstance(raw.get("function"), dict) else {}
    name = function.get("name") or raw.get("name") or ""
    args = function.get("arguments", raw.get("args", raw.get("arguments")))
    if isinstance(args, str):
        try:
            args = json.loads(args) if args.strip() else {}
        except ValueError:
            args = {"input": args}
    if not isinstance(args, dict):
        args = {} if args is None else {"input": args}
    return str(name), json.loads(json.dumps(args, default=str)), call


def _reason(decision: Any) -> str:
    return (decision.reason or f"policy '{decision.policy_name or 'unnamed'}'").rstrip(". ")


# ── the four actions ──────────────────────────────────────────────────────


@action(name="revsec_check_input")
async def revsec_check_input(context: Optional[Dict[str, Any]] = None, config: Any = None, **_: Any) -> Dict[str, Any]:
    """Check the user's message before the model sees it."""
    app = app_for(config)
    if not app.settings.enabled:
        return dict(_ALLOW)
    await app.ensure_registered()
    if not (_mcp._config.enabled and _mcp._config.check_prompts):
        return dict(_ALLOW)
    context = context or {}
    text = _checks.reply_text(context.get("user_message"))
    if not text.strip():
        return dict(_ALLOW)
    verdict = await _checks.check_prompt(text, agent_id=app.agent_id, model=app.model, session_id=_session(context))
    if verdict.allowed:
        return {"allowed": True, "message": "", "decision": verdict.decision}
    return {"allowed": False, "decision": "block", "rule": verdict.rule_name,
            "message": f"Blocked by RevSec: {_why(verdict)}. This request was not sent to the model."}


@action(name="revsec_check_output")
async def revsec_check_output(context: Optional[Dict[str, Any]] = None, config: Any = None, **_: Any) -> Dict[str, Any]:
    """Check the model's reply before the app uses it."""
    app = app_for(config)
    if not app.settings.enabled:
        return dict(_ALLOW)
    await app.ensure_registered()
    if not (_mcp._config.enabled and _mcp._config.check_replies):
        return dict(_ALLOW)
    context = context or {}
    text = _checks.reply_text(context.get("bot_message"))
    if not text.strip():
        return dict(_ALLOW)
    verdict = await _checks.check_reply(text, agent_id=app.agent_id, model=app.model, session_id=_session(context))
    if verdict.allowed:
        return {"allowed": True, "message": "", "decision": verdict.decision}
    return {"allowed": False, "decision": "block", "rule": verdict.rule_name, "message": verdict.withheld_reply()}


@action(name="revsec_check_tool_calls")
async def revsec_check_tool_calls(context: Optional[Dict[str, Any]] = None, config: Any = None,
                                  **_: Any) -> Dict[str, Any]:
    """Check each tool call the model asks for before the app runs it. ``tool_calls`` is what may run."""
    context = context or {}
    calls = list(context.get("tool_calls") or [])
    app = app_for(config)
    if not app.settings.enabled or not calls:
        return {"allowed": True, "message": "", "tool_calls": calls}
    parsed = [_tool_call(c) for c in calls]
    await app.ensure_registered([name for name, _a, _c in parsed])
    session = _session(context)

    async def decide(name: str, args: Dict[str, Any]) -> Optional[str]:
        decision = await _tools.evaluate(tool=name, args=args, agent_id=app.agent_id, session_id=session)
        if not decision.allowed and not decision.soft_launch_only:
            return _reason(decision)
        data = await _tools.scan_args(tool=name, args=args, agent_id=app.agent_id)
        return _reason(data) if data is not None else None

    reasons = await asyncio.gather(*(decide(name, args) for name, args, _c in parsed))
    kept = [call for (_n, _a, call), why in zip(parsed, reasons) if why is None]
    stopped = [f"{name}: {why}" for (name, _a, _c), why in zip(parsed, reasons) if why is not None]
    if not stopped:
        return {"allowed": True, "message": "", "tool_calls": calls}
    return {"allowed": False, "tool_calls": kept, "stopped": len(stopped),
            "message": "Blocked by RevSec: " + "; ".join(stopped) + "."}


@action(name="revsec_check_tool_result")
async def revsec_check_tool_result(context: Optional[Dict[str, Any]] = None, config: Any = None,
                                   **_: Any) -> Dict[str, Any]:
    """Check what a tool handed back before the model reads it."""
    app = app_for(config)
    if not app.settings.enabled:
        return dict(_ALLOW)
    await app.ensure_registered()
    if not (_mcp._config.enabled and _mcp._config.check_tool_results):
        return dict(_ALLOW)
    context = context or {}
    text = _checks.result_text(context.get("tool_message"))
    if not text.strip():
        return dict(_ALLOW)
    verdict = await _checks.check_tool_result(text, tool=context.get("tool_name"), agent_id=app.agent_id,
                                              session_id=_session(context))
    if verdict.allowed:
        return {"allowed": True, "message": "", "decision": verdict.decision}
    return {"allowed": False, "decision": "block", "rule": verdict.rule_name,
            "message": verdict.withheld_text("tool result")}
