"""RevSec rails for NVIDIA NeMo Guardrails.

Add the rails to an app's ``config.yml``::

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

and set ``REVSEC_API_KEY`` and ``REVSEC_BASE_URL``. If NeMo Guardrails can't
resolve the import path (a package installed outside NeMo Guardrails'
site-packages), use the absolute path ``nemoguardrails_revsec.RAILS_PATH``.
"""
from __future__ import annotations

from pathlib import Path

from nemoguardrails_revsec._version import __version__
from nemoguardrails_revsec.actions import (
    FRAMEWORK,
    INTEGRATION,
    SESSION_VARIABLE,
    RevSecRailsSettings,
    revsec_check_input,
    revsec_check_output,
    revsec_check_tool_calls,
    revsec_check_tool_result,
)

RAILS_PATH = str(Path(__file__).resolve().parent / "rails")
"""The rails folder, for ``import_paths`` when the short form ``nemoguardrails_revsec/rails`` doesn't resolve."""

FLOWS = {
    "input": "revsec check input",
    "output": "revsec check output",
    "tool_call": "revsec check tool calls",
    "tool_result": "revsec check tool results",
}
"""The flow to name under each of ``rails.input / output / tool_call / tool_result`` in config.yml."""

__all__ = [
    "FLOWS", "FRAMEWORK", "INTEGRATION", "RAILS_PATH", "SESSION_VARIABLE", "RevSecRailsSettings", "__version__",
    "revsec_check_input", "revsec_check_output", "revsec_check_tool_calls", "revsec_check_tool_result",
]
