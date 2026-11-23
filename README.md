# nemoguardrails-revsec: RevSec rails for NVIDIA NeMo Guardrails

**One set of AI policies for every NeMo Guardrails app, managed in one place.**

NeMo Guardrails lets each app check what goes in and out of its model. RevSec adds the rails that apply your
organization's policies, the same ones it applies to your other agents, AI tools and MCP servers, and keeps a record
of what every app did. Your security team changes a policy once in the RevSec console; every app that uses these rails
follows it without a redeploy.

## What it does for your business

- **Stops risky actions before they happen.** Each tool call the model asks for is checked before your app runs it. A
  refund above a limit, a delete, or a call that would carry a secret or a card number is taken out, and the reply
  says why.
- **Keeps prompt injection and leaked data away from your model.** The user's message is checked before the model
  sees it, and what each tool hands back (web pages, documents, database rows) is checked before the model reads it:
  instructions aimed at the model, secrets and personal data.
- **Checks the reply before anyone uses it.** Secrets or personal data in a reply, and payloads aimed at a database,
  a template, a shell or a browser that would run or render it, are withheld.
- **Gives you one view of every app.** Each app appears in your RevSec console as an agent with its model, the tools
  it has called, its risk rating, and its decisions. Replay any conversation in Activity Explorer.
- **Proves control.** Frameworks shows which controls in the EU AI Act, ISO/IEC 42001, NIST AI RMF, SOC 2 and more your
  policies are mapped to, and Evidence Packs gather the evidence for a customer's security review or auditor.
- **Works alongside your own rails.** Keep NeMo Guardrails' built-in rails and your own flows; list the RevSec flows
  next to them.

## Quick start

```bash
pip install nemoguardrails-revsec
export REVSEC_API_KEY=rsk_...
export REVSEC_BASE_URL=https://app.revsec.app/fcc
```

Get a key from the RevSec console (**Customer accounts → New key** in a builder account, or **Settings → SDK**).
Then add the rails to your app's `config.yml`:

```yaml
models:
  - type: main
    engine: nim
    model: meta/llama-3.3-70b-instruct

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
```

That's all. The first conversation registers the app in RevSec. From then on its messages, tool calls, tool results
and replies are checked, and the decisions show in the console. List only the flows you want; each one works on its
own.

If NeMo Guardrails can't find `nemoguardrails_revsec/rails` (a package installed outside NeMo Guardrails'
site-packages), use the absolute path:

```bash
python -c "import nemoguardrails_revsec; print(nemoguardrails_revsec.RAILS_PATH)"
```

## What RevSec checks

| Flow | When | If RevSec stops it |
|---|---|---|
| `revsec check input` | The user's message, before the model sees it | The model is never called; the reply says the request was blocked and why |
| `revsec check tool calls` | Each tool call the model asks for, before your app runs it | The call is taken out of the reply, so your app never runs it; when every call is stopped, the reply says why |
| `revsec check tool results` | What a tool handed back, before the model reads it | The model gets "withheld" instead of the content |
| `revsec check output` | The model's reply, before your app uses it | The reply is replaced with one saying it was withheld |

With `enable_rails_exceptions: true` in `config.yml`, a stop is returned as a `RevSecRailException` (with the reason as
its message) instead of a reply, as NeMo Guardrails' own rails do.

Tool calls are checked as the app's own tools, against the tool-call policies in RevSec's Agent Security (for example
the "NVIDIA NeMo agents: tool calls" pack), so a policy can name the app's tools and arguments.

## Options

Everything under `custom_data: revsec:` is optional:

```yaml
custom_data:
  revsec:
    agent_name: support-assistant    # default: nemo-guardrails-app
    description: Answers order questions and issues refunds
    owner_email: team@example.com
    environment: production
    customer_facing: true            # shown on the app and used in its risk rating
    failure_mode: fail_open          # or fail_closed: stop when RevSec can't be reached
    check_prompts: true              # false when model calls go through the RevSec AI gateway
    check_replies: true              # false when model calls go through the RevSec AI gateway
    check_tool_results: true
    dlp: false                       # true also scans each tool call's arguments for sensitive data
    register_agent: true
    enabled: true
```

`api_key` and `base_url` can be set here too; by default they come from `REVSEC_API_KEY` and `REVSEC_BASE_URL`.

To show one conversation's checks together in Activity Explorer, pass a conversation id as a context message:

```python
await rails.generate_async(messages=[
    {"role": "context", "content": {"revsec_session_id": "ticket-4821"}},
    {"role": "user", "content": "Where is my order?"},
])
```

If RevSec can't be reached, checks let the app go on by default, so an outage never stops your product. Set
`failure_mode: fail_closed` to stop it instead.

## Requirements

- Python 3.10 or later, and NeMo Guardrails 0.25 or later with Colang 1.0 (the default)
- A RevSec account: [start a free 30-day trial](https://app.revsec.app/start?from=nemo-guardrails), no card needed

## Links

- RevSec: https://app.revsec.app/start?from=nemo-guardrails
- Source and issues: https://github.com/RevUp-AI/nemoguardrails-revsec
- The RevSec Python SDK: https://pypi.org/project/revsec-sdk/
- For agents built with the NVIDIA NeMo Agent Toolkit: https://pypi.org/project/nat-revsec/

Licensed under Apache 2.0. RevSec is a product of RevUp AI LLC. NVIDIA and NeMo are trademarks of NVIDIA Corporation;
this package is not made or endorsed by NVIDIA.
