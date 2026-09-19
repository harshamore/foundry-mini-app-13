# Foundry-mini — LangChain / LangGraph edition

The same product as [`foundry-mini-app-12`](https://github.com/harshamore/foundry-mini-app-12)
— an **agentic security scanner** running the [Cisco Foundry Security Spec](https://github.com/CiscoDevNet/foundry-security-spec)'s
pipeline, real [CodeGuard](https://github.com/cosai-oasis/project-codeguard) rules, raw LLM
vs. harness compared side by side — rebuilt on **real LangChain chains
orchestrated by a LangGraph `StateGraph`**, with **Splunk Agent Observability**
wired through LangChain's own native `SplunkAOCallback` instead of manual
spans.

app-12 deliberately avoided LangChain (each role was a single structured
completion behind a custom seam, argued at the time that no role here needs
a multi-step tool-use loop or retrieval, so a framework wasn't worth the
weight). That reasoning holds for app-12's raw-SDK build specifically — this
is the other half of the comparison: the same roles, built the idiomatic
2026 LangChain way, so you can see what the framework actually buys you.

Runs with **Anthropic**, **OpenAI**, or **fully offline** (deterministic
engine, no key, no network) so it never breaks in front of an audience.

## What changed vs. app-12, and what didn't

**Unchanged — framework-agnostic, ported verbatim:**
- `finding.py` — the evidence gate (`evidence_gate()`), citation/fingerprint
  logic. The model proposes citations; this function, plain Python, decides
  pass/fail. Principle I doesn't change because the framework around it does.
- `index.py` — deterministic AST indexer (FR-020, never LLM-only).
- `rules.py` + the CodeGuard rule corpus.
- Every prompt's actual text (Cartographer, Detector, Triager, Reporter). The
  prompts were already real and generalized in app-12 — only the plumbing
  around each call changed.
- Every offline mock function — pure Python, no LangChain model touched in
  offline mode, same "never breaks in front of an audience" guarantee.

**Real change — how a role's LLM call happens:**
- app-12: `Model.ask_json(role, system, user)` — hand-built per-provider
  JSON-mode / forced-tool-use plumbing, hand-parsed with `extract_json()`.
- Here: `prompt | chat_model` real LangChain `Runnable`s, structured via
  `.with_structured_output(Schema, include_raw=True)` — LangChain's own
  native, cross-provider mechanism. `include_raw=True` matters: the plain
  form only returns the parsed object and discards the `AIMessage` carrying
  `usage_metadata` (token counts), which `Budget.charge()` needs.

**Real change — orchestration:**
- app-12: a plain `Pipeline` class with `stage_index()`/`stage_cartograph()`/
  etc. methods called in sequence, each mutating attributes on the object.
- Here: `graph.py`'s `HarnessState` (a `TypedDict`) flows through a compiled
  `StateGraph` — one node per spec role (`indexer` → `cartographer` →
  `detector` → `triager` → `validator` → `reporter` → `END`), invoked once
  per run via `.stream()`. `pipeline.py`'s `stream_harness()` iterates that
  stream so the UI still gets the same per-stage progress granularity
  app-12 had, just sourced from graph state deltas instead of attribute
  mutations.

**Real change — observability, and the richer hierarchy that comes with it.**
See below.

## Observability — SplunkAOCallback, not manual spans

app-12 wired Splunk Agent Observability by hand: manual `SplunkAOLogger.
start_trace()/add_llm_span()/conclude()/flush()` calls, plus a hand-rolled
`logging.Handler` to catch the SDK's own swallow-and-warn failures (the SDK's
trace/span calls don't raise on failure — they log via Python's `logging`
module instead, by design, so one bad span never crashes the caller's app).
That whole mechanism was necessary because app-12 had no framework
underneath to hook into.

Here, every role's real call IS a LangChain `Runnable`, so SAO attaches
through LangChain's own integration: one `SplunkAOCallback`, built once per
"Run" click, passed via `config={"callbacks": [...]}` on every
`chain.invoke()` (`llm.py`'s `invoke_structured()` is the one place it's
wired — same "single attachment point" principle as app-12, adapted to
LangChain idioms). The hard-won lesson about the SDK's own swallow-and-warn
behavior is carried over rather than rediscovered: `_WarningCollector` still
attaches to the `"splunk_ao"` logger and surfaces what it catches in the UI.

**The hierarchy this produces is richer than app-12's, for free**, from
LangChain's own callback propagation: one session per "Run" click (as
before), but now **one trace per graph invocation** — the whole harness
pipeline is "one complete interaction," matching SAO's own definition of a
trace — with each role's chain call showing up as a **nested named span**
inside that trace via its `run_name`/`tags`. app-12's flatter "one trace per
role" design was a simplification forced by having no natural nesting
mechanism in a raw-SDK build; this should be the more faithful mapping.

**Unverified, flagged plainly rather than assumed**: whether LangGraph
node-internal chain invocations actually propagate the top-level `config`'s
callbacks/tags far enough down to produce correctly-nested, correctly-named
spans, or whether every role's contribution flattens into one
undifferentiated trace. `SplunkAOCallback` is used here rather than
`SplunkAOMiddleware` specifically because the SDK's own docs only demonstrate
the middleware attached to `create_agent(...)` (a prebuilt ReAct-style
agent) — not a hand-rolled `StateGraph` — while the callback attached via
`config=` is the same mechanism already proven to work for Galileo tracing
in the sibling DeepAgents-based harness. **Check the actual trace tree the
first time this runs live with a real key.** If nesting doesn't come
through, the documented fallback is invoking each node's chain as its own
top-level call (one trace per role, matching app-12's flatter shape exactly)
instead of one `graph.stream()` for the whole run.

Three GUI fields, all optional (Observability expander in the sidebar): a
**SAO API key**, a **SAO project name** (default `foundry-mini`), and a
**SAO Agent Stream name** (default `streamlit`) — both get-or-created by
name. Leave the key blank and `splunk_ao` is never imported. `splunk-ao` is
in `requirements.txt` directly (not an optional extra) — this app's primary
target is Streamlit Community Cloud, a headless deploy with no live-install
lever, so nothing load-bearing stays optional-install-only.

## Run locally

```bash
pip install -r requirements.txt
streamlit run streamlit_app.py
```

## Deploy to Streamlit Community Cloud (free)

Push this folder to a GitHub repo, go to https://share.streamlit.io , "New
app", point it at `streamlit_app.py`. No secrets required — users paste
their own API key in the UI, or use offline demo mode.

## How it maps to the spec

| Spec role | Module |
|---|---|
| Indexer §5.2 | `foundry_mini/index.py` |
| Cartographer §5.3 | `foundry_mini/cartographer.py` |
| Detector §5.4 | `foundry_mini/detector.py` |
| Triager §5.5 | `foundry_mini/triager.py` |
| Validator §5.6 | `foundry_mini/validator.py` |
| Reporter §5.8 | `foundry_mini/reporter.py` |
| Finding lifecycle §7 | `foundry_mini/finding.py` |
| Rule corpus FR-041 | `foundry_mini/rules.py` |
| Orchestration | `foundry_mini/graph.py`, `foundry_mini/pipeline.py` |
| Provider layer §11.2 | `foundry_mini/llm.py` |

### Honored vs. deferred

**Honored:** Evidence Over Assertion (I) — a mechanical gate independent of
the model's own say-so; Surface Only What Survives (II); Fingerprints
Stable Under Edit (VIII); Coverage Before Yield (VI); Exploited Means
Demonstrated (VII).

**Deferred to the production build:** heartbeat liveness (III), atomic
mortal claims (IV), provider-as-rate-arbiter (V), infrastructure sandbox
(IX). Never executes fetched or pasted code — no live testbed means PoCs
stay sketches, by design.

---

_Detection rules: CodeGuard (CC-BY-4.0). Architecture: Cisco Foundry
Security Spec. This is a prototype, not the production system._
