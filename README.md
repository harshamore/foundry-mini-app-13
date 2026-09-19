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

**Correction, found by direct testing rather than assumed**: the plan going
in was "one trace per graph invocation, each role as a nested span inside
it" — richer than app-12's flat design, "for free" from LangChain's callback
propagation. That's not what actually happens. `llm.py`'s `invoke_structured()`
— the function every role's LLM call goes through — builds its own fresh
`config` at the point of each call (`run_name`/`tags` naming that role) and
attaches the same `SplunkAOCallback` instance there directly; LangGraph nodes
are plain Python functions, not `Runnable`s, so they never receive or nest
under the top-level `graph.stream()` call's config in the first place —
`tracer` reaches each node purely via closure. Combined with
`SplunkAOCallback` defaulting to `start_new_trace=True`, reusing the same
callback instance across independent calls produces **one trace per
individual chain invocation** — e.g. several separate `"triager"`-named
traces (one per candidate the role loops over), not one combined trace per
role, and the top-level `"full-pipeline"` attachment in `pipeline.py`
doesn't parent anything. Confirmed by constructing a real `SplunkAOLogger`
in `ingestion_hook` mode (bypasses the network entirely while still
exercising the real callback → commit → flush pipeline) and inspecting the
captured payload directly.

That same investigation also explains a bug this build shipped with and then
fixed: **`SplunkAOLogger.traces` is never populated by the callback-based
path** — a full offline round trip (a real, well-formed trace captured via
`ingestion_hook`, successfully flushed) still left `logger.traces == []`
throughout. `observability.py`'s activation check originally used
`len(logger.traces)`, ported directly from app-12's manual-span design where
that field *is* the right signal — here it always read zero, so the UI
reported "SAO tracing did not activate" even on runs where it demonstrably
had. Fixed by wrapping `SplunkAOCallback` in a subclass that counts
`on_chain_end` completions instead, confirmed empirically to be the correct
signal for this path.

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
