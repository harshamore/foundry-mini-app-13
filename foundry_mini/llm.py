"""
LLM layer — LangChain edition of app-12's model.py.

`invoke_structured()` is the one seam every role calls through, same
principle as app-12's `Model.ask_json()`, adapted to LangChain idioms:
  - mock mode never touches a LangChain model at all — calls the same
    deterministic offline mock functions app-12 already proved out, so the
    app runs with no key and never breaks in front of an audience;
  - live mode calls `.with_structured_output(Schema, include_raw=True)` —
    NOT the plain form, which only returns the parsed object and discards
    the AIMessage carrying `usage_metadata` (token counts) that Budget.
    charge() needs;
  - the `config=` passed to `.invoke()` carries `run_name`/`tags`/
    `metadata` naming the role, and the SAO callback when tracing is on —
    this is the one attachment point optional Splunk Agent Observability
    tracing needs (observability.py), touching no role's own logic.

Budget/ModelError carry over from app-12 essentially unchanged — zero
LangChain dependency, no reason to rewrite them.
"""

from __future__ import annotations

DEFAULTS = {
    "anthropic": "claude-sonnet-4-6",
    "openai": "gpt-4o",
}

# Illustrative rates for cost estimation — LangChain's usage_metadata gives
# token counts, not dollar cost, so this stays the same estimation table
# app-12 used.
_RATE = {
    "anthropic": (0.003 / 1000, 0.015 / 1000),
    "openai": (0.0025 / 1000, 0.010 / 1000),
    "mock": (0.003 / 1000, 0.015 / 1000),
}


class Budget:
    def __init__(self, usd_cap=None):
        self.usd_cap = usd_cap
        self.spent = 0.0
        self.estimated = 0.0
        self.calls = 0

    def charge(self, in_tok, out_tok, provider, estimated):
        rin, rout = _RATE.get(provider, _RATE["mock"])
        cost = in_tok * rin + out_tok * rout
        self.spent += cost
        if estimated:
            self.estimated += cost
        self.calls += 1

    def exceeded(self):
        return self.usd_cap is not None and self.spent >= self.usd_cap

    def summary(self):
        frac = (self.estimated / self.spent) if self.spent else 0.0
        return {
            "usd_spent": round(self.spent, 4),
            "usd_cap": self.usd_cap,
            "calls": self.calls,
            "estimated_fraction": round(frac, 2),
        }


class ModelError(Exception):
    pass


def build_chat_model(provider: str, api_key: str | None, model_name: str | None):
    """A real LangChain chat model, or None for offline/mock mode."""
    if provider not in ("anthropic", "openai") or not api_key:
        return None
    model = model_name or DEFAULTS.get(provider, "")
    try:
        if provider == "anthropic":
            from langchain_anthropic import ChatAnthropic
            return ChatAnthropic(model=model, api_key=api_key, max_tokens=2048)
        # OpenAI: use_responses_api=True matches what DeepAgents itself
        # defaults to for a plain "openai:..." model string (noted in the
        # sibling LangChain-based harness's own FastAPI backend,
        # langchain/src/foundry/api/app.py) -- ChatOpenAI's own default is
        # the legacy Chat Completions API, and the gpt-5.x reasoning-model
        # family rejects `reasoning_effort` together with structured
        # output/tools on /v1/chat/completions. Without this, every live
        # run against a reasoning model fails before a single call succeeds.
        from langchain_openai import ChatOpenAI
        return ChatOpenAI(model=model, api_key=api_key, use_responses_api=True)
    except Exception as e:
        raise ModelError(f"could not initialize {provider} client: {e}")


def invoke_structured(prompt, llm, role: str, inputs: dict, schema, model_name: str,
                      budget: Budget, mock_fn=None, tracer=None):
    """
    The one seam every node/chain calls through.

    Takes `prompt` and `llm` SEPARATELY, not a pre-built `prompt | llm`
    chain — `.with_structured_output()` is a `BaseChatModel` method, not
    part of the generic `Runnable` interface, so it must be applied to
    `llm` directly (`llm.with_structured_output(schema, include_raw=True)`)
    *before* piping into the prompt. Piping first and calling
    `.with_structured_output()` on the resulting `RunnableSequence` raises
    `AttributeError: 'RunnableSequence' object has no attribute
    'with_structured_output'` — confirmed live and against the installed
    langchain-core source, not assumed. `include_raw=True` matters
    separately: the plain form only returns the parsed object and discards
    the AIMessage carrying `usage_metadata` (token counts) that
    Budget.charge() needs. Confirmed against langchain-core 1.6.3's own
    with_structured_output() docstring: "The final output is always a
    dict with keys 'raw', 'parsed', and 'parsing_error'" for both
    ChatAnthropic and ChatOpenAI.

    Returns a parsed instance of `schema`. Raises ModelError (naming `role`)
    on a live call failure or an unparseable reply, mirroring app-12's
    ask_json() -- a parse failure must be loud, not a silent empty result.
    """
    if llm is None:
        # mock / offline: no LangChain model touched at all. mock_fn takes
        # no arguments by convention -- callers build it as a closure over
        # whatever context it needs (index, symbol, corpus, ...), the same
        # factory-function shape app-12 already used.
        answer = mock_fn() if mock_fn else schema()
        # Still simulate a nonzero spend/call count, matching app-12's own
        # "the mock is not a toy" budget fidelity -- estimated from the
        # mock's own input/output size, not silently free.
        in_tok = max(1, len(str(inputs))) // 4
        out_tok = max(1, len(str(answer))) // 4
        budget.charge(in_tok, out_tok, "mock", estimated=True)
        return answer

    structured_llm = llm.with_structured_output(schema, include_raw=True)
    chain = prompt | structured_llm
    config = {"run_name": role, "tags": [role], "metadata": {"role": role}}
    if tracer is not None:
        config["callbacks"] = [tracer.callback]

    try:
        result = chain.invoke(inputs, config=config)
    except Exception as e:
        raise ModelError(f"{role}: live call failed: {e}")

    parsed = result.get("parsed")
    raw = result.get("raw")
    if parsed is None:
        err = result.get("parsing_error")
        raise ModelError(f"{role}: could not parse a structured reply ({err})")

    usage = getattr(raw, "usage_metadata", None) or {}
    in_tok = usage.get("input_tokens", 0)
    out_tok = usage.get("output_tokens", 0)
    provider = "anthropic" if "claude" in (model_name or "").lower() else "openai"
    budget.charge(in_tok, out_tok, provider, estimated=(in_tok == 0 and out_tok == 0))
    return parsed
