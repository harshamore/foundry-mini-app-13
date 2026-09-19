"""
Optional Splunk Agent Observability (SAO) tracing — LangChain edition.

app-12 wired SAO by hand (manual SplunkAOLogger.start_trace()/add_llm_span()/
conclude()/flush() calls) because it had no framework underneath to hook
into. Here every role's real call IS a LangChain Runnable, so SAO attaches
through LangChain's own native integration instead: one SplunkAOCallback,
built once per "Run" click, passed via config={"callbacks": [...]} on every
chain.invoke() (llm.py's invoke_structured() is the one place it's wired).

Still strictly opt-in and fails soft, same as app-12: build_sao_tracer()
returns None whenever no API key is supplied — no import of `splunk_ao` is
even attempted — and any failure once a key IS set is caught and reported,
never raised.

Hard-won lesson ported from app-12, not rediscovered: the splunk-ao SDK's
own trace/span-emitting calls catch their own failures internally and log
via Python's `logging` module instead of raising. SplunkAOCallback almost
certainly goes through the same internals to emit its spans, so the same
_WarningCollector(logging.Handler) pattern — attach to the "splunk_ao"
logger, surface captured warnings in the UI — is carried over rather than
re-learned the hard way.

Target hierarchy: each role's own `invoke_structured()` call independently
attaches this callback with its own `run_name`/`tags` (confirmed by reading
`llm.py` — it builds a fresh config at every call site rather than relying on
propagation from a parent invocation), and `SplunkAOCallback` defaults to
`start_new_trace=True`, so in practice this produces one trace per
individual chain call — e.g. several separate `"triager"`-named traces, one
per candidate, not one combined trace for the whole role. Confirmed by
constructing a real `SplunkAOLogger` in `ingestion_hook` mode (bypasses the
network entirely, still exercises the real callback/commit/flush pipeline)
and inspecting the captured payload: a single `chain.invoke()` under this
config produces one well-formed, correctly-named, correctly-nested trace
(prompt-template span + LLM span) exactly as expected.

That same investigation surfaced the real bug behind "SAO tracing was
requested but did not activate" even when tracing demonstrably worked:
**`SplunkAOLogger.traces` is never populated by the callback-based path** —
confirmed empirically, not assumed: a full offline round trip (real trace
captured via `ingestion_hook`, successfully flushed) still left
`logger.traces == []` throughout. `logger.traces` is populated only by the
*manual* `start_trace()`/`add_trace()` API (what app-12's raw-SDK build and
Splunk's own sample scripts use) — the callback path builds and stages spans
through an entirely separate internal mechanism. `SAOTracer.activated` below
tracks activation via a `_TrackingCallback` subclass's `on_chain_end`
override instead, which the same investigation confirmed fires exactly when
an invocation completes and is staged for sending.
"""

from __future__ import annotations

import logging
import os
from typing import Any

DEFAULT_PROJECT = "foundry-mini"
DEFAULT_AGENT_STREAM = "streamlit"
DEFAULT_CONSOLE_URL = "https://console.multitenant.galileocloud.io"


class _WarningCollector(logging.Handler):
    """Captures splunk_ao's own internally-swallowed warnings so the app can
    show them instead of them vanishing into Python logging with no visible
    handler configured (see module docstring)."""

    def __init__(self):
        super().__init__(level=logging.WARNING)
        self.records: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(self.format(record))


def _make_tracking_callback(base_cls):
    """A SplunkAOCallback subclass that counts on_chain_end completions —
    confirmed the right activation signal by direct testing (see module
    docstring), unlike logger.traces which this build never populates."""

    class _TrackingCallback(base_cls):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.completed_count = 0

        def on_chain_end(self, *args, **kwargs):
            self.completed_count += 1
            return super().on_chain_end(*args, **kwargs)

    return _TrackingCallback


class SAOTracer:
    """One of these per SAO session — built for the main "Run" click, then
    reused (via st.session_state) by the two later follow-on actions too, so
    every real LLM call in a session gets traced, not just the main run.
    Wraps a tracking SplunkAOCallback; LangChain attaches it via config= at
    each chain.invoke() (llm.py), so this class's own job is bookkeeping
    (warnings, console urls, diagnostic counts), not manual span emission."""

    def __init__(self, callback: Any, logger: Any, console_url: str):
        self.callback = callback
        self._logger = logger
        self._console_url = console_url
        self._warnings = _WarningCollector()
        logging.getLogger("splunk_ao").addHandler(self._warnings)

    @property
    def session_id(self) -> str | None:
        return getattr(self._logger, "session_id", None)

    @property
    def sdk_warnings(self) -> list[str]:
        return self._warnings.records

    @property
    def completed_count(self) -> int:
        """How many chain invocations the callback actually completed and
        staged for sending, regardless of whether flush() has run yet."""
        return getattr(self.callback, "completed_count", 0)

    @property
    def activated(self) -> bool:
        return self.completed_count > 0

    def console_urls(self) -> tuple[str | None, str | None]:
        try:
            project_id = self._logger.project_id
            agent_stream_id = self._logger.agent_stream_id
            if not (project_id and agent_stream_id):
                return None, None
            project_url = f"{self._console_url.rstrip('/')}/project/{project_id}"
            return project_url, f"{project_url}/agent-streams/{agent_stream_id}"
        except Exception:
            return None, None

    def flush(self) -> None:
        """Push whatever's been staged so far. Safe to call repeatedly."""
        try:
            self._logger.flush()
        except Exception:
            pass

    def detach(self) -> None:
        """Remove this tracer's warning handler. Call only when a fresh
        "Run" click replaces this tracer with a new one."""
        logging.getLogger("splunk_ao").removeHandler(self._warnings)


def build_sao_tracer(api_key: str | None, project: str | None,
                     agent_stream: str | None = None) -> SAOTracer | None:
    """A ready-to-use SAOTracer, or None if tracing isn't configured/reachable.

    Same named limitation as app-12: splunk_ao_context is a process-wide
    singleton, fine for the single-user-at-a-time local/Streamlit-Cloud-demo
    scope this app targets.
    """
    if not api_key:
        return None

    os.environ["SPLUNK_AO_API_KEY"] = api_key
    os.environ.setdefault("SPLUNK_AO_CONSOLE_URL", DEFAULT_CONSOLE_URL)

    try:
        from splunk_ao import splunk_ao_context
        from splunk_ao.config import SplunkAOConfig
        from splunk_ao.handlers.langchain import SplunkAOCallback
    except ImportError:
        print("SAO API key is set but the `splunk-ao` package isn't installed "
             "(pip install splunk-ao) -- continuing without tracing.")
        return None

    try:
        splunk_ao_context.init(project=project or DEFAULT_PROJECT,
                               agent_stream=agent_stream or DEFAULT_AGENT_STREAM)
        logger = splunk_ao_context.get_logger_instance()
        logger.start_session()
        callback = _make_tracking_callback(SplunkAOCallback)(splunk_ao_logger=logger)
        console_url = SplunkAOConfig.get().console_url or DEFAULT_CONSOLE_URL
        return SAOTracer(callback, logger, console_url)
    except Exception as e:  # noqa: BLE001 -- init/network failure must not break a run
        print(f"SAO tracing unavailable ({type(e).__name__}: {e}) -- continuing without it.")
        return None
