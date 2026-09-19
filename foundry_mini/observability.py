"""
Optional Splunk Agent Observability (SAO) tracing — LangChain edition.

Target hierarchy, **verified empirically, not assumed** (constructed a real
`SplunkAOLogger` in `ingestion_hook` mode — bypasses the network entirely
while still exercising the real callback/commit/flush pipeline — and
inspected the captured payload directly): one **session** per "Run" click,
one **trace per role** (`cartographer`, `detector`, `triager`, `validator`,
`reporter`, `baseline`, `rule_authoring`, `remediator`), with every call that
role makes internally (each function checked, each candidate triaged, each
finding patched) showing up as its own **span nested inside that one trace**.

Getting this shape took two corrections along the way, both found by testing
rather than reading docs and assuming:

1. Naively attaching `SplunkAOCallback` per-call with its default
   `start_new_trace=True` does NOT produce "one trace per role" — it
   produces one trace per individual chain invocation (confirmed: several
   separate same-named traces, one per loop iteration, not one trace holding
   several spans). Fixed by constructing the callback with
   `start_new_trace=False` and having each role explicitly bracket its own
   work with `logger.start_trace(name=role)` / `logger.conclude()`
   (`start_role_trace()`/`end_role_trace()` below) — every `invoke_structured()`
   call made while that bracket is open then attaches as a span under the
   caller-owned trace instead of starting its own. Verified directly: one
   `start_trace(name="detector")` followed by three `chain.invoke()` calls
   with different `run_name`s produced exactly one `detector` trace with
   three top-level spans, each named after its own call, each with its own
   nested prompt/LLM sub-spans.

2. `SplunkAOLogger.traces` is never populated by the callback-based path —
   confirmed empirically: a full offline round trip (a real, well-formed
   trace captured via `ingestion_hook`, successfully flushed) still left
   `logger.traces == []` throughout. That field is populated only by the
   *manual* `start_trace()`/`add_trace()` API's own bookkeeping in other
   contexts, not by what the callback stages internally. `SAOTracer.
   activated` tracks a `_TrackingCallback` subclass's `on_chain_end`
   completions instead, confirmed the correct signal by the same test.

Still strictly opt-in and fails soft: `build_sao_tracer()` returns `None`
whenever no API key is supplied — no import of `splunk_ao` is even
attempted — and any failure once a key IS set is caught and reported, never
raised. The SDK's own trace/span-emitting calls also catch their own
failures internally and log via Python's `logging` module instead of
raising — `_WarningCollector` attaches to the `"splunk_ao"` logger so the UI
can surface those instead of them vanishing silently.
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

    `callback` is constructed with `start_new_trace=False`: it never starts
    a trace on its own. Each role is responsible for bracketing its own work
    with `start_role_trace(role)` / `end_role_trace()` so its calls attach as
    spans under one trace named after that role, instead of each call
    starting its own independent trace."""

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

    def start_role_trace(self, role: str, input_summary: str = "") -> None:
        """Open one trace for `role`. Every invoke_structured() call made
        before the matching end_role_trace() attaches as a span inside it,
        rather than starting its own trace (callback is start_new_trace=
        False) — this is what turns "one trace per call" into "one trace
        per role, calls as spans within it"."""
        try:
            self._logger.start_trace(name=role, input=input_summary or f"{role} stage")
        except Exception as e:  # noqa: BLE001 -- must not break a run
            print(f"SAO start_role_trace({role!r}) failed ({type(e).__name__}: {e}) "
                 f"-- continuing without it.")

    def end_role_trace(self, output_summary: str | None = None) -> None:
        """Close the trace opened by start_role_trace(). Always call this
        even on an error path (use try/finally) — an unconcluded trace left
        open would otherwise capture unrelated later spans as its children."""
        try:
            self._logger.conclude(output=output_summary)
        except Exception as e:  # noqa: BLE001 -- must not break a run
            print(f"SAO end_role_trace failed ({type(e).__name__}: {e}) "
                 f"-- continuing without it.")

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
        callback = _make_tracking_callback(SplunkAOCallback)(
            splunk_ao_logger=logger, start_new_trace=False)
        console_url = SplunkAOConfig.get().console_url or DEFAULT_CONSOLE_URL
        return SAOTracer(callback, logger, console_url)
    except Exception as e:  # noqa: BLE001 -- init/network failure must not break a run
        print(f"SAO tracing unavailable ({type(e).__name__}: {e}) -- continuing without it.")
        return None
