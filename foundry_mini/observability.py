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

Target hierarchy, richer than app-12's flat one, "for free" from LangChain's
own callback propagation: one session per "Run" click, one TRACE per graph
invocation (the whole harness pipeline is "one complete interaction"), each
role's own chain call as a named SPAN nested inside via its run_name/tags
(llm.py's invoke_structured()). UNVERIFIED, flagged not assumed: whether
LangGraph node-internal chain invocations propagate the top-level config's
callbacks/tags far enough down to produce correctly-nested, correctly-named
spans, or whether every role flattens into one undifferentiated trace —
confirm the actual trace tree the first time this runs live with a real key.
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


class SAOTracer:
    """One of these per SAO session — built for the main "Run" click, then
    reused (via st.session_state) by the two later follow-on actions too, so
    every real LLM call in a session gets traced, not just the main run.
    Wraps a SplunkAOCallback; LangChain attaches it via config= at each
    chain.invoke() (llm.py), so this class's own job is bookkeeping
    (warnings, console urls, diagnostic counts), not manual span emission."""

    def __init__(self, callback: Any, logger: Any, console_url: str):
        self.callback = callback
        self._logger = logger
        self._console_url = console_url
        self.pending_before_flush = 0
        self._warnings = _WarningCollector()
        logging.getLogger("splunk_ao").addHandler(self._warnings)

    @property
    def session_id(self) -> str | None:
        return getattr(self._logger, "session_id", None)

    @property
    def sdk_warnings(self) -> list[str]:
        return self._warnings.records

    @property
    def activated(self) -> bool:
        """True once at least one trace has actually been built locally by
        the callback. Checked against the logger's own trace list rather
        than a manually-set flag, since spans are now emitted by
        SplunkAOCallback internally, not by code in this module."""
        return len(getattr(self._logger, "traces", None) or []) > 0

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
        """Push whatever's been logged so far. Safe to call repeatedly.
        Records pending_before_flush the same way app-12 did: the trace
        count right before flushing tells apart "nothing was ever built"
        (0) from "something was built but never sent" (>0)."""
        self.pending_before_flush = len(getattr(self._logger, "traces", None) or [])
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
        callback = SplunkAOCallback(splunk_ao_logger=logger)
        console_url = SplunkAOConfig.get().console_url or DEFAULT_CONSOLE_URL
        return SAOTracer(callback, logger, console_url)
    except Exception as e:  # noqa: BLE001 -- init/network failure must not break a run
        print(f"SAO tracing unavailable ({type(e).__name__}: {e}) -- continuing without it.")
        return None
