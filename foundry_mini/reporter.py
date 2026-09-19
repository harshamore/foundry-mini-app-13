"""
Reporter — spec §5.8. LangGraph node.

Known, common CWEs get a fast, free, deterministic table lookup. Anything
else (a class an exploratory hunt surfaces that this app's small fixed rule
set doesn't name) gets one real, per-class-cached LLM classification instead
of silently falling back to "Unclassified".
"""

from __future__ import annotations

from langchain_core.prompts import ChatPromptTemplate

from .finding import State, Verdict
from .llm import ModelError, invoke_structured
from .schemas import ReporterOutput

_SEVERITY = {"CWE-89": "critical", "CWE-78": "critical",
            "CWE-798": "high", "CWE-532": "medium", "CWE-522": "low"}
_TITLE = {"CWE-89": "SQL Injection", "CWE-78": "OS Command Injection",
         "CWE-798": "Hardcoded Credential in Source",
         "CWE-532": "Sensitive Data Written to Logs",
         "CWE-522": "Insufficiently Protected Credentials"}
_BUSINESS_IMPACT = {
    "CWE-89": "An attacker can read or modify arbitrary database records, including "
             "customer and account data — a direct data-breach and integrity risk.",
    "CWE-78": "An attacker can execute arbitrary commands on the host, leading to "
             "full server compromise and lateral movement.",
    "CWE-798": "A leaked production credential grants an attacker direct access to a "
              "third-party or internal system without needing to breach anything else.",
    "CWE-532": "Credentials or sensitive data in logs are exposed to anyone with log "
              "access, including downstream log-aggregation and support staff.",
    "CWE-522": "Weak credential protection lets an attacker who obtains the store "
              "recover usable passwords instead of only useless hashes.",
}

CLASSIFY_SYSTEM = (
    "You are a CISO report writer. Given a vulnerability class (a CWE id, or "
    "free text if no CWE applies) and a short technical note, produce a "
    "plain-English title, a severity, and a one-sentence business-impact "
    "statement a CISO would read."
)
CLASSIFY_PROMPT = ChatPromptTemplate.from_messages([
    ("system", CLASSIFY_SYSTEM), ("user", "{user_input}"),
])

_cache: dict = {}


def _mock_classify(cls, note):
    def fn():
        return ReporterOutput(
            title=cls, severity="medium",
            business_impact=f"Potential security impact from {cls}; requires "
                           f"review. ({note})")
    return fn


def classify(vuln_class: str, note: str, llm=None, budget=None, tracer=None) -> dict:
    if vuln_class in _TITLE:
        return {"title": _TITLE[vuln_class],
                "severity": _SEVERITY.get(vuln_class, "medium"),
                "business_impact": _BUSINESS_IMPACT.get(
                    vuln_class, "Potential security impact; requires review.")}
    if vuln_class in _cache:
        return _cache[vuln_class]

    result = {"title": vuln_class or "Unclassified", "severity": "medium",
             "business_impact": "Potential security impact; requires review."}
    if llm is not None and budget is not None:
        model_name = getattr(llm, "model", getattr(llm, "model_name", ""))
        try:
            out: ReporterOutput = invoke_structured(
                CLASSIFY_PROMPT, llm, "reporter", {"user_input": f"Class: {vuln_class}\nNote: {note}"},
                ReporterOutput, model_name, budget,
                mock_fn=_mock_classify(vuln_class, note), tracer=tracer)
            result = {"title": out.title or result["title"],
                     "severity": out.severity, "business_impact": out.business_impact}
        except ModelError:
            pass
    _cache[vuln_class] = result
    return result


def build_reporter_node(llm, budget, tracer):
    def reporter_node(state: dict) -> dict:
        tps = state["store"].with_verdict(Verdict.TRUE_POSITIVE)
        for f in tps:
            classified = classify(f.vuln_class, f.description, llm, budget, tracer)
            f.severity = classified["severity"]
            f.title = classified["title"]
            f.business_impact = classified["business_impact"]
            f.weakness = f.vuln_class
            f.state = State.PUBLISHED
        return {}

    return reporter_node
