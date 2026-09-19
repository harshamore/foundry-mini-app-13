"""
Rule authoring — closing the flywheel. When exploration confirms a
vulnerability class no rule covers, this turns the gap into a real
CodeGuard-format rule: review, push into the live corpus (register_dynamic_
rule), or download the .md.

The CWE mapping and detection signal are set deterministically for known
classes — the model does not get to invent the regex that governs detection
for a class already understood well. For a genuinely novel class, the model
proposes a signal, validated by actually compiling it before use; if it
doesn't compile, a literal keyword from the gap's own pattern text is the
fallback, so the flywheel still produces a rule that fires.
"""

from __future__ import annotations

import re
from datetime import datetime

from langchain_core.prompts import ChatPromptTemplate

from .llm import invoke_structured
from .rules import Rule, register_dynamic_rule
from .schemas import RuleGuidance, RuleSignal

_SIGNAL_FOR = {
    "CWE-532": r"""log(ger|ging)?\.(info|debug|warning|error)\s*\(.*(password|passwd|pwd|secret|token|api_?key)""",
    "CWE-89": r"""(SELECT|INSERT|UPDATE|DELETE).*["']\s*\+""",
    "CWE-78": r"""(os\.system|subprocess\.\w+)\s*\(.*\+""",
    "CWE-798": r"""(sk_live_[A-Za-z0-9]{16,}|AKIA[0-9A-Z]{16})""",
}
_CLASS_NAME = {
    "CWE-532": "sensitive-data-in-logs", "CWE-89": "sql-injection",
    "CWE-78": "os-command-injection", "CWE-798": "hardcoded-secret",
}

GUIDANCE_SYSTEM = (
    "You are a secure-coding rule author. Given a vulnerability class and a "
    "described pattern, write concise prevention guidance."
)
GUIDANCE_PROMPT = ChatPromptTemplate.from_messages([
    ("system", GUIDANCE_SYSTEM), ("user", "{user_input}"),
])
SIGNAL_SYSTEM = (
    "You are a regex author for a security-rule engine. Given a "
    "vulnerability class and an observed pattern, propose a Python regex "
    "that would match it in source code."
)
SIGNAL_PROMPT = ChatPromptTemplate.from_messages([
    ("system", SIGNAL_SYSTEM), ("user", "{user_input}"),
])


def _mock_guidance(gap):
    cls = gap["vuln_class"]
    name = _CLASS_NAME.get(cls, cls.lower())

    def fn():
        return RuleGuidance(
            title=f"Prevent {name.replace('-', ' ')}",
            guidance=(f"Do not allow the pattern that leads to {cls}. "
                     f"Specifically: {gap['pattern']}. Keep sensitive values out "
                     f"of the dangerous sink: redact or omit secrets before "
                     f"logging; use parameterized APIs instead of string "
                     f"building; never place credentials in source."),
            example_bad="# risky: sensitive value flows into the sink unchanged",
            example_good="# safe: value is redacted / parameterized before the sink")
    return fn


def _signal_for(cls: str, gap: dict, llm, budget, tracer) -> str:
    if cls in _SIGNAL_FOR:
        return _SIGNAL_FOR[cls]
    model_name = getattr(llm, "model", getattr(llm, "model_name", "")) if llm else ""
    try:
        out: RuleSignal = invoke_structured(
            SIGNAL_PROMPT, llm, "rule_authoring.signal",
            {"user_input": f"Vulnerability class: {cls}\nObserved pattern: {gap.get('pattern','')}"},
            RuleSignal, model_name, budget, mock_fn=lambda: RuleSignal(signal=""),
            tracer=tracer)
        if out.signal:
            re.compile(out.signal)   # validate before trusting it
            return out.signal
    except Exception:
        pass
    return re.escape(gap.get("pattern", cls))


def draft_rule_from_gap(gap: dict, llm, budget, tracer=None) -> dict:
    cls = gap["vuln_class"]
    name = _CLASS_NAME.get(cls, cls.lower())

    if tracer is not None:
        tracer.start_role_trace("rule_authoring", f"gap: {cls}")
    try:
        signal = _signal_for(cls, gap, llm, budget, tracer)

        model_name = getattr(llm, "model", getattr(llm, "model_name", "")) if llm else ""
        drafted: RuleGuidance = invoke_structured(
            GUIDANCE_PROMPT, llm, "rule_authoring",
            {"user_input": f"Vulnerability class: {cls}\nObserved pattern: {gap['pattern']}\n"
                          f"Write a short prevention rule for developers."},
            RuleGuidance, model_name, budget, mock_fn=_mock_guidance(gap), tracer=tracer)
    finally:
        if tracer is not None:
            tracer.end_role_trace()

    filename = f"codeguard-authored-{name}.md"
    markdown = (
        "---\n"
        f"description: {drafted.title}\n"
        "languages:\n  - python\n"
        "alwaysApply: true\n"
        f"authored: {datetime.utcnow().strftime('%Y-%m-%d')}\n"
        f"cwe: {cls}\n"
        "source: discovered by Foundry exploratory hunt (rule-gap flywheel)\n"
        "---\n\n"
        f"# {drafted.title}\n\n{drafted.guidance}\n\n"
        f"## Avoid\n\n```python\n{drafted.example_bad}\n```\n\n"
        f"## Prefer\n\n```python\n{drafted.example_good}\n```\n"
    )
    rule = Rule(id=filename.replace(".md", ""), description=drafted.title,
               languages=["python"], body=markdown, vuln_class=cls, signal=signal)
    return {"filename": filename, "markdown": markdown, "rule": rule, "vuln_class": cls}


def push_rule(drafted: dict) -> None:
    register_dynamic_rule(drafted["rule"])
