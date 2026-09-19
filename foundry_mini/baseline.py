"""
Baseline scanner — the "raw LLM, no Foundry spec" comparison.

Deliberately the naive approach a competent person would try first: hand the
whole code to the model, ask it to find vulnerabilities, take the answer at
face value. NO indexer, NO security map, NO rule corpus, NO evidence gate, NO
fingerprinting, NO validation. This is a GOOD-FAITH prompt, not a strawman —
structured output with locations and severity, what a sensible engineer
would write, same as app-12's version.
"""

from __future__ import annotations

from langchain_core.prompts import ChatPromptTemplate

from .llm import invoke_structured
from .schemas import BaselineOutput

BASELINE_SYSTEM = (
    "You are a senior application security engineer. You will be given the full "
    "source of a program. Find the security vulnerabilities in it. For each one, "
    "report the file, the function or symbol, the vulnerability class (a CWE id "
    "if you can), a severity (critical/high/medium/low), and a one-sentence "
    "explanation. If you find nothing, return an empty list."
)
BASELINE_PROMPT = ChatPromptTemplate.from_messages([
    ("system", BASELINE_SYSTEM), ("user", "{user_input}"),
])


def _mock_baseline(sources):
    """
    Tuned to behave like a STRONG model would on the built-in sample: catches
    the obvious data-flow bugs and a visible hardcoded key, plausibly MISSES
    the subtlest issue (the password written to logs — exactly why the
    harness routes that class to exploration), and ADDS a confident,
    unsubstantiated finding citing a function that doesn't exist. That last
    item is the honest crux: the raw approach has no way to notice its own
    citation is fabricated.
    """
    import re

    def fn():
        findings = []
        joined = "\n".join(sources.values())
        if re.search(r'(SELECT|INSERT|UPDATE|DELETE).*["\']\s*\+', joined, re.I) or \
           re.search(r'["\']\s*\+\s*\w+', joined):
            findings.append({"file": _file_of(sources, "execute") or list(sources)[0],
                             "symbol": "find_user_by_name", "vuln_class": "CWE-89",
                             "severity": "critical",
                             "why": "User input is concatenated directly into a SQL query."})
        if re.search(r'(system|call|Popen)\(', joined):
            findings.append({"file": _file_of(sources, "subprocess") or list(sources)[0],
                             "symbol": "export_report", "vuln_class": "CWE-78",
                             "severity": "critical",
                             "why": "User input is passed into a shell command."})
        if re.search(r'sk_live_|AKIA|api_?key\s*=', joined, re.I):
            findings.append({"file": _file_of(sources, "AKIA") or list(sources)[0],
                             "symbol": "AWS_ACCESS_KEY_ID", "vuln_class": "CWE-798",
                             "severity": "high",
                             "why": "A secret key appears hardcoded in the source."})
        findings.append({"file": list(sources)[0], "symbol": "encrypt_payload",
                         "vuln_class": "CWE-327", "severity": "medium",
                         "why": "The encryption routine appears to use a weak cipher."})
        return BaselineOutput(findings=findings)
    return fn


def _file_of(sources, needle):
    for f, src in sources.items():
        if needle in src:
            return f
    return None


def run_baseline(sources, llm, budget, tracer=None):
    """One model call over the whole codebase. Returns a list of plain dict
    findings exactly as the model reported them — nothing verified, nothing
    filtered."""
    corpus_text = "\n\n".join(f"### FILE: {name}\n{src}" for name, src in sources.items())
    user_input = f"Here is the full source:\n\n{corpus_text}"
    model_name = getattr(llm, "model", getattr(llm, "model_name", "")) if llm else ""
    out: BaselineOutput = invoke_structured(
        BASELINE_PROMPT, llm, "baseline", {"user_input": user_input}, BaselineOutput, model_name,
        budget, mock_fn=_mock_baseline(sources), tracer=tracer)

    findings = [f.model_dump() for f in out.findings]
    for f in findings:
        f["_symbol_exists"] = _symbol_present(sources, f.get("symbol", ""))
    return findings


def _symbol_present(sources, symbol):
    if not symbol:
        return False
    for src in sources.values():
        if symbol in src:
            return True
    return False
