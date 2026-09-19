"""
Validator — spec §5.6. LangGraph node.

No live execution of fetched/pasted code — running arbitrary untrusted code
in a Streamlit Cloud free-tier app is a real code-execution risk, not just a
scope cut. `exploited` always stays False (Principle VII: no testbed -> no
execution claim). The model sketches a plausible PoC narrative instead.
"""

from __future__ import annotations

from langchain_core.prompts import ChatPromptTemplate

from .llm import ModelError, invoke_structured
from .schemas import ValidatorOutput

VALIDATOR_SYSTEM = (
    "You are writing a short proof-of-concept SKETCH for a confirmed "
    "vulnerability finding: a paragraph of attacker-perspective narrative "
    "(what input you would send, what happens as a result), not runnable "
    "exploit code and not a claim that it was executed — no live testbed is "
    "configured for this run, so this is illustrative only."
)
VALIDATOR_PROMPT = ChatPromptTemplate.from_messages([
    ("system", VALIDATOR_SYSTEM), ("user", "{user_input}"),
])


def _mock_poc(finding):
    def fn():
        return ValidatorOutput(
            poc=f"An attacker exploiting {finding.vuln_class} at "
               f"{finding.symbol}() would supply crafted input at the cited "
               f"reachability point to trigger the cited impact.")
    return fn


def poc_sketch(finding, llm, budget, tracer=None) -> str:
    user_input = (f"Finding: {finding.vuln_class} in {finding.symbol} "
                 f"({finding.file}).\nInvestigation: {finding.investigation}\n"
                 f"Write the PoC sketch.")
    model_name = getattr(llm, "model", getattr(llm, "model_name", "")) if llm else ""
    try:
        out: ValidatorOutput = invoke_structured(
            VALIDATOR_PROMPT, llm, "validator", {"user_input": user_input}, ValidatorOutput,
            model_name, budget, mock_fn=_mock_poc(finding), tracer=tracer)
        return out.poc or "(model returned no PoC narrative)"
    except ModelError:
        return "(PoC sketch unavailable — model call failed for this finding)"


def build_validator_node(llm, budget, tracer):
    def validator_node(state: dict) -> dict:
        from .finding import Verdict
        tps = state["store"].with_verdict(Verdict.TRUE_POSITIVE)
        if tracer is not None:
            tracer.start_role_trace("validator", f"{len(tps)} confirmed finding(s)")
        try:
            for f in tps:
                f.poc = poc_sketch(f, llm, budget, tracer)
                f.exploited = False   # Principle VII: no testbed -> no execution claim
        finally:
            if tracer is not None:
                tracer.end_role_trace()
        return {}

    return validator_node
