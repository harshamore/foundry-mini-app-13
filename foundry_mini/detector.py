"""
Detector — spec §5.4. LangGraph node: rule sweep + secret scan (FR-039,
deterministic) + exploratory hunt (FR-040) + generic rule-gap detection
(FR-042). Ported from app-12/foundry_mini/detector.py; secret_scan is
unchanged (regex, no model involved either build).
"""

from __future__ import annotations

import re

from langchain_core.prompts import ChatPromptTemplate

from .finding import Finding
from .llm import invoke_structured
from .schemas import ExploratoryOutput, RuleSweepOutput
from .textutil import line_of_offset

_SECRET_PATTERNS = [
    (r"sk_live_[A-Za-z0-9]{16,}", "Stripe live secret key"),
    (r"AKIA[0-9A-Z]{16}", "AWS access key id"),
    (r"-----BEGIN (RSA |EC )?PRIVATE KEY-----", "private key"),
    (r"gh[pousr]_[A-Za-z0-9]{16,}", "GitHub token"),
    (r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", "JWT"),
]


def secret_scan(index, store) -> int:
    added = 0
    for pattern, label in _SECRET_PATTERNS:
        rx = re.compile(pattern)
        for f, src in index.sources.items():
            for i, line in enumerate(src.splitlines(), start=1):
                if rx.search(line):
                    m = re.match(r"\s*([A-Za-z_][A-Za-z0-9_]*)\s*=", line)
                    symbol = m.group(1) if m else f"secret_L{i}"
                    finding = Finding(file=f, symbol=symbol, vuln_class="CWE-798",
                                      description=f"hardcoded {label} in source",
                                      technique="secret-scan")
                    if store.add_candidate(finding):
                        added += 1
    return added


# ------------------------------------------------------------- rule sweep ---
RULE_SWEEP_SYSTEM = (
    "You are a security detector applying a fixed rule corpus to one "
    "function. For each rule below, decide whether the function's OWN code "
    "(not a hypothetical) exhibits that rule's vulnerability class. Cite the "
    "real line number (from the numbered text given) where the pattern "
    "appears. Only include a rule in your reply if it actually fires on "
    "this function."
)
RULE_SWEEP_PROMPT = ChatPromptTemplate.from_messages([
    ("system", RULE_SWEEP_SYSTEM), ("user", "{user_input}"),
])


def _rule_by_id(corpus, rule_id):
    for r in corpus:
        if r.id == rule_id:
            return r
    return None


def _mock_rule_sweep(index, symbol, corpus):
    meta = index.find_symbol(symbol)
    body = index.get_function_body(symbol)

    def fn():
        fires = []
        for rule in corpus:
            m = re.search(rule.signal, body, re.IGNORECASE | re.DOTALL)
            if m:
                fires.append({"rule_id": rule.id,
                             "line": line_of_offset(body, m.start(), meta["line"]),
                             "why": f"matches {rule.vuln_class} pattern"})
        return RuleSweepOutput(fires=fires)
    return fn


def rule_sweep(index, corpus, llm, budget, store, tracer=None) -> int:
    added = 0
    if not corpus:
        return added
    rules_block = "\n".join(
        f"- {r.id} ({r.vuln_class}): {r.description}" for r in corpus)
    chain = (RULE_SWEEP_PROMPT | llm) if llm is not None else None
    model_name = getattr(llm, "model", getattr(llm, "model_name", "")) if llm else ""
    for symbol in index.list_functions():
        meta = index.find_symbol(symbol)
        user_input = (f"RULES:\n{rules_block}\n\n"
                     f"FUNCTION {symbol} in {meta['file']} "
                     f"(callers: {index.get_callers(symbol)}), real line numbers:\n"
                     f"{index.numbered_body(symbol)}")
        out: RuleSweepOutput = invoke_structured(
            chain, "detector.rule_sweep", {"user_input": user_input},
            RuleSweepOutput, model_name, budget,
            mock_fn=_mock_rule_sweep(index, symbol, corpus), tracer=tracer)
        for hit in out.fires:
            rule = _rule_by_id(corpus, hit.rule_id)
            if rule is None:
                continue
            f = Finding(file=meta["file"], symbol=symbol, vuln_class=rule.vuln_class,
                        description=hit.why or f"rule {rule.id} fired",
                        technique=rule.id)
            if store.add_candidate(f):
                added += 1
    return added


# --------------------------------------------------------- exploratory hunt -
EXPLORATORY_SYSTEM = (
    "You are an exploratory security agent. Reason about THIS target's "
    "design and report vulnerabilities no generic rule would catch — logic "
    "flaws, sensitive data reaching an unexpected sink, missing "
    "authorization, unsafe deserialization, path traversal, SSRF, or "
    "anything else specific to how these functions are wired together. Cite "
    "a real line number from the function text given; use a CWE id for "
    "vuln_class when one applies. If you find nothing, return an empty list."
)
EXPLORATORY_PROMPT = ChatPromptTemplate.from_messages([
    ("system", EXPLORATORY_SYSTEM), ("user", "{user_input}"),
])


def _mock_exploratory(index):
    def fn():
        findings = []
        for symbol in index.list_functions():
            body = index.get_function_body(symbol)
            meta = index.find_symbol(symbol)
            m = re.search(r"log(ger|ging)?\.\w+\(.*(password|passwd|pwd|secret|token)",
                         body, re.IGNORECASE | re.DOTALL)
            if m:
                findings.append({"symbol": symbol, "file": meta["file"],
                                 "vuln_class": "CWE-532",
                                 "line": line_of_offset(body, m.start(), meta["line"]),
                                 "why": "plaintext credential reaches a log sink; "
                                        "exposed to anyone with log read access"})
        return ExploratoryOutput(findings=findings)
    return fn


def exploratory_hunt(index, llm, budget, store, coverage, corpus, tracer=None):
    user_input = "Target functions, real line numbers:\n\n" + "\n\n".join(
        f"### {s} — {index.find_symbol(s)['file']}\n{index.numbered_body(s)}"
        for s in index.list_functions())
    chain = (EXPLORATORY_PROMPT | llm) if llm is not None else None
    model_name = getattr(llm, "model", getattr(llm, "model_name", "")) if llm else ""
    out: ExploratoryOutput = invoke_structured(
        chain, "detector.exploratory", {"user_input": user_input},
        ExploratoryOutput, model_name, budget,
        mock_fn=_mock_exploratory(index), tracer=tracer)

    covered_classes = {r.vuln_class for r in corpus}
    added, gaps = 0, []
    for item in out.findings:
        f = Finding(file=item.file, symbol=item.symbol, vuln_class=item.vuln_class,
                    description=item.why, technique="exploratory")
        if store.add_candidate(f):
            added += 1
            coverage.record_attempt("exploratory-design-review", "exploratory")
            if f.vuln_class not in covered_classes:
                gaps.append({
                    "finding": f.symbol, "vuln_class": f.vuln_class,
                    "pattern": item.why or "pattern not covered by the rule corpus",
                    "action": f"author a CodeGuard rule for {f.vuln_class} so the "
                             f"next sweep catches this class systematically",
                })
    return added, gaps


def build_detector_node(llm, budget, tracer, load_corpus_fn):
    """Factory: closes over this run's llm/budget/tracer plus the rule
    corpus loader (rules.py's load_corpus), returns the LangGraph node."""

    def detector_node(state: dict) -> dict:
        index = state["index"]
        store = state["store"]
        coverage = state["coverage"]
        corpus = load_corpus_fn()
        for r in corpus:
            coverage.ensure(f"triage:{r.vuln_class}")
        coverage.ensure("triage:CWE-798")

        rule_sweep(index, corpus, llm, budget, store, tracer)
        secret_scan(index, store)
        _, gaps = exploratory_hunt(index, llm, budget, store, coverage, corpus, tracer)
        coverage.record_attempt("triage:CWE-798", "secret-scan")

        return {"corpus": corpus, "rule_gaps": gaps}

    return detector_node
