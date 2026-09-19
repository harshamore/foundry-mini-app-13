"""
Substrate + orchestrator. FindingStore/CoverageChecklist/Result carry over
from app-12 essentially unchanged (framework-agnostic). stream_harness()
replaces app-12's Pipeline.stage_*() methods: it drives the compiled
LangGraph graph via .stream(), yielding a (stage_name, summary, state) tuple
after each node completes — same per-stage progress granularity the
Streamlit UI already had in app-12, just sourced from graph state deltas
instead of Pipeline attribute mutations.
"""

from __future__ import annotations

from .finding import Verdict
from .graph import build_graph
from .rules import load_corpus


class FindingStore:
    def __init__(self):
        self._by_fp = {}

    def add_candidate(self, finding) -> bool:
        fp = finding.fingerprint()
        if fp in self._by_fp:
            return False
        self._by_fp[fp] = finding
        return True

    def all(self):
        return list(self._by_fp.values())

    def with_verdict(self, verdict):
        return [f for f in self._by_fp.values() if f.verdict == verdict]


class CoverageChecklist:
    def __init__(self, goals):
        self.items = {g: {"attempted": False, "techniques": []} for g in goals}

    def ensure(self, goal):
        self.items.setdefault(goal, {"attempted": False, "techniques": []})

    def record_attempt(self, goal, technique):
        self.ensure(goal)
        self.items[goal]["attempted"] = True
        if technique not in self.items[goal]["techniques"]:
            self.items[goal]["techniques"].append(technique)

    def complete(self):
        return all(v["attempted"] for v in self.items.values())

    def report(self):
        return {"complete": self.complete(), "items": self.items}


class Result:
    def __init__(self):
        self.security_map = {}
        self.true_positives = []
        self.demotions = []
        self.rule_gaps = []
        self.coverage = {}
        self.budget = {}
        self.n_functions = 0
        self.n_rules = 0


def _summarize(stage: str, state: dict) -> dict:
    if stage == "indexer":
        fns = state["index"].list_functions()
        return {"functions": len(fns), "names": fns}
    if stage == "cartographer":
        m = state["security_map"]
        return {"entry_points": len(m["attack_surface"]),
               "trust_boundaries": len(m["trust_boundaries"]),
               "data_flows": len(m["data_flows"]),
               "llm_augmented": m.get("llm_augmented", False)}
    if stage == "detector":
        store = state["store"]
        return {"rules": len(state["corpus"]), "total_candidates": len(store.all()),
               "rule_gaps": len(state["rule_gaps"])}
    if stage == "triager":
        store = state["store"]
        tps = store.with_verdict(Verdict.TRUE_POSITIVE)
        return {"true_positives": len(tps), "demoted": len(state["demotions"])}
    if stage == "validator":
        tps = state["store"].with_verdict(Verdict.TRUE_POSITIVE)
        return {"poc_sketches": len(tps), "exploited": 0}
    if stage == "reporter":
        return {"classified": len(state["store"].with_verdict(Verdict.TRUE_POSITIVE))}
    return {}


def stream_harness(sources: dict, llm, budget, tracer=None):
    """Generator: yields (stage_name, summary_dict, state) after each of the
    six role nodes completes. The caller (streamlit_app.py) drives progress
    UI per stage and can stop consuming early (e.g. on budget.exceeded())
    exactly like app-12 could stop between Pipeline.stage_*() calls — this
    graph is a simple linear chain with no parallel branches, so LangGraph
    only advances to the next node when the generator is asked for another
    value.
    """
    store = FindingStore()
    coverage = CoverageChecklist(["exploratory-design-review"])
    state: dict = {
        "sources": sources, "store": store, "coverage": coverage,
        "corpus": [], "demotions": [], "rule_gaps": [],
    }
    graph = build_graph(llm, budget, tracer, load_corpus)
    # No tracer.callback attached here on purpose: each role now brackets its
    # own trace directly (start_role_trace()/end_role_trace(), called from
    # inside the node functions) rather than relying on this outer
    # graph.stream() invocation to parent anything. Attaching the same
    # callback here too was a leftover from an earlier, abandoned design
    # ("one trace for the whole graph run") and conflicted with the per-role
    # brackets -- the graph call would register itself as the callback's
    # own root and swallow every nested per-role call into it instead of
    # letting each one attach to its own role's trace, which is why every
    # role except `baseline` (the one thing that runs outside this graph
    # entirely) stopped showing up.
    config = {"recursion_limit": 25}

    for chunk in graph.stream(state, config=config):
        for stage_name, update in chunk.items():
            if update:   # a node with nothing to add yields None, not {}
                state.update(update)
            yield stage_name, _summarize(stage_name, state), state


def finalize(state: dict, budget) -> Result:
    r = Result()
    r.security_map = state["security_map"]
    r.n_functions = len(state["index"].list_functions())
    r.n_rules = len(state["corpus"])
    tps = state["store"].with_verdict(Verdict.TRUE_POSITIVE)
    r.true_positives = sorted(
        tps, key=lambda x: ({"critical": 0, "high": 1, "medium": 2,
                             "low": 3}.get(x.severity, 9), x.file))
    r.demotions = state["demotions"]
    r.rule_gaps = state["rule_gaps"]
    r.coverage = state["coverage"].report()
    r.budget = budget.summary()
    return r
