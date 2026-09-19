"""
The compiled LangGraph StateGraph — one node per Foundry Security Spec role,
same order as app-12's Pipeline stages: Indexer (deterministic) ->
Cartographer -> Detector -> Triager -> Validator -> Reporter -> END.

HarnessState carries mutable substrate objects (FindingStore, CoverageChecklist
— defined in pipeline.py) by reference, mutated in place by each node, the
same imperative shape app-12's Pipeline used — LangGraph's default state
merge (a node's returned partial dict overwrites those keys; everything else
stays the same object reference) makes this a natural fit for what is
fundamentally a sequential, stateful pipeline, not a branching agent.
"""

from __future__ import annotations

from typing import Any, TypedDict

from langgraph.graph import END, StateGraph

from .index import build_index


class HarnessState(TypedDict, total=False):
    sources: dict
    index: Any
    security_map: dict
    corpus: list
    store: Any
    coverage: Any
    demotions: list
    rule_gaps: list


def indexer_node(state: HarnessState) -> dict:
    index = build_index(state["sources"])
    if not index.list_functions():
        raise RuntimeError("Index gate failed: no functions found (FR-003). "
                           "Is the input valid Python with function definitions?")
    return {"index": index}


def build_graph(llm, budget, tracer, load_corpus_fn):
    """Factory: closes over this run's llm/budget/tracer (all None-able for
    offline/mock mode, except budget) plus the CodeGuard corpus loader."""
    from .cartographer import build_cartographer_node
    from .detector import build_detector_node
    from .reporter import build_reporter_node
    from .triager import build_triager_node
    from .validator import build_validator_node

    g = StateGraph(HarnessState)
    g.add_node("indexer", indexer_node)
    g.add_node("cartographer", build_cartographer_node(llm, budget, tracer))
    g.add_node("detector", build_detector_node(llm, budget, tracer, load_corpus_fn))
    g.add_node("triager", build_triager_node(llm, budget, tracer))
    g.add_node("validator", build_validator_node(llm, budget, tracer))
    g.add_node("reporter", build_reporter_node(llm, budget, tracer))

    g.set_entry_point("indexer")
    g.add_edge("indexer", "cartographer")
    g.add_edge("cartographer", "detector")
    g.add_edge("detector", "triager")
    g.add_edge("triager", "validator")
    g.add_edge("validator", "reporter")
    g.add_edge("reporter", END)

    return g.compile()
