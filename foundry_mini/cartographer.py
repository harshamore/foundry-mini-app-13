"""
Cartographer — spec §5.3. LangGraph node.

Same two-layer design as app-12: a heuristic substring scan (cheap,
deterministic, non-empty per FR-036a) as the floor, and a real LLM pass as
the primary source of truth when a live model is available. Logic ported
verbatim from app-12/foundry_mini/cartographer.py; only the "ask the model"
plumbing changed from Model.ask_json() to a LangChain chain.
"""

from __future__ import annotations

from langchain_core.prompts import ChatPromptTemplate

from .llm import ModelError, invoke_structured
from .schemas import CartographerOutput

ENTRY_HINTS = ("request", "params", "args", "form", "query")
SINK_HINTS = {
    "execute": "database query (SQL sink)",
    "system": "shell execution (command sink)",
    "call": "shell execution (command sink)",
    "Popen": "shell execution (command sink)",
    "info": "log sink",
    "debug": "log sink",
}

CARTOGRAPHER_SYSTEM = (
    "You are a security architect mapping a codebase's attack surface. You "
    "are given every file in the target, with real line numbers. Identify:\n"
    "1. entry_points - functions/handlers that receive externally-controlled "
    "input, via ANY mechanism: HTTP route/decorator, CLI argument, "
    "environment variable, file read, queue/message consumer, "
    "deserialization, form field. Do not limit yourself to functions with "
    "request-like parameter names.\n"
    "2. trust_boundaries - for each entry point, the specific line where "
    "untrusted data starts being treated as trusted (used in a query, a "
    "command, a path, a template, etc. without validation).\n"
    "3. data_flows - lines where a value reaches a sensitive sink: database "
    "query, shell/process exec, filesystem write, network call, logging "
    "call, deserialization, template render, or crypto routine.\n"
    "Cite every item to a real symbol, file, and line number taken from the "
    "text you were given. Never invent a line number."
)

CARTOGRAPHER_PROMPT = ChatPromptTemplate.from_messages([
    ("system", CARTOGRAPHER_SYSTEM),
    ("user", "{user_input}"),
])


def _heuristic_map(index) -> dict:
    entry_points, trust_boundaries, data_flows = [], [], []
    for symbol in index.list_functions():
        body = index.get_function_body(symbol)
        meta = index.find_symbol(symbol)
        if any(h in body for h in ENTRY_HINTS):
            entry_points.append({
                "symbol": symbol, "file": meta["file"], "line": meta["line"],
                "note": "accepts request-derived input (heuristic: parameter-like name)",
            })
            trust_boundaries.append({
                "symbol": symbol, "file": meta["file"], "line": meta["line"],
                "note": "untrusted request data enters trusted processing here",
            })
        for needle, kind in SINK_HINTS.items():
            if needle + "(" in body or "." + needle in body:
                data_flows.append({"symbol": symbol, "file": meta["file"], "sink": kind})
    return {
        "architecture": f"{len(index.list_functions())} functions indexed in target",
        "attack_surface": entry_points,
        "trust_boundaries": trust_boundaries,
        "data_flows": data_flows,
    }


def _valid_entry(e: dict, index, line_key="line") -> bool:
    f = e.get("file")
    if f not in index.sources:
        return False
    line = e.get(line_key)
    if not isinstance(line, int):
        return False
    return 1 <= line <= len(index.sources[f].splitlines())


def _llm_map(index, llm, budget, tracer) -> dict:
    files_block = "\n\n".join(
        f"### FILE: {f}\n{index.numbered_file(f)}" for f in index.sources)
    user_input = (f"Functions defined in this target: {index.list_functions()}\n\n"
                 f"{files_block}")
    out: CartographerOutput = invoke_structured(
        CARTOGRAPHER_PROMPT, llm, "cartographer", {"user_input": user_input}, CartographerOutput,
        getattr(llm, "model", getattr(llm, "model_name", "")), budget, tracer=tracer)

    entries = [e.model_dump() for e in out.entry_points if _valid_entry(e.model_dump(), index)]
    bounds = [e.model_dump() for e in out.trust_boundaries if _valid_entry(e.model_dump(), index)]
    flows = [e.model_dump() for e in out.data_flows if e.file in index.sources]
    return {"attack_surface": entries, "trust_boundaries": bounds, "data_flows": flows}


def _dedup(items, key):
    seen, out = set(), []
    for it in items:
        k = key(it)
        if k in seen:
            continue
        seen.add(k)
        out.append(it)
    return out


def _merge(heuristic: dict, llm_map: dict) -> dict:
    return {
        "architecture": heuristic["architecture"],
        "attack_surface": _dedup(
            heuristic["attack_surface"] + llm_map["attack_surface"],
            key=lambda e: (e.get("symbol"), e.get("file"), e.get("line"))),
        "trust_boundaries": _dedup(
            heuristic["trust_boundaries"] + llm_map["trust_boundaries"],
            key=lambda e: (e.get("symbol"), e.get("file"), e.get("line"))),
        "data_flows": _dedup(
            heuristic["data_flows"] + llm_map["data_flows"],
            key=lambda e: (e.get("symbol"), e.get("file"), e.get("sink"))),
        "llm_augmented": True,
    }


def build_security_map(index, llm, budget, tracer=None) -> dict:
    heuristic = _heuristic_map(index)
    if llm is None:
        heuristic["llm_augmented"] = False
        return heuristic
    try:
        llm_map = _llm_map(index, llm, budget, tracer)
    except ModelError:
        heuristic["llm_augmented"] = False
        return heuristic
    return _merge(heuristic, llm_map)


def build_cartographer_node(llm, budget, tracer):
    """Factory: closes over this run's llm/budget/tracer, returns the plain
    `state -> partial state update` function LangGraph calls."""

    def cartographer_node(state: dict) -> dict:
        security_map = build_security_map(state["index"], llm, budget, tracer)
        return {"security_map": security_map}

    return cartographer_node
