"""
Structured-output schemas — one Pydantic model per role's reply shape.

This is the one piece app-12 couldn't have: LangChain's `with_structured_
output(Schema)` is a native, cross-provider mechanism for "make the model
return exactly this shape," replacing app-12's hand-built per-provider JSON-
mode / forced-tool-use plumbing in its own model.py. Every role still writes
its own real prompt (unchanged from app-12 — these are already real,
generalized prompts, not templates keyed to known bugs); only the "how do I
get JSON back reliably" plumbing changes.
"""

from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, Field


class MapEntry(BaseModel):
    symbol: str
    file: str
    line: int
    note: str = ""


class DataFlowEntry(BaseModel):
    symbol: str
    file: str
    sink: str


class CartographerOutput(BaseModel):
    entry_points: list[MapEntry] = Field(default_factory=list)
    trust_boundaries: list[MapEntry] = Field(default_factory=list)
    data_flows: list[DataFlowEntry] = Field(default_factory=list)


class RuleFire(BaseModel):
    rule_id: str
    line: int
    why: str


class RuleSweepOutput(BaseModel):
    fires: list[RuleFire] = Field(default_factory=list)


class ExploratoryFinding(BaseModel):
    symbol: str
    file: str
    vuln_class: str
    line: int
    why: str


class ExploratoryOutput(BaseModel):
    findings: list[ExploratoryFinding] = Field(default_factory=list)


class TriageCitation(BaseModel):
    leg: Literal["reachability", "trust-boundary", "impact"]
    file: Optional[str] = None
    line: int
    note: str = ""


class TriageOutput(BaseModel):
    citations: list[TriageCitation] = Field(default_factory=list)
    narrative: str = ""


class ValidatorOutput(BaseModel):
    poc: str


class ReporterOutput(BaseModel):
    title: str
    severity: Literal["critical", "high", "medium", "low"]
    business_impact: str


class BaselineFinding(BaseModel):
    file: str
    symbol: str
    vuln_class: str
    severity: str
    why: str


class BaselineOutput(BaseModel):
    findings: list[BaselineFinding] = Field(default_factory=list)


class RuleGuidance(BaseModel):
    title: str
    guidance: str
    example_bad: str = ""
    example_good: str = ""


class RuleSignal(BaseModel):
    signal: str = ""


class PatchOutput(BaseModel):
    before: str
    after: str
    why: str
