"""Deterministic APC policy for an AAuth Supervision Server.

The policy implements the Bounded Agents (Agentic Principal Chain) authorization
model on top of what Supervision -00 gives an SS:

  * Classification: each act is mapped to a semantic action class by ordered,
    declarative rules over the resource, operation, scope, tool, and (when the
    PS forwards them) the resource-asserted R3 `parameters` and `result`.
  * Provenance: every classification records where its evidence came from:
    `resource` (R3 proposal forwarded by the PS), `configured` (resource identity
    only) or `agent` (justification, permission parameters, audit records); an act
    replayed to this SS is marked as replayed. Agent-asserted evidence can only make a
    class more severe, never less (a compromised agent cannot talk its way down), and
    missing evidence never makes it less either: a class assumed for missing data is
    also each class the data could have given.
  * Composition closure: prohibited pairs and ordered sequences of classes over
    the agent's history (its mission, its acts outside missions, and as uncertain its
    other missions, other instances of its provider and open acts). A violation
    established on certain evidence is denied; one that depends on uncertain evidence
    is put to the person (`ask`).
  * Budgets: ceilings on count and amount per class, and at metered resources (AAuth
    Budgets), per mission and for the acts outside missions.
  * Intent: resources and tools outside the approved mission are asked.
  * Reach: the person's earlier answers (`apply`) settle matching asks, an allow
    or a "no", but never override the SS's own deny, and cover a composition only if
    the answer was given for that composition (and a "may" never covers a certain
    one).

No model is consulted. The same inputs always give the same decision.
"""

from __future__ import annotations

import bisect
import collections
import fnmatch
import heapq
import math
import re
import time
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass, field, replace
from datetime import UTC
from typing import Any, Protocol, runtime_checkable

from . import markdown as md
from .store import (
    EXP_SKEW,
    PERSON_TOKEN,
    STAMP_SLACK,
    Alias,
    HistoryEntry,
    Mission,
    Reach,
    elsewhere_copy,
)
from .store import iso_to_epoch as _iso_to_epoch

# ------------------------------------------------------------------ config


@dataclass
class Rule:
    cls: str
    resource: str = "*"
    operation: str | None = None
    scope: str | None = None
    tool: str | None = None
    result_contains_any: list[str] | None = None
    param_domain_not_in: dict[str, list[str]] | None = None
    param_gt: dict[str, int] | None = None
    param_in: dict[str, list[str]] | None = None
    amount_param: str | None = None
    if_unknown: str | None = None

    @property
    def needs_data(self) -> bool:
        return bool(self.result_contains_any or self.param_domain_not_in or self.param_gt
                    or self.param_in)


@dataclass
class Budget:
    max_count: int | None = None
    max_amount: int | None = None


@dataclass
class ResourceBudget:
    """The person's ceiling at one metered resource, per mission and for the acts outside
    missions (AAuth Budgets).

    In the resource's own `unit` and `decimals`: Budgets has the resource denominate, and
    a figure in another scale is never converted, only refused as incomparable."""

    unit: str
    decimals: int
    max_amount: int

    @property
    def denomination(self) -> str:
        return f"{self.unit}/{self.decimals}"


@dataclass
class PolicyConfig:
    severity: list[str] = field(default_factory=list)  # least -> most severe
    high_impact: set[str] = field(default_factory=set)
    rules: list[Rule] = field(default_factory=list)
    prohibited_pairs: list[tuple[str, str]] = field(default_factory=list)
    prohibited_sequences: list[tuple[str, ...]] = field(default_factory=list)
    budgets: dict[str, Budget] = field(default_factory=dict)
    # AAuth Budgets: ceilings at metered resources, per mission and outside missions, keyed by the resource's
    # server identifier. Checked against the `budget` offers and `budget_consumed` records
    # the resource puts in its resource tokens.
    resource_budgets: dict[str, ResourceBudget] = field(default_factory=dict)
    deny_resources: list[str] = field(default_factory=list)
    allowed_tools: list[str] = field(default_factory=lambda: ["*"])
    ask_tools: list[str] = field(default_factory=list)
    allow_unlisted_resources: bool = False
    clarify_missing_justification: bool = False
    max_mission_seconds: int | None = None
    default_class: str = "unclassified"
    ask_on_mission_update: bool = False
    composition_on_certain: str = "deny"  # deny | ask
    # Non-spec extension (AAuth #256): the request member carrying the resource-asserted R3
    # proposal. None (the default) is spec-only Supervision -00: the member is ignored.
    r3_member: str | None = None
    # Resources (patterns, like `deny_resources`) that may serve a request on a person
    # token alone (Person Identity Access): a person token issued for one is an act.
    serves_on_identity: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> PolicyConfig:
        """Build a config from its JSON form. A malformed file raises ValueError naming the
        member; nothing is silently ignored, because a misspelt key in a security policy
        (`high_imapct`) would otherwise quietly drop a protection."""
        _check_policy_shape(d)
        rules = []
        for r in d.get("rules", []):
            r = dict(r)
            r["cls"] = r.pop("class")
            rules.append(Rule(**r))
        return cls(
            severity=list(d.get("severity", [])),
            high_impact=set(d.get("high_impact", [])),
            rules=rules,
            prohibited_pairs=[tuple(p) for p in d.get("prohibited_pairs", [])],  # type: ignore[misc]
            prohibited_sequences=[tuple(s) for s in d.get("prohibited_sequences", [])],
            budgets={k: Budget(**v) for k, v in d.get("budgets", {}).items()},
            resource_budgets={k: ResourceBudget(**v)
                              for k, v in d.get("resource_budgets", {}).items()},
            deny_resources=list(d.get("deny_resources", [])),
            allowed_tools=list(d.get("allowed_tools", ["*"])),
            ask_tools=list(d.get("ask_tools", [])),
            allow_unlisted_resources=bool(d.get("allow_unlisted_resources", False)),
            clarify_missing_justification=bool(d.get("clarify_missing_justification", False)),
            max_mission_seconds=d.get("max_mission_seconds"),
            default_class=d.get("default_class", "unclassified"),
            ask_on_mission_update=bool(d.get("ask_on_mission_update", False)),
            composition_on_certain=d.get("composition_on_certain", "deny"),
            r3_member=d.get("r3_member"),
            serves_on_identity=list(d.get("serves_on_identity", [])),
        )

    def rank(self, cls: str) -> int:
        return self.severity.index(cls) if cls in self.severity else -1


# The tools a proposal's ask names one by one, each cut to MAX_TOOL_SHOWN characters; the
# rest are counted.
MAX_TOOLS_NAMED = 20
MAX_TOOL_SHOWN = 64

# Core, Server Identifiers: a lowercase https host (A-labels for IDNs), and nothing else;
# a name DNS can carry (RFC 1035 2.3.4: labels of 63 octets or less, names of 255 octets
# or less, which is 253 characters written with dots).
_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
SERVER_ID = re.compile(rf"https://(?=[a-z0-9.-]{{1,253}}(?![a-z0-9.-])){_LABEL}(?:\.{_LABEL})*")


def _is_str_list(v: Any) -> bool:
    return isinstance(v, list) and all(isinstance(x, str) for x in v)


def _is_count(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and v >= 0


def _finite(v: Any) -> bool:
    """A JSON number the SS can compare a value with: finite, and within the float range
    (an integer past it has no float, and comparing would fail)."""
    if isinstance(v, bool) or not isinstance(v, int | float):
        return False
    try:
        return math.isfinite(v)
    except OverflowError:
        return False


# The longest `max_mission_seconds` a policy may set: ten years. Far past it, the mission's
# `expires_at` has no date to be written as.
MAX_MISSION_SECONDS = 10 * 366 * 86400
# The largest `decimals` of a metered resource's ceiling.
MAX_DECIMALS = 18


# Whether a resource pattern can match a server identifier (`https://` and a lowercase
# host, no port or path; patterns compare case-sensitively). A pattern with no wildcard is
# an identifier. Otherwise the pattern, read as `fnmatch` reads it, is walked against the
# grammar of an identifier (`https://`, then labels of letters and digits with inner
# hyphens, dots between), breadth first, and an identifier it reaches is checked as a
# whole (the walk leaves label and name lengths to that check).
_ID_CHARS = "abcdefghijklmnopqrstuvwxyz0123456789.-:/"
_HOST_AT = len("https://")  # the grammar's state at the start of a label
_IN_LABEL = _HOST_AT + 1  # after a letter or digit: an identifier may end here
_AFTER_HYPHEN = _HOST_AT + 2


def _id_step(q: int, ch: str) -> int | None:
    """The identifier grammar's state after `ch` in state `q`, None if `ch` cannot follow."""
    if q < _HOST_AT:
        return q + 1 if ch == "https://"[q] else None
    if ch.isalnum():
        return _IN_LABEL
    if ch == "-" and q != _HOST_AT:
        return _AFTER_HYPHEN
    return _HOST_AT if ch == "." and q == _IN_LABEL else None


def _glob_tokens(pattern: str) -> list[frozenset[str] | None]:
    """The pattern as `fnmatch` reads it: None for `*`, and for every other token the
    identifier characters it admits (a class: `!` negates, a `]` first is a member, and a
    `[` with no closing `]` is the character itself)."""
    out: list[frozenset[str] | None] = []
    i, n = 0, len(pattern)
    while i < n:
        c = pattern[i]
        if c == "*":
            out.append(None)
        elif c == "?":
            out.append(frozenset(_ID_CHARS))
        elif c == "[":
            j = i + 1
            j += pattern[j:j + 1] == "!"
            j += pattern[j:j + 1] == "]"
            j = pattern.find("]", j)
            if j < 0:
                out.append(frozenset())  # the character `[` itself, in no identifier
            else:
                out.append(frozenset(x for x in _ID_CHARS
                                     if fnmatch.fnmatchcase(x, pattern[i:j + 1])))
                i = j
        else:
            out.append(frozenset(c) & frozenset(_ID_CHARS))
        i += 1
    return out


def _can_match(pattern: str) -> bool:
    if not any(c in pattern for c in "*?["):
        return bool(SERVER_ID.fullmatch(pattern))
    tokens = _glob_tokens(pattern)
    start = (0, 0)
    came: dict[tuple[int, int], tuple[tuple[int, int], str] | None] = {start: None}
    todo = collections.deque([start])
    while todo:
        i, q = state = todo.popleft()
        if i == len(tokens) and q == _IN_LABEL:
            witness = ""
            at: tuple[int, int] = state
            while (back := came[at]) is not None:
                at, ch = back
                witness = ch + witness
            return bool(SERVER_ID.fullmatch(witness)) and fnmatch.fnmatchcase(witness, pattern)
        if i == len(tokens):
            continue
        token = tokens[i]
        moves = [((i + 1, q), "")] if token is None else []
        for ch in (_ID_CHARS if token is None else sorted(token)):
            nq = _id_step(q, ch)
            if nq is not None:
                moves.append(((i if token is None else i + 1, nq), ch))
        for nxt, ch in moves:
            if nxt not in came:
                came[nxt] = (state, ch)
                todo.append(nxt)
    return False


_RULE_STR = ("class", "resource", "operation", "scope", "tool", "amount_param", "if_unknown")
_TOP_STR_LISTS = ("severity", "high_impact", "deny_resources", "allowed_tools", "ask_tools",
                  "serves_on_identity")
_TOP_BOOLS = ("allow_unlisted_resources", "clarify_missing_justification",
              "ask_on_mission_update")
_TOP_KEYS = frozenset(_TOP_STR_LISTS + _TOP_BOOLS + (
    "rules", "prohibited_pairs", "prohibited_sequences", "budgets", "resource_budgets",
    "max_mission_seconds",
    "default_class", "composition_on_certain", "r3_member"))


_DEAD = ("can never match a server identifier (a lowercase https host, with no port or "
         "path)")


def _check_policy_shape(d: Any) -> None:
    def bad(where: str, what: str) -> None:
        raise ValueError(f"{where}: {what}")

    if not isinstance(d, dict):
        bad("policy", "must be a JSON object")
    for k in d:
        if k not in _TOP_KEYS:
            bad(k, "unknown member")
    for k in _TOP_STR_LISTS:
        if k in d and not _is_str_list(d[k]):
            bad(k, "must be an array of strings")
    for k in ("deny_resources", "serves_on_identity"):
        for i, p in enumerate(d.get(k, [])):
            if not _can_match(p):
                bad(f"{k}[{i}]", _DEAD)
    for k in _TOP_BOOLS:
        if k in d and not isinstance(d[k], bool):
            bad(k, "must be true or false")
    for k in ("default_class", "composition_on_certain"):
        if k in d and not (isinstance(d[k], str) and d[k]):
            bad(k, "must be a non-empty string")
    if d.get("r3_member") is not None and not (isinstance(d["r3_member"], str)
                                               and d["r3_member"]):
        bad("r3_member", "must be a non-empty string or null (null: spec-only, extension off)")
    if "max_mission_seconds" in d and d["max_mission_seconds"] is not None and not (
            _is_count(d["max_mission_seconds"])
            and 0 < d["max_mission_seconds"] <= MAX_MISSION_SECONDS):
        bad("max_mission_seconds", f"must be a positive integer of at most "
                                   f"{MAX_MISSION_SECONDS} (ten years)")
    rules = d.get("rules", [])
    if not isinstance(rules, list):
        bad("rules", "must be an array")
    for i, r in enumerate(rules):
        w = f"rules[{i}]"
        if not isinstance(r, dict):
            bad(w, "must be an object")
        if not isinstance(r.get("class"), str) or not r["class"]:
            bad(w, "needs a non-empty string `class`")
        for k, v in r.items():
            if k in _RULE_STR:
                if not isinstance(v, str):
                    bad(f"{w}.{k}", "must be a string")
                if k == "resource" and v and not _can_match(v):
                    bad(f"{w}.{k}", _DEAD)
            elif k == "result_contains_any":
                if not _is_str_list(v) or not v:
                    bad(f"{w}.{k}", "must be a non-empty array of strings")
            elif k == "param_domain_not_in":
                if not isinstance(v, dict) or not v or not all(
                        isinstance(p, str) and _is_str_list(x) for p, x in v.items()):
                    bad(f"{w}.{k}", "must map parameter names to arrays of domains")
            elif k == "param_gt":
                # A threshold of NaN or infinity (JSON readers take `NaN`, `Infinity`
                # and `1e400`) is never exceeded: the rule would never fire.
                if not isinstance(v, dict) or not v or not all(
                        isinstance(p, str) and _finite(x) for p, x in v.items()):
                    bad(f"{w}.{k}", "must map parameter names to finite numbers")
            elif k == "param_in":
                if not isinstance(v, dict) or not v or not all(
                        isinstance(p, str) and _is_str_list(x) and x for p, x in v.items()):
                    bad(f"{w}.{k}", "must map parameter names to non-empty arrays of strings")
            else:
                bad(f"{w}.{k}", "unknown member")
    for k, n in (("prohibited_pairs", 2), ("prohibited_sequences", 0)):
        v = d.get(k, [])
        if not isinstance(v, list) or not all(_is_str_list(x) for x in v):
            bad(k, "must be an array of arrays of class names")
        if n and any(len(x) != n for x in v):
            bad(k, f"each entry must name exactly {n} classes")
        if not n and any(len(x) < 2 for x in v):
            # A sequence is "these classes, in this order"; fewer than two is not a
            # sequence, and evaluating one would fail on every decision.
            bad(k, "each entry must name at least 2 classes")
    budgets = d.get("budgets", {})
    if not isinstance(budgets, dict):
        bad("budgets", "must be an object keyed by class")
    for c, b in budgets.items():
        if not isinstance(b, dict) or not b:
            bad(f"budgets.{c}", "must be an object with max_count and/or max_amount")
        for k, v in b.items():
            if k not in ("max_count", "max_amount"):
                bad(f"budgets.{c}.{k}", "unknown member")
            if not _is_count(v):
                bad(f"budgets.{c}.{k}", "must be a non-negative integer")
    rbs = d.get("resource_budgets", {})
    if not isinstance(rbs, dict):
        bad("resource_budgets", "must be an object keyed by resource identifier")
    for res, rb in rbs.items():
        w = f"resource_budgets.{res}"
        if not SERVER_ID.fullmatch(res):
            bad(w, "the key must be a server identifier (lowercase https host)")
        if not isinstance(rb, dict) or set(rb) != {"unit", "decimals", "max_amount"}:
            bad(w, "must be an object with exactly unit, decimals and max_amount")
        if not isinstance(rb["unit"], str) or not rb["unit"]:
            bad(f"{w}.unit", "must be a non-empty string")
        # Budgets L326: no amount has more than 15 digits; a scale past MAX_DECIMALS
        # would write every amount the person reads with that many places.
        if not (_is_count(rb["decimals"]) and rb["decimals"] <= MAX_DECIMALS):
            bad(f"{w}.decimals", f"must be an integer from 0 to {MAX_DECIMALS}")
        if not (_is_count(rb["max_amount"]) and rb["max_amount"] <= MAX_AMOUNT):
            bad(f"{w}.max_amount", "must be a non-negative integer of at most 15 digits")


# ------------------------------------------------------------------ acts


@dataclass
class Act:
    """An act normalized from a supervision request."""

    act: str  # auth_token | permission | person_token
    iss: str
    sub: str
    agent: str
    mission_s256: str = ""
    resource: str = ""
    operations: list[str] = field(default_factory=list)
    scope: str = ""
    tool: str = ""
    parameters: dict[str, Any] | None = None
    parameters_provenance: str = ""  # resource | agent
    result: dict[str, Any] | None = None
    justification: str = ""
    # AAuth Budgets, from the forwarded resource token: the resource's `budget` offer as
    # "<unit>/<decimals>" and `amount`, and its `budget_consumed` record, if any.
    budget_unit: str = ""
    budget_amount: int | None = None
    consumed_jti: str = ""
    consumed: int | None = None
    # How far ahead of the SS's clock the PS's stamps run (`Store.leads`), for where its
    # acts took place against a token's end.
    ps_lead: float = 0.0


@dataclass
class Classification:
    cls: str
    provenance: str
    uncertain: bool
    amount: int | None = None
    detail: str = ""
    # When the agent's data raised the class to `cls` through a rule of that class: every
    # further class the act has, as each further raising rule is set aside, down to the
    # class no raising rule gives it (the agent's data still read, never below the class
    # the act has with that data unknown), each with its own certainty and amount.
    blind: list[Alias] = field(default_factory=list)


@dataclass
class Decision:
    decision: str  # allow | deny | ask | clarify
    reason: str = ""
    summary: str = ""
    recommendation: str = ""
    apply_options: list[dict[str, str]] = field(default_factory=list)
    narrow: dict[str, Any] = field(default_factory=dict)
    clarification: str = ""
    entry: HistoryEntry | None = None
    kind: str = ""
    composition: list[str] = field(default_factory=list)
    trace: list[str] = field(default_factory=list)
    # An ask names every composition the act would complete (`composition`, the first,
    # is the one an answer with reach covers), and the plain gates it is also asked for
    # (`intent`, `high_impact`), which such an answer then covers too, each on its own.
    compositions: list[list[str]] = field(default_factory=list)
    plain: bool = False
    gates: list[str] = field(default_factory=list)
    # Whether `composition` is completed on certain evidence: an `allow` with reach given
    # then may cover later certain completions; one given to "may complete" may not.
    certain: bool = False


def _glob(pattern: str | None, value: str) -> bool:
    return pattern is None or fnmatch.fnmatchcase(value, pattern)


# A recipient the rule can read: `local@domain`, with no quoting, routing (`%`, `!`),
# comment or whitespace in the local part. The domain is all that follows the `@`; it
# counts only if it is exactly a listed domain.
_MAILBOX = re.compile(r'[^\s@"(),:;<>\[\]\\%!]+@(.+)')


def _domains(value: str) -> list[str]:
    """The domain of each recipient `value` names, "" for one that cannot be read.

    One parameter may name several recipients ("a@x.example, b@y.example"), and a mail
    service sends to each, so each is checked. A recipient counts as a plain
    `local@domain`, or `Name <local@domain>` with no `@` in the name; any other form (a
    quoted or routed local part, a comment, whitespace) gives "", which no listed domain
    matches. The domain is all that follows the first `@`, so one with a stray `@` or a
    line break in it matches no listed domain either. A value without `@` names a domain
    itself."""
    parts, cur, quoted = [], "", False
    for ch in value.lower():
        if ch == '"':
            quoted = not quoted
        if ch in ",;" and not quoted:
            parts.append(cur)
            cur = ""
        else:
            cur += ch
    parts.append(cur)
    out = []
    for part in (p.strip() for p in parts):
        if not part:
            continue
        if "@" not in part:
            out.append(part)
            continue
        if part.endswith(">"):
            name, _, part = part[:-1].partition("<")
            if "@" in name:
                out.append("")
                continue
        m = _MAILBOX.fullmatch(part)
        out.append(m.group(1) if m else "")
    return out or [""]


def _is_digest(v: Any) -> bool:
    """An R3 digest object stands in for a large or sensitive value (R3, Proposal Document)."""
    return isinstance(v, dict) and isinstance(v.get("s256"), str)


# Budgets, Range Limits: "Implementations MUST NOT issue a budget whose amount exceeds
# 999,999,999,999,999 (15 digits)". No larger figure is an amount the SS can count.
MAX_AMOUNT = 999_999_999_999_999

# The `open` marks of acts the SS answered that are not history yet (`Store.open_acts`).
_NOT_YET = ("own", "other")

_SEQUENCE_SEARCH_BUDGET = 20_000  # search steps before the SS stops and treats it as possible


def _floats(h: HistoryEntry) -> bool:
    """Whether an entry's position says nothing of when it took place: a token replayed
    after a routing change, or any act `unplaced` (an audit record is placed by its
    report, which always follows its action)."""
    return not h.detail.endswith("audit record") and (
        h.unplaced or h.detail.endswith("replayed"))


class _Pinned:
    """Among the entries `keep` admits (by position), with their stamps: the last position
    of one stamped no later than a given time (`at_most`, -1 with none) and the first of
    one stamped after it (`first_after`, the history's length with none), in O(log n) once
    the table is built on first use (most searches never ask)."""

    def __init__(self, stamps: list[float], keep: list[bool]) -> None:
        self.stamps, self.keep = stamps, keep
        self.ats: list[float] | None = None
        self.last: list[int] = []
        self.first: list[int] = []

    def _build(self) -> list[float]:
        if self.ats is None:
            pinned = sorted((a, j) for j, a in enumerate(self.stamps) if self.keep[j])
            self.ats = [a for a, _ in pinned]
            m = -1
            for _, j in pinned:
                m = max(m, j)
                self.last.append(m)
            f = len(self.stamps)
            self.first = [0] * len(pinned)
            for k in range(len(pinned) - 1, -1, -1):
                f = min(f, pinned[k][1])
                self.first[k] = f
        return self.ats

    def at_most(self, t: float) -> int:
        k = bisect.bisect_right(self._build(), t)
        return self.last[k - 1] if k else -1

    def first_after(self, t: float) -> int:
        k = bisect.bisect_right(self._build(), t)
        return self.first[k] if k < len(self.first) else len(self.stamps)


# The work a decision spends on missions' own passes (`Policy._compositions`), counted in
# entries composed: twice its history, and never less than this; each pass also costs
# `MISSION_PASS_COST`, the fixed work of its searches.
MISSION_PASS_WORK = 20_000
MISSION_PASS_COST = 100


def _sequence_completable(seq: tuple[str, ...], cls: str, history: list[HistoryEntry],
                          now: float, certain_only: bool = False,
                          floated: bool = False, lead: float = 0.0) -> bool | None:
    """Whether the act being decided, of class `cls`, with `history` could make the effects
    of `seq` happen in order. `None` when the search ran out of budget: the caller asks it
    as unsettled (treated as possible, not as uncertain evidence), and no `allow` answer
    given with reach covers it (a `deny` given with reach still applies).

    Acts are placed on the order in which the SS learned of them: history entry `i` at
    position `i`, the act being decided at `len(history)`. A grant, which has no
    lifetime, can take effect at any moment from its position on; an audited action at
    any position up to its report. An issued token can be
    presented at any moment from its position until its `exp` plus `EXP_SKEW`: up to the
    last later entry the PS reported no later than that, and past the act being decided if
    it has not passed by `now`. The act being decided is
    placed at its position: every history entry starts before it, so a later use of its
    own token changes nothing here (it is checked when the acts after it are decided,
    with its `exp` in history by then). The sequence is completable if distinct acts, one
    of them the act being decided, can take the steps at non-decreasing moments.

    An entry with `blind` classes may take a step as any of its classes, never two steps:
    it is one act. With `certain_only`, an entry takes a step only as a class it is certain of,
    and only where it surely could. A position says when an entry took place only for an
    entry pinned at it (`_floats`): only those place a token's end of life, from their
    stamps, in the certain pass (an audit record not either: its report can follow an
    expiry). A token whose place is not known takes a step from before any entry (-0.5)
    or, in the certain pass, from its start (`start`): after every pinned act (an entry
    pinned at its place, not an audit record) stamped no later than it and the moment
    just after each, after the certain end of every audit record stamped no later, and
    after the start of every such token stamped earlier; to just after the last pinned
    act stamped within its `exp` plus `EXP_SKEW` (in both passes; past the end while
    live). In the certain pass, one that may have ended before the first pinned act
    stamped after it takes a step at its start only, if it ended after the latest its
    own stamp can be on the SS's clock (`at`) and no pinned act stamped after it stands
    before that start, and none if not. Such an act with no `exp` (one moment, not known)
    takes none in the certain pass. There, too, an audit record may take a step from
    before any such start up to its end, which stands among those starts by its stamp;
    and a token reaches the start of every such token issued while it was surely live.
    So any two acts the certain pass may put in an order could surely act in that order.
    With `floated` too, certain classes take the uncertain pass's windows: what the
    stamps leave open.

    Every shortcut below only skips choices that cannot succeed where another one tried
    would, so the answer is the plain search's; they keep an honest history from running
    the search out of budget, which would put it to the person.
    """
    n = len(history)
    inf = math.inf
    need = Counter(seq)
    classes = [[c for c, unc in _entry_classes(h) if not (certain_only and unc)]
               for h in history]
    have = Counter(c for cs in classes for c in cs)
    have[cls] += 1
    if cls not in need or any(have[c] < k for c, k in need.items()):
        # Each step takes a distinct act: a class with fewer acts than steps cannot fill.
        return False
    # Each entry's stamp: the PS's (`iat`) where kept, so stamps of one clock are compared
    # (`at` may be the SS's, for an act decided before it was reported).
    st = [float(h.iat or h.at) for h in history]
    # The earliest the SS's clock may have read when each act took place: a token's end
    # (`exp`, read by the resource on its clock) is on the SS's, and the PS's stamps run
    # `lead` ahead of it (behind, below 0), as its requests show (`Store.leads`); an act
    # reported long after it (`HistoryEntry.wide`) as far before its stamp as `at` is past.
    ts = [s - (h.at - s if h.wide else lead) - STAMP_SLACK if h.iat else s
          for s, h in zip(st, history, strict=True)]
    # Where an expired token's window ends: the last entry that may have taken place no
    # later than its `exp`. `low[j]` is the earliest such time from entry `j` on; it never
    # decreases, and at the last index it admits it is that entry's own time, so one
    # bisection finds the entry (times need not rise: a replayed or audited entry carries
    # `iat`).
    low: list[float] = [inf] * n
    m = inf
    for j in range(n - 1, -1, -1):
        m = min(m, ts[j])
        low[j] = m
    # The certain pass's windows, unless `floated`: certain classes over the uncertain
    # pass's windows, where every act whose place is not known floats.
    narrow = certain_only and not floated
    floating = [_floats(h) for h in history]
    if any(f and h.detail.endswith("replayed") for f, h in zip(floating, history, strict=True)):
        # A replayed token stamped after every entry before it and before every entry
        # pinned after it took place where it arrived: a mission log replayed in order
        # stands as it was recorded (Supervision L619). A tie is not after.
        after = [inf] * (n + 1)
        for j in range(n - 1, -1, -1):
            after[j] = after[j + 1] if floating[j] else min(after[j + 1], st[j])
        seen = -inf
        for j, h in enumerate(history):
            if floating[j] and h.detail.endswith("replayed") and seen < st[j] < after[j + 1]:
                floating[j] = False
            if not floating[j]:
                seen = max(seen, st[j])
    pinned = _Pinned(st, [not f for f in floating])
    # The acts that took place where they stand: pinned, and not an audit record.
    acts = [not f and not h.detail.endswith("audit record")
            for f, h in zip(floating, history, strict=True)]
    # Where a token ends: the resource reads its `exp` by its own clock, so for certain a
    # token was live at an act only if that act took place before it even at its latest:
    # `at`, the latest the SS knows it took place by (a report's arrival, for an act
    # reported where it stands; a PS clock behind would otherwise stretch every token's
    # life by its lag).
    ends = _Pinned([float(h.at) for h in history] if narrow else ts, acts)
    later = _Pinned(st, acts)

    # The certain pass may put one act before another wherever the first one's window
    # starts no later than the second one's ends. So each such pair must surely be able
    # to act in that order: the first one must be able to act before the second one last
    # can. Pinned acts keep their positions. In the span between two of them, a token
    # whose place is not known starts (`start`), and an audit record ends (`audit_end`),
    # at a point ranked by its stamp: a token in the span after the last pinned act
    # stamped no later than it, an audit record in the span before the first one stamped
    # in its second or after it (and no later than its report). Within a span a token's
    # start follows the moment just after its first pinned act, an audit record's end
    # stands among those starts (no act's window starts between them), and a token's
    # start follows the end of an audit record of the same stamp. Then:
    #  - a token starts after the moment just after every pinned act stamped no later
    #    than it (a token surely live only up to there may have ended before this one was
    #    issued), and before every pinned act stamped after it;
    #  - it starts after the start of every such token stamped earlier (one of those may
    #    have ended before it was issued), and before that of every one stamped later;
    #  - it starts after the end of every audit record stamped no later (that action may
    #    have been at its stamp, which need not follow this token's issuance), and before
    #    the end of every one stamped later (that action may have been at its stamp, after
    #    this token's issuance, as is needed for this token to come first);
    #  - every pinned act standing before an audit record's end is stamped before it.
    # An audited action may also have been as early as any act, so an audit record's
    # window starts before every such token's start (-1).
    ranks: list[list[float]] = []

    def table() -> list[list[float]]:
        # Built on first use: the stamps of the entries that are not pinned acts, in
        # order; and for each position, the last pinned act before it (-1: none).
        if not ranks:
            ranks.append(sorted({st[k] for k in range(n) if not acts[k]}))
            prev, p = [], -1.0
            for k in range(n):
                prev.append(p)
                if acts[k]:
                    p = float(k)
            ranks.append([*prev, p])
        return ranks

    def ranked(j: int, after: float, sign: float) -> float:
        # Past the moment just after the pinned act at `after` (-1: none), by the rank of
        # entry `j`'s stamp: a token's start (sign 1) comes after the end of an audit
        # record (sign -1) of the same stamp, and before the next stamp's.
        own = table()[0]
        rank = bisect.bisect_left(own, st[j]) / len(own)
        return after + 0.5 + 0.4 * rank + sign * 0.1 / len(own)

    def start(i: int) -> float:
        return ranked(i, later.at_most(st[i]), 1.0)

    def audit_end(j: int) -> float:
        return min(float(j), ranked(j, table()[1][later.first_after(st[j] - 1)], -1.0))

    # The starts of the tokens whose place is not known, by `at` (the latest the SS's
    # clock can have read when each was issued), each with the latest start so far:
    # only those whose start stands before every pinned act stamped after them.
    issued: list[list[float]] = []

    def reach(x: float) -> float:
        # The latest start, in the certain pass, of a token whose place is not known
        # issued while a token ending at `x` (`exp` plus `EXP_SKEW`) was surely live.
        if not issued:
            starts = [(j, start(j)) for j in range(n) if floating[j] and history[j].iat]
            anchors = sorted((float(history[j].at), s) for j, s in starts
                             if s < later.first_after(st[j]))
            top, tops = -inf, []
            for _, s in anchors:
                top = max(top, s)
                tops.append(top)
            issued.extend(([a for a, _ in anchors], tops))
        ats, tops = issued
        k = bisect.bisect_right(ats, x - 1)
        return tops[k - 1] if k else -inf

    # How many entries lead the history below a given number (`HistoryEntry.after_n`):
    # acts not yet history (open) count as later than any.
    floors: list[float] = []
    if any(h.after_n for h in history):
        m = 0.0
        for h in history:
            m = max(m, inf if h.open in _NOT_YET else float(h.n))
            floors.append(m)
    # Floating acts with a floor (`after_n`) start no earlier than it, in the uncertain
    # pass: a token live when one of them was stamped reaches that floor too.
    # Sorted by stamp, with the latest floor up to each: one search per token.
    floored = sorted(
        (ts[j], bisect.bisect_left(floors, float(h.after_n)) - 0.5)
        for j, h in enumerate(history) if floating[j] and h.after_n) if floors and not narrow \
        else []
    floored_at = [a for a, _ in floored]
    floored_max: list[float] = []
    for _, fl in floored:
        floored_max.append(max(fl, floored_max[-1]) if floored_max else fl)
    windows: dict[str, list[tuple[int, float, float]]] = {c: [] for c in need}
    # Acts that may take a step as either of two classes: the shortcuts below compare
    # acts of one class, so these are always tried.
    aliased: set[int] = set()
    for i, h in enumerate(history):
        mine = [c for c in classes[i] if c in need]
        if not mine:
            continue
        x = inf if h.token_exp is None else h.token_exp + EXP_SKEW
        if h.detail.endswith("audit record"):
            # An audit record reports an action already taken, at some moment before the
            # report: anywhere from before every entry (as a token whose place is not known
            # may be) up to it, and, for certain, before every pinned act stamped after it
            # (reported late, it may arrive after those), in the backstop's loose pass too
            # (an act there may only start earlier than its place). The uncertain pass
            # keeps the whole span: a pool with fewer acts must never complete more.
            lo, hi = -0.5, float(i)
            if narrow:
                # For certain, before acts stamped in its own second too (which came
                # first is not settled); the backstop keeps that second, so it is asked.
                # Among tokens whose place is not known, by its stamp (`audit_end`).
                lo, hi = -1.0, audit_end(i)
            elif certain_only:
                hi = min(hi, pinned.first_after(st[i]) - 0.5)
        elif not floating[i]:
            # Reported in the second of an act recorded since its decision (`after_n`, not
            # floating): which came first is not settled, so outside the certain pass it
            # may have been used from that decision on (in the backstop's loose pass too:
            # a completion that needs it first is then unsettled, never "may").
            lo = float(i) if narrow or not h.after_n else min(
                float(i), bisect.bisect_left(floors, float(h.after_n)) - 0.5)
            if h.token_exp is None:
                hi = float(i)
            elif x > now:
                hi = inf
            else:
                # Surely live when an entry stamped a whole second before its end took
                # place; may be at one stamped in that second (stamps are whole seconds).
                last = (ends.at_most(x - 1) if narrow
                        else bisect.bisect_right(low, x) - 1)
                hi = last + 0.5 if last > i else float(i)
        else:
            # A token replayed to this SS after a routing change arrives where the replay
            # puts it (after the mission logs, Supervision L619), not where it was taken,
            # and so do other acts whose place is not known (`HistoryEntry.unplaced`): it
            # may have been usable from the start of the history (or from the entries
            # recorded after the answer it follows, `after_n`), and surely from where its
            # stamp places it (below); in either case until just after the last pinned
            # entry stamped while it was live.
            if narrow and h.token_exp is None:
                continue
            if narrow:
                # For certain, from where its stamp places it among the others (`start`),
                # and never before the entries recorded before the answer it follows
                # (`after_n`): the SS's own order, which no PS clock can move.
                lo = start(i)
                if h.after_n:
                    lo = max(lo, bisect.bisect_left(floors, float(h.after_n)) - 0.5)
            elif h.after_n:
                lo = bisect.bisect_left(floors, float(h.after_n)) - 0.5
            else:
                lo = -0.5
            if h.token_exp is None:
                hi = float(i)
            elif x > now:
                hi = inf
            else:
                last = ends.at_most(x - 1 if narrow else x)
                if narrow and (last < 0 or last + 0.5 < lo):
                    # It may have ended before the first pinned act stamped after it. If it
                    # ended after the latest its own stamp can be on the SS's clock (`at`),
                    # it was live at the end of that second: after every act stamped no
                    # later than it, so it takes a step at its start, and only there. A
                    # token spent when issued, or kept with no stamp of the PS's, takes
                    # none. Nor does one where a pinned act stamped after it stands before
                    # that start (the stamps contradict the order the acts took place in),
                    # or whose floor is past that start (the stamps say it was live only
                    # where it cannot have been used).
                    if (not h.iat or x <= h.at or later.first_after(st[i]) < lo
                            or lo > start(i)):
                        continue
                    hi = lo
                else:
                    # In the uncertain pass, its own floor at least, and the floor of every
                    # floored act stamped while it was live.
                    k = bisect.bisect_right(floored_at, x)
                    hi = max(last + 0.5, lo, floored_max[k - 1] if k else lo)
        if narrow and hi < inf and x < inf:
            # A token reaches, for certain, the start of every token whose place is not
            # known issued while it was surely live (by `at`). Each act the search may then
            # put before it could act by that issuance, while it was live: a pinned act
            # standing before that start is stamped no later than that token, a token
            # whose place is not known starting no later is stamped no later, and an
            # audit record may be as early as any.
            hi = max(hi, reach(x))
        if len(mine) > 1:
            aliased.add(i)
        for c in mine:
            windows[c].append((i, lo, hi))
    windows[cls].append((n, float(n), float(n)))
    for ws in windows.values():
        ws.sort(key=lambda w: (w[1], w[0]))  # by start: the pruning below relies on it

    # The earliest moment each step could land if acts could repeat: a step with nowhere
    # to land then has nowhere to land at all, so an order that cannot hold is settled
    # here, before any search.
    t = -inf
    earliest: list[float] = []
    for c in seq:
        at = min((max(t, lo) for _, lo, hi in windows[c] if max(t, lo) <= hi), default=None)
        if at is None:
            return False
        t = at
        earliest.append(t)
    # Likewise the latest moment each step could land, going back from the last. Each
    # step needs an act of its own: the steps of a class up to step j need as many
    # distinct acts that start no later than step j's latest moment, and those from step
    # j on as many that end no earlier than its earliest. Counts and the moments above
    # let acts repeat; this does not.
    latest: list[float] = [inf] * len(seq)
    t = inf
    for j in range(len(seq) - 1, -1, -1):
        t = min(t, max((hi for _, lo, hi in windows[seq[j]] if lo <= t), default=-inf))
        latest[j] = t
    for j, c in enumerate(seq):
        if sum(1 for _, lo, _ in windows[c] if lo <= latest[j]) < seq[:j + 1].count(c) or \
                sum(1 for _, _, hi in windows[c] if hi >= earliest[j]) < seq[j:].count(c):
            return False

    # The act being decided is the latest act: every step after the one it takes lands at
    # its moment or later, where only a token still live can take it.
    live = Counter(c for c, ws in windows.items() for _, _, hi in ws if hi == inf)
    tails = [(k, Counter(seq[k + 1:])) for k, c in enumerate(seq) if c == cls]

    def mine_fits(step: int) -> bool:
        return any(k >= step and all(live[c] >= m for c, m in tail.items())
                   for k, tail in tails)

    budget = [_SEQUENCE_SEARCH_BUDGET]
    used = [False] * (n + 1)

    def place(step: int, t: float) -> bool | None:
        if step == len(seq):
            return used[n]
        if not used[n] and not mine_fits(step):
            return False
        budget[0] -= 1
        if budget[0] < 0:
            return None
        c = seq[step]
        # Among unused acts of the step's class that end at the same moment, the one that
        # starts earliest is never a worse choice (it lands no later, and any later step
        # it would have taken another can take instead), so only that one is tried. The
        # windows are in start order, so it is the first met. Live tokens all end at
        # infinity: however many there are, they cost one branch, not a permutation.
        # Likewise among one-off acts (a token that expired before the next report) the
        # earliest that can still take the step is tried and no other: a later
        # one would leave the earlier one behind, unusable by any later step. An act that
        # may take the step under either of two classes is tried whatever went before it,
        # and leaves its end out of `tried`: a later act of one class ending at the same
        # moment may be the better choice. One of one class tried first is never worse.
        tried: set[float] = set()
        one_off = False
        for k, lo, hi in windows[c]:
            if used[k] or hi in tried:
                continue
            at = max(t, lo)
            if at > hi:
                continue
            if k not in aliased:
                if lo == hi and k != n:
                    if one_off:
                        continue
                    one_off = True
                tried.add(hi)
            used[k] = True
            live[c] -= hi == inf
            r = place(step + 1, at)
            used[k] = False
            live[c] += hi == inf
            if r is not False:
                return r
        return False

    return place(0, -inf)


# --------------------------------------------------------------- policy interface


@runtime_checkable
class SupervisionPolicy(Protocol):
    """The decision interface the protocol layer (`SupervisionServer`) depends on.

    `SupervisionServer` is pure Supervision -00 wire logic: it parses and verifies the
    request, builds an `Act`, keeps the mission/history/reach state, and signs the
    answer. It never reaches into how a decision is made. Any object with these
    methods and two attributes can drive it; the APC `Policy` below is one such object,
    but a trivial allow-list, a rule engine or an adapter to a language model could
    replace it without touching the protocol layer. `decide` runs while the PS waits,
    under the store lock (there is no deferred decision), so it answers in time.

    * `classify(act)` maps an act to a semantic class with provenance (used where
      there is no live decision: replayed tokens, audit records, and person tokens
      reported or issued at approval).
    * `decide(act, mission, history, reach, now, clarify=...)` is the per-act decision
      over the mission state: `allow | deny | ask | clarify`.
    * `decide_proposal(body, now)` decides a mission proposal (which resources/tools the
      mission may touch): `allow | deny | ask`.

    Two attributes let the protocol layer stay policy-agnostic without reading a
    concrete config object:

    * `r3_member` is the request member that carries the resource-asserted R3 proposal
      (a wire name the parser needs, not a policy knob). This is a NON-SPEC extension
      (AAuth #256); None means spec-only Supervision -00 and the member is ignored.
    * `ask_on_mission_update` says whether an agent-reported mission change is put to the
      person. A policy that does not model updates returns False.

    And `serves_on_identity(resource)` says whether a person token for that resource is
    an act (the resource may serve on it alone); the protocol layer then records it from
    `person_token.issued`. A policy that does not model it returns False.
    """

    @property
    def r3_member(self) -> str | None: ...

    @property
    def ask_on_mission_update(self) -> bool: ...

    def serves_on_identity(self, resource: str) -> bool: ...

    def classify(self, act: Act) -> Classification: ...

    def decide(self, act: Act, mission: Mission | None, history: list[HistoryEntry],
               reach: list[Reach], now: float | None = None, *,
               clarify: bool = True) -> Decision: ...

    def decide_proposal(self, body: dict[str, Any], now: float | None = None) -> Decision: ...


class Policy:
    def __init__(self, cfg: PolicyConfig) -> None:
        self.cfg = cfg

    # The two protocol-level attributes, surfaced from the APC config so the protocol
    # layer never reads `policy.cfg` (see SupervisionPolicy).
    @property
    def r3_member(self) -> str | None:
        return self.cfg.r3_member

    @property
    def ask_on_mission_update(self) -> bool:
        return self.cfg.ask_on_mission_update

    def serves_on_identity(self, resource: str) -> bool:
        return any(_glob(p, resource) for p in self.cfg.serves_on_identity)

    # -------------------------------------------------------- classification

    def _data_match(self, r: Rule, act: Act) -> bool | None:
        """True/False if the rule's data conditions are decidable, None if not."""
        ok = True
        if r.result_contains_any:
            if act.result is None:
                return None
            # The members of `result` are the resource's (R3 L653): a member named for a
            # value shows it is there, and only a `contains` list declares the whole
            # contents, so only that list can show a value is absent.
            contains = act.result.get("contains")
            hit = bool({str(k) for k in act.result if k != "contains"}
                       & set(r.result_contains_any))
            if isinstance(contains, list):
                hit = hit or bool({str(x) for x in contains} & set(r.result_contains_any))
            elif not hit:
                return None
            ok = ok and hit
        if r.param_domain_not_in:
            # The act is outside when any recipient in any named parameter is: a mail goes
            # to all of them. A named parameter the act does not carry names nobody (a
            # mail with no `bcc`); with none of them present the recipients are unknown.
            params = act.parameters or {}
            named = [p for p in r.param_domain_not_in if p in params]
            if not named:
                return None
            outside = False
            for pname in named:
                v = params[pname]
                addrs = v if isinstance(v, list) else [v]
                if any(_is_digest(a) or not isinstance(a, str) for a in addrs):
                    return None  # R3 digest object or non-string: the value is not visible
                allowed = {x.lower() for x in r.param_domain_not_in[pname]}
                outside = outside or any(d not in allowed for a in addrs for d in _domains(a))
            ok = ok and outside
        for pname, limit in (r.param_gt or {}).items():
            if act.parameters is None or pname not in act.parameters:
                return None
            if _is_digest(act.parameters[pname]):
                return None
            try:
                value = float(act.parameters[pname])
            except (TypeError, ValueError, OverflowError):  # an integer past the float range
                return None
            # NaN compares false with everything, so it would read as "not over the limit"
            # and escape `if_unknown`. A value that is not a finite number is not visible.
            if not math.isfinite(value):
                return None
            ok = ok and value > limit
        for pname, values in (r.param_in or {}).items():
            # A code the resource states (a merchant category, a payee id), matched exactly.
            # A list names each of its values, like a list of recipients: one in the set is
            # enough. An integer reads as its decimal digits; anything else, or a parameter
            # the act does not carry, is not visible.
            v = (act.parameters or {}).get(pname)
            items = v if isinstance(v, list) else [v]
            if not all(isinstance(x, str) or (isinstance(x, int) and not isinstance(x, bool))
                       for x in items):
                return None  # absent, an R3 digest object, a float, an object
            ok = ok and any(str(x) in values for x in items)
        return ok

    def _static_match(self, r: Rule, act: Act) -> bool:
        # A rule's resource is matched against the act's resource only: a permission's
        # `action` is the agent's own string, and must not pass for a resource identifier.
        if not _glob(r.resource, act.resource):
            return False
        if r.operation is not None and not any(_glob(r.operation, o) for o in act.operations):
            return False
        if r.scope is not None and not any(_glob(r.scope, s) for s in act.scope.split()):
            return False
        if r.tool is not None and not _glob(r.tool, act.tool):
            return False
        return True

    def classify(self, act: Act) -> Classification:
        if act.act == "person_token" and self.serves_on_identity(act.resource):
            # Person Identity Access (Protocol L326-L346): the resource serves on the
            # token alone, and what it serves is not seen, so the token is an uncertain act
            # of the most severe class the policy gives the resource, and of each of its
            # other classes too (as a class assumed for data a rule does not have).
            classes = self._identity_classes(act.resource)
            first = max(classes, key=self.cfg.rank)
            return Classification(first, "configured", True, None, PERSON_TOKEN,
                                  [Alias(k, assumed=True) for k in classes if k != first])
        return self._classify(act)

    def _classify(self, act: Act) -> Classification:
        c, rule = self._scan_at(act)
        if act.parameters_provenance != "agent" or not (act.parameters or act.result):
            return c
        # Agent-asserted data may tighten, never loosen, for EVERY rule shape: whatever the
        # agent's data made of the act, it is at least as severe as the act would be with
        # that data unknown (`base`), and as certain as that is.
        blind = Act(act.act, act.iss, act.sub, act.agent, act.mission_s256, act.resource,
                    list(act.operations), act.scope, act.tool)
        base = self._scan(blind)
        # Where a data rule the agent's data decided gave the class, a higher class need not
        # be in the compositions, budgets or gates a lower one is in, nor need the class a
        # later rule gives. So the act is also each class the rules give it with each such
        # data rule set aside in turn (the agent's data still read), down to the rule that
        # closes the scan without it; each held to `base`, with its own certainty.
        found = [c]
        skip: set[int] = set()
        while rule >= 0:
            skip.add(rule)
            o, rule = self._scan_at(act, frozenset(skip))
            found.append(o)
        rank = self.cfg.rank
        # The last reading closes at the rule `base` closes at, with the agent's data read:
        # its amount is the one that rule reads, for a class the data would have lowered.
        last = found[-1]
        held: dict[str, Classification] = {}  # each class once, as certain as any reading
        amounts: dict[str, int] = {}  # and the largest amount any reading of it reads
        for e in found:
            if rank(e.cls) < rank(base.cls):
                e = Classification(base.cls, "agent", base.uncertain, last.amount,
                                   "agent-asserted evidence cannot lower the class")
            k = held.get(e.cls)
            if k is None or (k.uncertain and not e.uncertain):
                held[e.cls] = e
            if e.amount is not None:
                amounts[e.cls] = max(amounts.get(e.cls, e.amount), e.amount)
        for cls, amount in amounts.items():
            held[cls].amount = amount
        first = c.cls if rank(c.cls) >= rank(base.cls) else base.cls
        primary = held[first]
        primary.blind = [_alias(e) for cls, e in held.items() if cls != first]
        # A class assumed in any reading keeps the classes it was assumed over (one assumed
        # only with the agent's data set aside is marked so).
        for e in [*found, base]:
            for a in e.blind:
                if a.assumed and a.cls != first and a.cls not in held:
                    held[a.cls] = e
                    primary.blind.append(replace(a, set_aside=e is base))
        return primary

    def _identity_classes(self, resource: str) -> list[str]:
        """Every class (and `if_unknown` fallback) of the rules for `resource`, whatever
        operation, scope or data they are narrowed to, once each; a tool rule is about a
        local tool, not the resource. The default class where no rule names it."""
        found = [cls for r in self.cfg.rules if r.tool is None and _glob(r.resource, resource)
                 for cls in (r.cls, r.if_unknown) if cls]
        return list(dict.fromkeys(found)) or [self.cfg.default_class]

    def _scan(self, act: Act) -> Classification:
        return self._scan_at(act)[0]

    def _scan_at(self, act: Act, skip: frozenset[int] = frozenset()
                 ) -> tuple[Classification, int]:
        """The class the first rule that decides the act gives it, rules at the positions in
        `skip` set aside, and the position of that rule where it is a data rule its data
        decided (-1 where a static rule or no rule decided)."""
        # Flags read only for truthiness: `False` -> `None` is an equivalent mutant.
        unknown_seen = False  # pragma: no mutate
        decided_on_resource = False  # pragma: no mutate
        unseen = ""  # the most severe class of a data rule that could not read the act
        # The class of every data rule that could not read the act, with the amount it reads.
        unread: list[tuple[str, int | None]] = []
        for i, r in enumerate(self.cfg.rules):
            if i in skip:
                continue
            if not self._static_match(r, act):
                if r.needs_data and _glob(r.resource, act.resource) and (
                        r.tool is None or _glob(r.tool, act.tool)):
                    # A data rule for this resource, narrowed to another operation or
                    # scope, did not read the act: the data it needs is unknown here too.
                    unknown_seen = True
                    unseen = self._severer(unseen, r.cls)
                    unread.append((r.cls, self._amount(r, act)))
                continue
            if r.needs_data:
                m = self._data_match(r, act)
                if m is None:
                    unknown_seen = True
                    unseen = self._severer(unseen, r.cls)
                    unread.append((r.cls, self._amount(r, act)))
                    continue
                if act.parameters_provenance == "resource" or (
                        r.result_contains_any and act.result is not None):
                    decided_on_resource = True
                if m:
                    prov = "resource" if decided_on_resource else "agent"
                    return Classification(r.cls, prov, False, self._amount(r, act),
                                          f"rule {r.cls} on {prov}-asserted data"), i
                continue
            # A static rule closes the scan.
            # A rule that names no operation does not say what the act's operations do
            # there: a data rule that could not read them could have (`_unread`).
            c = self._static(act, r, unknown_seen, decided_on_resource, unseen)
            return _assumed_as(c, [(r.cls, self._amount(r, act)), *unread],
                               bool(act.operations) and r.operation is None), -1
        c = self._unread(act, unseen, self.cfg.default_class, None) or Classification(
            self.cfg.default_class, "configured", False, None, "no rule matched")
        return _assumed_as(c, [(self.cfg.default_class, None), *unread],
                           bool(act.operations)), -1

    def _static(self, act: Act, r: Rule, unknown_seen: bool, decided_on_resource: bool,
                unseen: str) -> Classification:
        """The class a static rule gives the act, the scan having seen what it has."""
        fallback = r.if_unknown
        no_proposal = act.act == "auth_token" and act.parameters_provenance != "resource"
        if fallback and (unknown_seen or no_proposal):
            return Classification(fallback, "configured", True, self._amount(r, act),
                                  f"data needed by a more specific rule is unavailable; "
                                  f"assumed {fallback}")
        if act.parameters_provenance == "agent" and not decided_on_resource and fallback \
                and self.cfg.rank(fallback) > self.cfg.rank(r.cls):
            # Agent-asserted data may tighten, never loosen.
            return Classification(fallback, "agent", True, self._amount(r, act),
                                  "agent-asserted evidence cannot lower the class")
        if not fallback and r.operation is None:
            assumed = self._unread(act, unseen, r.cls, self._amount(r, act))
            if assumed is not None:
                return assumed
        # A proposal the resource bound into its token, naming the act's operations or
        # parameters, is the resource's word for the act whatever rule matched: the
        # detail the high-impact gate asks for. One that names neither describes nothing.
        prov = "resource" if decided_on_resource or _described(act) else "configured"
        return Classification(r.cls, prov, False, self._amount(r, act), f"rule {r.cls}")

    def _severer(self, a: str, b: str) -> str:
        return b if not a or self.cfg.rank(b) > self.cfg.rank(a) else a

    def _unread(self, act: Act, unseen: str, cls: str,
                amount: int | None) -> Classification | None:
        """A rule that does not name the act's operations (narrowed to a scope or to the
        whole resource, or no rule at all) does not say what those operations do there.
        With no `if_unknown` to fall back on, a data rule for the resource that could not
        read the act could have: the act may be of that rule's class, uncertain."""
        if act.operations and unseen and self.cfg.rank(unseen) > self.cfg.rank(cls):
            return Classification(unseen, "configured", True, amount,
                                  f"data needed by a more specific rule is unavailable; "
                                  f"assumed {unseen}")
        return None

    @staticmethod
    def _amount(r: Rule, act: Act) -> int | None:
        if not r.amount_param:
            return None
        if act.parameters is None or r.amount_param not in act.parameters:
            return None
        # An amount the supervisor cannot read as a non-negative whole number is treated as
        # not visible, so the budget asks instead of counting it. A negative amount would
        # otherwise lower the running total and let a later payment through the ceiling.
        v = act.parameters[r.amount_param]
        if isinstance(v, bool):
            return None
        if isinstance(v, float):
            v = int(v) if v.is_integer() else None
        elif isinstance(v, str):
            # At most 15 digits (Budgets, Range Limits): a longer string is no amount, and
            # converting one of thousands of digits would fail the request.
            v = int(v) if v.isascii() and v.isdigit() and len(v) <= 15 else None
        if not isinstance(v, int) or v < 0 or v > MAX_AMOUNT:
            return None
        return v

    # ------------------------------------------------------------ evaluation

    def _composition(self, cls: str, uncertain: bool, resource: str,
                     history: list[HistoryEntry], now: float = 0.0, lead: float = 0.0
                     ) -> tuple[list[str], bool]:
        """Return the violated pair/sequence and whether it rests on uncertain evidence.

        A violation is certain when it can be completed from certain history entries
        alone; an uncertain entry never masks a certain one that also completes it.

        A prohibited sequence is checked whichever of its steps the act is, not only the
        last: an issued token can be presented until its `exp`, so a token granted earlier
        for a later step can still take effect after this act.

        A completion the search could not settle counts here as possible and uncertain;
        `decide` keeps it apart, so that no answer covers it.
        """
        found = self._compositions(cls, uncertain, history, now, lead)
        if not found:
            return [], False
        comp, unc = found[0]
        return comp, unc is not False

    def _compositions_of(self, c: Classification, history: list[HistoryEntry],
                         now: float, lead: float = 0.0
                         ) -> list[tuple[list[str], bool | None]]:
        """The compositions the act completes, as its class and, where the agent's data
        raised that class, as each further class it has (`Classification.blind`), with that
        class's own certainty; every act in history likewise (`_sequence_completable`),
        each one act under any of its classes. A composition found more than one way keeps
        the firmest answer."""
        found = self._compositions(c.cls, c.uncertain, history, now, lead)
        if not c.blind:
            return found
        merged = dict((tuple(comp), unc) for comp, unc in found)
        for a in c.blind:
            for comp, unc in self._compositions(a.cls, not a.certain, history, now, lead):
                merged[tuple(comp)] = min(merged.get(tuple(comp), True), unc, key=_firmness)
        return [(list(k), v) for k, v in sorted(merged.items(), key=lambda kv:
                                                 self._order().index(kv[0]))]

    def _order(self) -> list[tuple[str, ...]]:
        """Every composition in policy order (pairs first), as `_compositions` keys them."""
        return [tuple(x) for p in self.cfg.prohibited_pairs for x in (p, p[::-1])] + [
            tuple(q) for q in self.cfg.prohibited_sequences]

    def _compositions(self, cls: str, uncertain: bool, history: list[HistoryEntry],
                      now: float, lead: float = 0.0) -> list[tuple[list[str], bool | None]]:
        """Every prohibited pair and sequence the act completes, each with whether it
        rests on uncertain evidence, in policy order (pairs first).

        Acts of other missions are marked by `scope`. The act composes with each such
        mission on its own (certain where the evidence is, for an act outside missions
        and a mission of its agent), and with all of them together, every act of a
        mission then uncertain: a composition that needs two missions is asked, never
        denied. A composition certain in any pass is certain.

        Computed without a pass per mission over the whole history, which would make a
        decision's cost grow with the number of missions, under the store lock: the pass
        over all missions together finds every composition any one mission does, and a
        mission's own pass adds only certainty, so only its certain acts are composed with
        the act's own certain ones, and only where it has any
        (`tests/test_cross_mission_scale.py` checks the answer against the plain
        computation)."""
        scopes: dict[str, list[tuple[int, HistoryEntry]]] = {}
        shared: list[tuple[int, HistoryEntry]] = []
        for i, h in enumerate(history):
            (scopes.setdefault(h.scope, []) if h.scope else shared).append((i, h))
        if not scopes:
            return self._compositions_in(cls, uncertain, history, now, lead)
        found: dict[tuple[str, ...], bool | None] = {}

        def merge(pool: list[HistoryEntry]) -> None:
            for comp, unc in self._compositions_in(cls, uncertain, pool, now, lead):
                found[tuple(comp)] = min(found.get(tuple(comp), True), unc, key=_firmness)

        def joined(a: list[tuple[int, HistoryEntry]], b: list[tuple[int, HistoryEntry]]
                   ) -> list[HistoryEntry]:
            return [h for _, h in heapq.merge(a, b, key=lambda e: e[0])]

        merge([elsewhere_copy(h, h.scope) if h.scope and not h.open else h for h in history])
        # A mission's own pass can only make certain what the pass over all of them found:
        # a pool with fewer acts completes nothing more. So none runs when nothing found
        # is short of certain, and they stop once everything found is certain. A mission
        # whose certain acts have no class of a composition still short of certain adds
        # no step, and none of their stamps a certain act's own does not give; past a
        # budget of work (as for one search's steps), what is still short of certain is
        # unsettled: asked, and no answer covers it.
        if not uncertain and any(v is not False for v in found.values()):
            certain = [e for e in shared if not _uncertain(e[1])]
            budget = max(MISSION_PASS_WORK, 2 * len(history))
            for group in scopes.values():
                short = {c for comp, v in found.items() if v is not False for c in comp}
                mine = [e for e in group if not _uncertain(e[1])]
                if not any(not unc and k in short
                           for _, h in mine for k, unc in _entry_classes(h)):
                    continue
                budget -= len(certain) + len(mine) + MISSION_PASS_COST
                if budget < 0:
                    for k, v in found.items():
                        if v:
                            found[k] = None
                    break
                merge(joined(certain, mine))
                if all(v is False for v in found.values()):
                    break
        order = self._order()
        return [(list(k), v) for k, v in sorted(found.items(), key=lambda kv: order.index(kv[0]))]

    def _compositions_in(self, cls: str, uncertain: bool, history: list[HistoryEntry],
                         now: float, lead: float = 0.0
                         ) -> list[tuple[list[str], bool | None]]:
        unc_of = _uncertain
        out: list[tuple[list[str], bool | None]] = []
        for a, b in self.cfg.prohibited_pairs:
            for other, me in ((a, b), (b, a)):
                if cls != me:
                    continue
                hits = [unc for h in history for k, unc in _entry_classes(h) if k == other]
                if hits:
                    out.append(([other, me], uncertain or all(hits)))
        for seq in self.cfg.prohibited_sequences:
            if cls not in seq:
                continue
            for certain_only in (True, False):
                pool = [h for h in history if not certain_only or not unc_of(h)]
                found = _sequence_completable(seq, cls, pool, now, certain_only, lead=lead)
                if found is False and certain_only and not uncertain and (
                        _sequence_completable(seq, cls, pool, now, True, floated=True,
                                              lead=lead) is not False):
                    # Certain acts complete it once the record's places and stamps are
                    # read loosely (acts whose place is not known float, a stamp in a
                    # token's last second counts as within it): they settle it neither
                    # way, so it is asked, and no answer about a "may" covers it.
                    found = None
                if found is None:  # unsettled: asked, and no reach covers it
                    out.append((list(seq), None))
                    break
                if found:
                    out.append((list(seq), uncertain or not certain_only))
                    break
        return out

    def _reach(self, reach: list[Reach], act: Act, kind: str, composition: list[str],
               answer: str = "allow", certain: bool = False, gate: str = "") -> Reach | None:
        for r in reach:
            if (r.iss, r.sub, r.agent) != (act.iss, act.sub, act.agent) or r.kind != kind:
                continue
            if r.gate != gate:
                # An answer to one plain gate is about the question that gate put, not the
                # other one, nor a composition.
                continue
            if r.answer != answer:
                continue
            if certain and not r.certain:
                # Allowed when it "may" complete: never put to the person as "would". (A
                # "no" is looked up without `certain`: given to "may", it answers "would".)
                continue
            if r.value == "once":
                continue
            if r.value != "always" and r.mission_s256 != act.mission_s256:
                # A `mission` reach holds in the mission it was given in, and one given to
                # an act outside any mission holds outside missions only: an empty
                # mission is not a wildcard.
                continue
            if r.composition_override != composition:
                # An answer about a composition covers that composition and nothing else:
                # not another composition, and not a plain gate (intent, high impact)
                # the person was never asked about. A plain answer covers no composition.
                continue
            return r
        return None

    def decide(self, act: Act, mission: Mission | None, history: list[HistoryEntry],
               reach: list[Reach], now: float | None = None, *,
               clarify: bool = True) -> Decision:
        """Decide one act. `clarify=False` is used once the agent has answered a
        clarification: the act then goes to the person instead of looping."""
        now = time.time() if now is None else now
        trace: list[str] = []
        cfg = self.cfg

        if mission is not None:
            if mission.state != "active":
                return Decision("deny", reason="The mission has terminated.", trace=["mission"])
            exp = _iso_to_epoch(mission.blob.get("expires_at"))
            if exp is not None and now >= exp:
                return Decision("deny", reason="The mission has expired.", trace=["mission"])

        if act.act == "person_token" and not self.serves_on_identity(act.resource):
            return self._decide_person_token(act, mission, reach, now)
        # A person token spends no budget: what it reads is not seen (`classify`).
        identity = act.act == "person_token"

        if any(_glob(p, act.resource) for p in cfg.deny_resources if act.resource):
            return Decision("deny", reason=f"{act.resource} is not permitted by policy.",
                            trace=["deny_resources"])

        c = self.classify(act)
        trace.append(f"class={c.cls} provenance={c.provenance} uncertain={c.uncertain} ({c.detail})")
        target = act.resource or act.tool
        # A permission whose `action` reads as a resource identifier is kept apart from the
        # resource: an answer about one must never reach the other.
        kind = f"{c.cls}|{'tool:' if not act.resource and SERVER_ID.match(target) else ''}" \
            f"{target}"
        entry = HistoryEntry(c.cls, target, c.provenance, at=int(now), amount=c.amount or 0,
                             detail=("uncertain: " if c.uncertain else "") + c.detail,
                             amount_known=c.amount is not None, blind=list(c.blind))
        if act.budget_amount is not None:
            entry.unit, entry.allocated = act.budget_unit, act.budget_amount
        # The high-impact gate applies to the act if any of its classes is high impact (the
        # agent's data cannot take it out of the gate by raising its class).
        high = next((k for k in [c.cls] + [a.cls for a in c.blind] if k in cfg.high_impact),
                    "")

        # Budgets count the act's own history only: entries borrowed from across the
        # mission boundary compose, but a mission's ceilings are the mission's.
        own = [h for h in history if not h.borrowed]
        # Acts of the same history the SS answered that have not happened yet (an ask the
        # person is deciding, an allowed token not yet reported issued): they spend
        # nothing, but a ceiling they would cross once they happen is put to the person
        # (Budgets, Concurrency: per-token budgets SHOULD sum within the ceiling).
        pending = [h for h in history if h.open == "own"]

        # Every gate that denies is checked before any gate that asks, so that an ask for
        # one reason never puts to the person an act that policy denies for another. The
        # asks are collected, and the person is told every reason at once.
        asks: list[tuple[str, str]] = []  # what the person is told, and the trace note
        budget_asked = False

        # AAuth Budgets: the person's ceiling at a metered resource, against the resource's
        # own offer and consumption records. Once spent it refuses; before then, an act
        # that may cross it is put to the person (Supervision -00 cannot grant less, AAuth
        # #259). A permission act has no resource.
        rb = None if identity else cfg.resource_budgets.get(act.resource)
        if rb is not None:
            over = self._resource_budget(act, rb, own, trace, pending)
            if over is not None:
                verdict, text, note = over
                if verdict == "deny":
                    return Decision("deny", reason=text, entry=entry, kind=kind,
                                    trace=trace + [note])
                asks.append((text, note))
                budget_asked = True

        # Budgets: no remembered answer passes them, and a spent one refuses what it
        # cannot compare. An act counts against the budget of each class it is: its own,
        # and each further one where the agent's data raised it (an earlier act likewise),
        # with the amount that class's rule reads. A class only assumed for data a rule
        # needs (`Alias.assumed`) may not be the act's: a ceiling reached only through such
        # classes is put to the person. A deny names the budget, never its figures: the
        # agent reads the reason (Supervision L265), and Budgets keeps the ceiling from it
        # (L218); they stay in the trace.
        for cls, amount, firm in [(c.cls, c.amount, True)] + [
                (a.cls, a.amount if a.amount_known else None, not a.assumed) for a in c.blind]:
            b = None if identity else cfg.budgets.get(cls)
            if b is None:
                continue
            same = [h for h in own if _has(h, cls) and not _person_token(h)]
            waiting = [h for h in pending if _has(h, cls) and not _person_token(h)]
            sure = [h for h in same if not _assumed_in(h, cls)] if firm else []
            where = "in this mission" if act.mission_s256 else "outside missions"
            name = md.code(cls)
            # Earlier acts not reported yet whose part the supervisor knows (their amounts,
            # and that they are of the class, as this act is).
            known = firm and all(_as(h, cls)[1] and not _assumed_in(h, cls) for h in waiting)
            # What they may count, for the person: the figure the asks below give.
            wait_known = sum(_as(h, cls)[0] for h in waiting if _as(h, cls)[1])
            wait_unseen = any(not _as(h, cls)[1] for h in waiting)
            wait_note = "" if not waiting else (
                f" Earlier {name} acts not reported yet may count " + " and ".join(
                    [f"{wait_known} more"] * (bool(wait_known) or not wait_unseen)
                    + ["an amount not known"] * wait_unseen) + ".")
            past = b.max_count is not None and len(same) + 1 > b.max_count
            if b.max_count is not None and past:
                if firm and len(sure) + 1 > b.max_count:
                    return Decision("deny", reason=f"Budget exhausted: no more {name} acts "
                                    f"{where}.", entry=entry, kind=kind,
                                    trace=trace + [f"budget count: {b.max_count}"])
                asks.append((f"This act may pass the budget of at most {b.max_count} {name} "
                             f"act{'s' if b.max_count != 1 else ''} {where}. The count "
                             f"includes acts that may not be {name} acts: {ASSUMED}.",
                             "budget count assumed"))
                budget_asked = True
            # Acts answered but not reported yet that would take the count past the cap
            # (counting only acts surely of the class, where some are only assumed of it).
            if b.max_count is not None and waiting and \
                    len(sure if past else same) + len(waiting) + 1 > b.max_count:
                n = len(sure if past else same)
                # "Would" only where the acts surely of the class pass it without the others.
                asks.append((_waiting_text(len(waiting), f"{name} act",
                                           f"the {name} budget of {b.max_count} "
                                           f"act{'s' if b.max_count != 1 else ''}",
                                           known=firm and not any(_assumed_in(h, cls)
                                                                  for h in waiting)
                                           and len(sure) + len(waiting) + 1 > b.max_count)
                             + f" {n} {name} act{'' if n == 1 else 's'} "
                             f"{'is' if n == 1 else 'are'} counted {where}.",
                             "budget count with open acts"))
                budget_asked = True
            # An amount of 0 spends nothing: no amount budget refuses it.
            if b.max_amount is not None and amount != 0:
                spent = sum(_as(h, cls)[0] for h in same)
                unseen = sum(1 for h in same if not _as(h, cls)[1])
                if amount is not None and spent + amount > b.max_amount:
                    firm_spent = sum(_as(h, cls)[0] for h in sure)
                    if firm and firm_spent + amount > b.max_amount:
                        return Decision("deny", reason=f"Budget exceeded: this act's amount "
                                        f"would take the {name} budget {where} past its "
                                        f"limit.", entry=entry, kind=kind, trace=trace + [
                                            f"budget amount: {firm_spent} + {amount} of "
                                            f"{b.max_amount}"])
                    asks.append((f"This act may pass the {name} budget of {b.max_amount} "
                                 f"({spent} + {amount}). The total includes acts that may not "
                                 f"be {name} acts: {ASSUMED}.",
                                 "budget amount assumed"))
                    budget_asked = True
                    if waiting and (any(not _as(h, cls)[1] for h in waiting) or firm_spent
                                    + amount + sum(_as(h, cls)[0] for h in waiting)
                                    > b.max_amount):
                        asks.append((_waiting_text(len(waiting), f"{name} act",
                                                   f"the {name} budget of {b.max_amount}",
                                                   known=known)
                                     + f" This act's amount is {amount}, and {firm_spent} of "
                                     f"the budget is counted {where}." + wait_note,
                                     "budget amount with open acts"))
                elif amount is None:
                    # A spent budget only goes further: the person's "yes" would pass it.
                    counted = sum(_as(h, cls)[0] for h in same if not _assumed_in(h, cls))
                    if firm and counted >= b.max_amount:
                        return Decision("deny", reason=f"Budget exhausted: the {name} budget "
                                        f"{where} is spent, and this act's amount is not "
                                        f"visible to the supervisor.", entry=entry, kind=kind,
                                        trace=trace + [f"budget amount: {counted} of "
                                                       f"{b.max_amount}"])
                    known_part = [f"{counted} of it is counted {where}"] * bool(counted) + [
                        f"the amount of {unseen} earlier {name} act{'s' * (unseen > 1)} is "
                        f"not known either"] * bool(unseen)
                    said = (
                        f"This act may be a {name} act, of an amount the supervisor cannot "
                        f"see; the {name} budget of {b.max_amount} is already spent "
                        f"({counted} counted {where})." if counted >= b.max_amount else
                        (f"The {name} amount is not visible to the supervisor" if firm else
                         f"This act may be a {name} act, of an amount the supervisor cannot "
                         f"see") + f", so the {name} budget of {b.max_amount} cannot be "
                        f"checked" + "".join(f"; {p}" for p in known_part[:1]) + "".join(
                            f", and {p}" for p in known_part[1:]) + ".")
                    asks.append((said + wait_note, "budget amount unknown"))
                    budget_asked = True
                elif unseen:
                    # An earlier act whose amount the SS never saw is not 0: the total
                    # spent is unknown, and assuming less than was spent overruns.
                    asks.append((f"The amount of {unseen} earlier {name} "
                                 f"act{'s' if unseen > 1 else ''} is not known to the "
                                 f"supervisor, so the {name} budget of {b.max_amount} cannot "
                                 f"be checked." + wait_note,
                                 "budget history unknown"))
                    budget_asked = True
                elif waiting and (any(not _as(h, cls)[1] for h in waiting) or spent + amount
                                  + sum(_as(h, cls)[0] for h in waiting) > b.max_amount):
                    surely = sum(_as(h, cls)[0] for h in sure)
                    asks.append((_waiting_text(len(waiting), f"{name} act",
                                               f"the {name} budget of {b.max_amount}",
                                               known=known and surely + amount + wait_known
                                               > b.max_amount)
                                 + f" This act's amount is {amount}, and {spent} of the "
                                 f"budget is counted {where}." + wait_note,
                                 "budget amount with open acts"))
                    budget_asked = True

        # Composition closure over the history. A completion on certain evidence is denied
        # outright (unless the policy asks instead), whatever the person answered before:
        # they are never asked about one, and an answer about a completion that "may"
        # happen is not an answer about one that would. Otherwise an answer the person
        # gave for one composition covers that composition only, so every one the act
        # completes must be covered before a reach can let it through.
        open_comps: list[tuple[list[str], bool | None]] = []
        covered: list[list[str]] = []
        for comp, comp_unc in self._compositions_of(c, history, now, act.ps_lead):
            trace.append(f"composition {comp} uncertain={comp_unc}")
            if comp_unc is False and cfg.composition_on_certain != "ask":
                return Decision("deny", reason=self._comp_summary([comp], False), entry=entry,
                                kind=kind, composition=comp, trace=trace)
            # A completion the search could not settle is not covered by any answer.
            r = self._reach(reach, act, kind, comp, certain=comp_unc is False) \
                if comp_unc is not None else None
            if r is not None:
                trace.append(f"reach {r.value} overrides composition {comp}")
                covered.append(comp)
            else:
                open_comps.append((comp, comp_unc))
        open_comps.sort(key=lambda oc: _firmness(oc[1]))  # certain, unsettled, uncertain
        # Where a composition is certain once a class of this act it is in doubt of is taken
        # as certain, the other acts are certain and only this act is in doubt: only its
        # doubts are named. A list of every uncertain act that could take a step would tell
        # the person a certain act is in doubt. Those compositions are told together, with
        # this act's doubts once; others resting on the same doubts are told once too. A
        # class of this act already searched as certain is not searched again.
        sure_if_act: set[tuple[str, ...]] = set()
        for k in dict.fromkeys([c.cls] * c.uncertain + [a.cls for a in c.blind
                                                        if not a.certain]):
            if any(unc and k in comp for comp, unc in open_comps):
                sure_if_act |= {tuple(comp) for comp, unc in self._compositions(
                    k, False, history, now, act.ps_lead) if unc is False}
        told: dict[tuple[bool | None, bool, tuple[str, ...]], list[list[str]]] = {}
        for comp, unc in open_comps:
            act_only = bool(unc) and tuple(comp) in sure_if_act
            doubts = tuple(_doubts(comp, c, history)) if unc and not act_only else ()
            told.setdefault((unc, act_only, doubts), []).append(comp)
        asks += [(self._comp_summary(group, unc, _doubts(
            [k for comp in group for k in comp], c, history, act_only=True) if act_only
            else list(doubts), act_only), "") for (unc, act_only, doubts), group in told.items()]

        # Intent: inside the approved mission?
        gates: list[str] = []
        if mission is not None:
            outside: tuple[str, str] | None = None
            if act.act == "permission":
                tools = [t.get("name") for t in mission.blob.get("approved_tools", [])
                         if isinstance(t, dict)]
                if act.tool not in tools:
                    outside = (f"{md.code(act.tool)} is not an approved tool for this mission.",
                               "tool outside mission")
            elif act.resource and not cfg.allow_unlisted_resources:
                if act.resource not in mission.blob.get("approved_resources", []):
                    outside = (f"{act.resource} is not among the mission's approved resources.",
                               "resource outside mission")
            r = self._reach(reach, act, kind, [], gate="intent") if outside else None
            if r is not None:
                trace.append(f"reach {r.value}")
            elif outside is not None:
                asks.append(outside)
                gates.append("intent")

        # High impact acts need resource-asserted evidence. A permission act never has
        # any (its parameters come from the agent), so a high-impact tool is put to the
        # person unless the person already gave it reach, which also settles it before
        # any question to the agent. The agent is asked only when nothing else is open.
        # The resource's word is for the act's own class: a high-impact class the act only
        # may have besides (one not certain) has none.
        gated = bool(high) and (c.provenance != "resource" or (
            high != c.cls and not {a.cls: a.certain for a in c.blind}[high]))
        r = self._reach(reach, act, kind, [], gate="high_impact") if gated else None
        if r is not None:
            trace.append(f"reach {r.value}")
        elif gated:
            if not asks and clarify and cfg.clarify_missing_justification \
                    and not act.justification:
                return Decision("clarify", clarification=f"What is this {md.code(high)} act "
                                "for, and what will it send or change?", entry=entry, kind=kind,
                                trace=trace + ["clarify"])
            # What the person is told rests on what the supervisor has: the resource's
            # proposal or none, and a class it read or one the act only may have (assumed,
            # or another class it has with the agent's data set aside).
            unsure = c.uncertain or (high != c.cls and not {
                a.cls: a.certain for a in c.blind}[high])
            name, be = md.code(high), "may be" if unsure else "is"
            what = (f"This may be a {name} act: the resource's description of it does not "
                    f"show what the policy's rules read" if _described(act) and unsure else
                    f"This is a {name} act, and no rule of the policy reads its class from "
                    f"the resource's description of it" if _described(act) else
                    f"This {be} a {name} act, done with the agent's own tool, and the "
                    f"supervisor has only the agent's account of it" if act.act == "permission"
                    else f"This {be} a {name} act, and the supervisor has no detail of it from "
                    f"the resource")
            asks.append((what + (
                f"; the agent says: {md.code(act.justification.rstrip('.'))}"
                if act.justification else "") + ".", "high impact, no resource evidence"))
            gates.append("high_impact")

        if asks:
            comps = [comp for comp, _ in open_comps]
            # Where the person has already said no with reach, they are not asked again:
            # the SS applies the answer (Supervision L582), wherever recorded acts complete
            # the composition, another mission's or instance's included. Not where only an
            # act not yet history (an open ask or allow) completes it: that act may never
            # happen, and a "no" is about compositions acts complete.
            declined = comps
            if comps and any(h.open in _NOT_YET for h in history):
                recorded = {tuple(comp) for comp, _ in self._compositions_of(
                    c, [h for h in history if h.open not in _NOT_YET], now, act.ps_lead)}
                declined = [comp for comp in comps if tuple(comp) in recorded]
            if any(self._reach(reach, act, kind, comp, "deny") for comp in declined) or any(
                    self._reach(reach, act, kind, [], "deny", gate=g) for g in gates):
                return Decision("deny", reason=f"The person declined acts like this on "
                                f"{target}.", entry=entry, kind=kind, trace=trace + ["declined"])
            return Decision(
                "ask", summary=" ".join(text for text, _ in asks),
                certain=bool(open_comps) and open_comps[0][1] is False,
                recommendation="deny" if budget_asked or comps else "",
                apply_options=_apply_options(act.resource or md.code(act.tool),
                                             comps[0] if comps else None, cls=c.cls,
                                             via="on" if act.resource else "with",
                                             gates=gates, budget=budget_asked,
                                             in_mission=bool(act.mission_s256),
                                             settled=not open_comps or open_comps[0][1]
                                             is not None,
                                             certain=bool(open_comps)
                                             and open_comps[0][1] is False),
                entry=entry, kind=kind, composition=comps[0] if comps else [],
                compositions=comps, plain=bool(gates), gates=gates,
                trace=trace + [note for _, note in asks if note])

        return Decision("allow", entry=entry, kind=kind, trace=trace, narrow=self.narrow(mission),
                        composition=covered[0] if covered else [])

    def _decide_person_token(self, act: Act, mission: Mission | None, reach: list[Reach],
                             now: float) -> Decision:
        """A person token for a resource that does not serve on identity: an identity
        check, which composes with nothing; only where it may go is decided."""
        if any(_glob(p, act.resource) for p in self.cfg.deny_resources if act.resource):
            return Decision("deny", reason=f"{act.resource} is not permitted by policy.")
        if mission is not None and not self.cfg.allow_unlisted_resources:
            if act.resource not in mission.blob.get("approved_resources", []):
                kind = f"identity|{act.resource}"
                if self._reach(reach, act, kind, [], "deny"):
                    return Decision("deny", reason=f"The person declined to be identified "
                                    f"to {act.resource}.", kind=kind)
                if not self._reach(reach, act, kind, []):
                    return Decision("ask", summary=f"The agent asks to identify you to "
                                    f"{act.resource}, which is not among the mission's approved "
                                    f"resources.", kind=kind,
                                    apply_options=_apply_options(act.resource,
                                                                 identity=True))
        return Decision("allow", narrow=self.narrow(mission))

    def _resource_budget(self, act: Act, rb: ResourceBudget, history: list[HistoryEntry],
                         trace: list[str], pending: list[HistoryEntry]
                         ) -> tuple[str, str, str] | None:
        """AAuth Budgets at a metered resource: None when the offer fits the ceiling, else
        `deny` or `ask` with what the person or agent is told and a trace note.

        What this mission has committed at the resource is, per earlier allocation, the
        whole allocation (Budgets, Unreported Allocations: "the issuer MUST account for the
        allocation as fully consumed"), or the latest resource-signed `budget_consumed`
        for its token when that is higher: a record settles nothing (L841). The new
        allocation is the resource's offer, the most the PS may grant. Supervision -00
        gives the SS no way to grant less, so an offer that would cross the ceiling is put
        to the person with the headroom stated, not silently narrowed."""
        where = f"at {act.resource}"
        # Per mission; outside missions, one ceiling for every act outside them.
        ceiling = (f"the {_money(rb.max_amount, rb)} mission ceiling" if act.mission_s256
                   else f"the {_money(rb.max_amount, rb)} ceiling outside missions")
        prior = [h for h in history if h.resource == act.resource and not _person_token(h)]
        # A consumption record never lowers what an allocation holds: "A consumption
        # record settles nothing" (Budgets L841), the token "may spend more before it
        # expires" (L465), and a live allocation stays reserved until a reading settles it
        # (L847). It can only raise it, when the resource reports more than was allocated.
        committed = sum(max(h.allocated, h.consumed) if h.consumed is not None
                        else h.allocated for h in prior if h.unit == rb.denomination)
        if act.budget_amount == 0 and act.budget_unit == rb.denomination:
            return None  # a grant of 0 spends nothing (Budgets L344, L913)
        # The agent reads a deny's reason, and Budgets keeps the ceiling from it (L218).
        exhausted = ("deny", f"Budget exhausted {where}.", f"resource budget exhausted: "
                     f"{committed} of {rb.max_amount} {rb.denomination}")
        unknown = any(h.unit != rb.denomination for h in prior)
        # What is left, for the person: at most that, where an earlier act's spend there
        # is not known.
        left = f"{'at most ' if unknown else ''}{_money(rb.max_amount - committed, rb)}"
        # Allocations allowed or still being decided and not reported yet book nothing, but
        # the person is told what they may take.
        waiting = [h for h in pending if h.resource == act.resource
                   and not _person_token(h)]  # a person token carries no allocation
        held = sum(h.allocated for h in waiting if h.unit == rb.denomination)
        other = any(h.unit != rb.denomination for h in waiting)
        held_note = "" if not waiting else (
            " Allocations allowed or still being decided, not reported yet, may take " +
            " and ".join([f"{_money(held, rb)} more"] * (bool(held) or not other)
                         + ["an amount in another unit or scale"] * other) + ".")
        if committed >= rb.max_amount and (
                act.budget_amount is None or act.budget_unit != rb.denomination
                or any(h.unit != rb.denomination for h in prior)):
            # A spent ceiling only goes further with an offer it cannot compare: the
            # person's "yes" would pass it.
            return exhausted
        if act.budget_amount is None:
            return ("ask", f"{act.resource} is metered against {ceiling}, of which {left} is "
                    f"left, but it offered no budget for this act, so the spend cannot be "
                    f"bounded." + held_note, "resource budget: no offer")
        if act.budget_unit != rb.denomination:
            return ("ask", f"{act.resource} offers "
                    f"{_offered(act.budget_amount, act.budget_unit or '')}, but its ceiling is "
                    f"set in {rb.unit} with {_places(rb.decimals)}: {left} of {ceiling} is "
                    f"left." + held_note, "resource budget: other unit")
        if unknown:
            return ("ask", f"An earlier act {where} has no budget the supervisor can account "
                    f"for, so " + ("the mission's spend there" if act.mission_s256 else
                                   "the spend there outside missions") + " is unknown. This "
                    f"act offers {_money(act.budget_amount, rb)}, and "
                    f"{_money(committed, rb)} of {ceiling} is accounted for." + held_note,
                    "resource budget: unbounded history")
        offer = act.budget_amount
        trace.append(f"resource budget: committed {committed} + offer {offer} "
                     f"vs {rb.max_amount} {rb.denomination}")
        if committed + offer <= rb.max_amount:
            if not waiting:
                return None
            if other or committed + offer + held > rb.max_amount:
                return ("ask", _waiting_text(len(waiting), "allocation",
                                             f"{ceiling} {where}", known=not other)
                        + f" This act offers {_money(offer, rb)}, and "
                        f"{_money(rb.max_amount - committed, rb)} of {ceiling} is left."
                        + held_note, "resource budget: open allocations")
            return None
        if committed >= rb.max_amount:
            return exhausted
        return ("ask", f"{act.resource} offers {_money(offer, rb)}, but only "
                f"{_money(rb.max_amount - committed, rb)} of {ceiling} is left. The "
                f"supervisor has no way to grant a smaller amount." + held_note,
                "resource budget: offer over headroom")

    @staticmethod
    def _comp_summary(comps: list[list[str]], uncertain: bool | None,
                      doubts: list[str] | None = None, own: bool = False) -> str:
        """What the person is told of compositions the act completes: certain (`False`),
        possible (`True`, with the doubts it cannot confirm, each a sentence; `own` where
        only this act's are), or not settled (`None`)."""
        parts = [_names(c) for c in comps]
        names = parts[0] if len(parts) == 1 else "; ".join(parts[:-1]) + "; and " + parts[-1]
        what = ("a combination the policy forbids" if len(comps) == 1 else
                "combinations the policy forbids")
        if uncertain is None:
            # Unsettled: what is recorded does not settle the order of the acts (some
            # took place where it is not known), or the search ran out of its budget.
            return (f"The supervisor cannot tell whether this act completes {what}: {names}. "
                    f"What is recorded does not settle the order of those acts, or whether a "
                    f"token was still live at one of them, or settling it would take more "
                    f"work than the supervisor allows for one decision. It is treated as "
                    f"possible.")
        head = (f"Together with other acts, this act {'may' if uncertain else 'would'} "
                f"complete {what}: {names}.")
        if not uncertain:
            return head
        why = ("The supervisor is certain of the other acts, not of this one." if own else
               "The supervisor can neither confirm nor rule it out, as it cannot confirm "
               "every act that could complete it.")
        return " ".join([head, why, *(doubts or [])])

    def narrow(self, mission: Mission | None) -> dict[str, Any]:
        """The narrowing every `allow` under this mission carries: an `exp` no later than
        the mission's `expires_at`. Public so a policy layered on this one (see
        `examples/layered_policy.py`) narrows its own allows exactly the same way."""
        if mission is None:
            return {}
        exp = _iso_to_epoch(mission.blob.get("expires_at"))
        return {"exp": int(exp)} if exp is not None else {}

    # --------------------------------------------------------- missions

    def decide_proposal(self, body: dict[str, Any], now: float | None = None) -> Decision:
        now = time.time() if now is None else now
        resources_in, tools_in = body.get("resources", []), body.get("tools", [])
        if not isinstance(resources_in, list) or not isinstance(tools_in, list):
            raise ValueError("resources and tools must be arrays")
        resources = [r for r in resources_in if isinstance(r, str)]
        tools = [t for t in tools_in if isinstance(t, dict)]
        denied = [r for r in resources if any(_glob(p, r) for p in self.cfg.deny_resources)]
        if denied:
            return Decision("deny", reason=f"Not permitted by policy: {', '.join(denied)}.")
        approved_tools, asked = [], []
        for t in tools:
            name = str(t.get("name", ""))
            if any(_glob(p, name) for p in self.cfg.ask_tools):
                asked.append(t)
            elif any(_glob(p, name) for p in self.cfg.allowed_tools):
                approved_tools.append(t)
        refined: dict[str, Any] = {
            "description": body.get("description", ""),
            "approved_tools": approved_tools,
            "approved_resources": resources,
        }
        if self.cfg.max_mission_seconds:
            refined["expires_at"] = _epoch_to_iso(now + self.cfg.max_mission_seconds)
        if asked:
            # The supervisor's sentence first, then the agent's names, each cut and up to a
            # count, so the names cannot bury what the supervisor says.
            names = ", ".join(md.code(str(t.get("name")), MAX_TOOL_SHOWN)
                              for t in asked[:MAX_TOOLS_NAMED])
            more = (f" and {len(asked) - MAX_TOOLS_NAMED} more"
                    if len(asked) > MAX_TOOLS_NAMED else "")
            return Decision("ask", summary=f"The proposed refinement leaves out tools that "
                            f"need your approval, so approving it as proposed does not grant "
                            f"them: {names}{more}.",
                            narrow={"proposed": refined})
        return Decision("allow", narrow=refined)


# Which acts a budget counts though they may not be of its class, in the person's terms.
ASSUMED = ("this act or earlier ones, whose class was assumed because a request did not show "
           "what the policy's rules read")

# What makes a composition only possible, in the person's terms, in the order they are told.
_DOUBTS = (
    # Held above what the agent's details would make it (`Policy._static`): the agent's word
    # can only tighten.
    ("act-word", "The agent's own details would make this act less severe, and the "
                 "supervisor cannot check them."),
    ("act-assumed", "This act's class is assumed, because the request does not show what the "
                    "policy's rules read."),
    ("act-person-token", "This act is a person token, on which the resource may serve a "
                         "request."),
    # Another class the act has where the agent's details raised it, or one kept only with
    # them set aside (`Alias.set_aside`): a class resting on those details being false.
    ("act-blind", "Without the details the agent gave, this act may have another class."),
    ("blind", "Without the details the agent gave, an earlier act may have another class."),
    ("word", "The agent's own details would make an earlier act less severe, and the "
             "supervisor cannot check them."),
    ("assumed", "An earlier act's class was assumed, because what the supervisor received "
                "about it did not show what the policy's rules read."),
    ("open", "An earlier act is not settled yet: it is still being decided, or it was allowed "
             "and its token is not yet reported issued."),
    ("mission", "One of the acts is in another mission."),
    ("agent", "One of the acts is by another agent from the same provider."),
    ("link", "One of the acts is by another agent, which an act not settled yet may link to "
             "this one."),
    ("person_token", "A person token for {tokens} may have let that resource serve a "
                     "request."),
)


# What an ask says of a person token being decided: the PS's own text may say it first.
PERSON_TOKEN_TOLD = dict(_DOUBTS)["act-person-token"]


def _doubts(comp: list[str], c: Classification, history: list[HistoryEntry],
            act_only: bool = False) -> list[str]:
    """The kinds of uncertain evidence a composition can rest on: the act's own classes,
    and the uncertain entries that could take one of its other steps (an entry of another
    mission is uncertain wherever it is composed with acts of another scope,
    `Policy._compositions`); with `act_only`, the act's own only. An entry is named where
    its class could take a step, though the order of the acts, or a certain entry of
    that class, may leave it none."""
    kinds: set[str] = set()
    tokens: list[str] = []  # the resources the person tokens it rests on were issued for
    # Held above what the agent's details would make it: its other classes are what those
    # details may make of it, told by that.
    word = c.uncertain and c.provenance == "agent"
    if c.uncertain:
        kinds.add("act-person-token" if c.detail == PERSON_TOKEN else
                  "act-word" if word else "act-assumed")
    for a in c.blind:
        if a.cls not in comp or (a.certain and not a.assumed):
            continue
        if not a.assumed:
            kinds.add("act-blind")
        elif c.detail != PERSON_TOKEN:
            kinds.add(("act-word" if word else "act-blind") if a.set_aside else "act-assumed")
    if act_only:
        return [text for k, text in _DOUBTS if k in kinds and k.startswith("act-")]
    mine = {c.cls, *(a.cls for a in c.blind)} & set(comp)
    # Where the act can take one step only, an earlier act of that class takes none.
    steps = set(comp) - mine if len(mine) == 1 and comp.count(next(iter(mine))) == 1 \
        else set(comp)
    near = [h for h in history if {k for k, _ in _entry_classes(h)} & steps]
    # A mission of the agent's, outside missions, composes certainly with the act on its
    # own (`Policy._compositions`): it is a doubt only where acts of another scope are
    # needed too.
    spread = len({h.scope for h in near if h.scope}) > 1
    for h in near:
        if any(a.cls in steps and (not a.certain or _uncertain(h)) and not a.assumed
               for a in h.blind):
            kinds.add("blind")
        # Where the act is (not settled yet, another mission, another agent), and what it
        # is (a person token, a class resting on the agent's word or assumed): each named.
        if h.open in ("own", "other"):
            kinds.add("open")
        elif h.open == "mission" or (h.scope and not h.open and spread):
            kinds.add("mission")
        elif h.open in ("agent", "link"):
            kinds.add(h.open)
        own = h.detail.split(": ", 2)[2] if h.open and h.detail.count(": ") >= 2 else h.detail
        if own.endswith(PERSON_TOKEN):
            kinds.add("person_token")
            if h.resource not in tokens:
                tokens.append(h.resource)
        elif own.startswith("uncertain"):
            kinds.add("word" if h.provenance == "agent" else "assumed")
        else:
            kinds.update("blind" if a.set_aside else "assumed" for a in h.blind
                         if a.cls in steps and a.assumed)
    return [text.format(tokens=" or ".join(tokens)) for k, text in _DOUBTS if k in kinds]


def _uncertain(h: HistoryEntry) -> bool:
    """Whether an entry rests on uncertain evidence."""
    return h.detail.startswith("uncertain")


def _entry_classes(h: HistoryEntry) -> list[tuple[str, bool]]:
    """The classes an entry has, each with whether it rests on uncertain evidence there:
    its own, and each further class the agent's data raised it from, uncertain where that
    class was and wherever the act itself is (another agent's, another mission's, not
    settled yet)."""
    unc = _uncertain(h)
    return [(h.action_class, unc)] + [(a.cls, unc or not a.certain) for a in h.blind]


def _has(h: HistoryEntry, cls: str) -> bool:
    """Whether `cls` is one of the entry's classes."""
    return h.action_class == cls or any(a.cls == cls for a in h.blind)


def _assumed_in(h: HistoryEntry, cls: str) -> bool:
    """Whether an entry is of `cls` only as a class assumed for data a rule needs."""
    return h.action_class != cls and all(a.assumed for a in h.blind if a.cls == cls)


def _as(h: HistoryEntry, cls: str) -> tuple[int, bool]:
    """The amount an entry counts for the budget of one of its classes, and whether it is
    known: its own for its class, the further class's rule's for that class."""
    if h.action_class == cls:
        return h.amount, h.amount_known
    a = {x.cls: x for x in h.blind}[cls]  # `_has(h, cls)` holds: the class is there
    return a.amount, a.amount_known


def _assumed_as(c: Classification, classes: list[tuple[str, int | None]],
                unread: bool = False) -> Classification:
    """A class assumed (uncertain, for data a rule needs and does not have) is also each
    class the rules would give the act with that data (the closing rule's own, and each
    unread data rule's), uncertain: it composes as any of them, as an act whose class the
    agent's data raised does, and counts with the amount that class's rule reads (the
    most, where several do; not known where one reads none). So is a class read where an
    unread data rule could have given another (`unread`: no rule named its operations)."""
    assumed = c.uncertain and c.detail.startswith("data needed")
    if c.detail == PERSON_TOKEN or not (assumed or unread):
        return c
    amounts: dict[str, list[int | None]] = {}
    for cls, amount in classes:
        amounts.setdefault(cls, []).append(amount)
    # The act's own class counts the most any rule of that class reads (the closing rule's
    # where none of them reads one), as each further class does.
    own = [a for a in [c.amount, *amounts.get(c.cls, [])] if a is not None]
    c.amount = max(own) if own else None
    for cls, seen in amounts.items():
        if cls != c.cls and all(a.cls != cls for a in c.blind):
            known = [a for a in seen if a is not None]
            most = max(known) if len(known) == len(seen) else None
            c.blind.append(Alias(cls, False, most or 0, most is not None, assumed=True))
    return c


def _alias(c: Classification) -> Alias:
    """A further class of an act, from the classification that gave it."""
    return Alias(c.cls, not c.uncertain, c.amount or 0, c.amount is not None)


def _person_token(h: HistoryEntry) -> bool:
    """A person token recorded as an act: it may have been access, so it composes, but it
    spends no budget (no count, and no allocation at a metered resource)."""
    return h.detail.endswith(PERSON_TOKEN)


def _firmness(uncertain: bool | None) -> int:
    """Certain first, then unsettled (the order is not settled), then uncertain."""
    return 0 if uncertain is False else 1 if uncertain is None else 2


def _described(act: Act) -> bool:
    """Whether a proposal the resource bound into its token names the act's operations or
    parameters: the resource's word for what the act does."""
    return act.parameters_provenance == "resource" and bool(act.operations or act.parameters)


def _names(classes: list[str]) -> str:
    """Classes as the person reads them: each the policy's own name, in a code span, in
    the order they would take effect."""
    return ", then ".join(md.code(c) for c in classes)


def _waiting_text(count: int, what: str, limit: str, known: bool = True) -> str:
    """What the person is told when acts not yet settled (`what`, a singular noun) and
    this one would take a budget past its limit once they happen: "may" where the
    supervisor does not know what each of them is or spends (`known`)."""
    verb = "would" if known else "may"
    if count == 1:
        return (f"An earlier {what} is allowed or still being decided, and has not been "
                f"reported done yet. If it goes ahead, it and this act together {verb} take "
                f"{limit} past its limit.")
    return (f"{count} earlier {what}s are allowed or still being decided, and have not been "
            f"reported done yet. If they go ahead, they and this act together {verb} take "
            f"{limit} past its limit.")


def _places(decimals: int) -> str:
    return f"{decimals} decimal place{'' if decimals == 1 else 's'}"


def _money(amount: int, rb: ResourceBudget) -> str:
    """An integer amount in the resource's scale, printed exactly: 2500 at 2 decimals is
    "25.00 USD". Integer arithmetic only, as Budgets' Value Representation requires."""
    return _scaled(amount, rb.unit, rb.decimals)


def _scaled(amount: int, unit: str, decimals: int) -> str:
    if decimals == 0:
        return f"{amount} {unit}"
    whole, frac = divmod(amount, 10 ** decimals)
    return f"{whole}.{frac:0{decimals}d} {unit}"


def _offered(amount: int, denomination: str) -> str:
    """A resource's offer in its own unit and scale, as the person reads it: 150 at
    `EUR/2` is "1.50 EUR". The unit is the resource's word: shown plain only as a short
    word of ASCII letters, else quoted (and cut), so it can neither bury the text around
    it, be unseen, nor pass for another unit."""
    unit, _, decimals = denomination.rpartition("/")
    if unit and decimals.isdigit() and int(decimals) <= MAX_DECIMALS:
        plain = unit.isascii() and unit.isalpha() and len(unit) <= 16
        return _scaled(amount, unit if plain else md.code(unit), int(decimals))
    return f"{amount} in {md.code(denomination)}"


def _apply_options(target: str, composition: list[str] | None = None, *, cls: str = "",
                   via: str = "on", gates: Sequence[str] = ("intent",), budget: bool = False,
                   in_mission: bool = True, settled: bool = True, certain: bool = False,
                   identity: bool = False) -> list[dict[str, str]]:
    """The reaches an ask offers: exactly those the SS will apply to the answer.

    A budget is a ceiling no remembered answer passes, so a budget ask offers this act
    only; so does a composition the order does not settle, which no answer covers.
    A composition answer holds for the rest of a mission, for that composition; outside
    any mission nothing would bound it, so it is this act only there. An answer for the
    gates that asked (`gates`) is applied, an `allow` or a `deny` alike, where the same
    gate would ask again: for a resource or tool the mission leaves out, in every mission
    that leaves it out; for a high-impact act, wherever it would be asked for that. Each
    label names what the answer is keyed on: the act's class (as "acts like this") and its
    target, which the caller gives as Markdown (a tool name, the agent's, is quoted), this
    agent, where it applies, and the scope."""
    once = [{"value": "once", "label": "This act only"}]
    if budget or not settled:
        return once
    acts = f"{md.code(cls)} acts by this agent {via} {target}"
    left_out = f"in {'a' if identity else 'any'} mission that does not include it"
    if identity:
        what = f"Identifying you to {target} when this agent asks"
    elif "high_impact" in gates:
        why = "the same reason" if len(gates) == 1 else "one of the same reasons"
        what = f"{acts} that the supervisor would ask you about for {why}"
    else:
        what = acts
    if composition:
        if not in_mission:
            return once
        names = _names(composition)
        # The label names the reach, never the answer: the person may give it to a deny.
        # One given to a "may" never covers a completion that would be certain.
        verb = "complete" if certain else "may complete"
        label = (f"{acts} that {verb} {names}" if not gates else
                 f"{what} or that {verb} {names}" if what != acts else
                 f"{acts}, including when they {verb} {names}")
        return once + [{"value": "mission", "label": f"{label}, for the rest of this mission"}]
    scope = ", for the rest of this mission" if in_mission else ", outside missions, from now on"
    # Where only a mission that leaves the target out asks, no other place would.
    always = (f" {left_out}" if identity else f", {left_out}" if what == acts else
              ", in any mission or none")
    return once + [{"value": "mission", "label": what + scope},
                   {"value": "always", "label": f"{what}{always}, from now on"}]


def _epoch_to_iso(t: float) -> str:
    from datetime import datetime

    return datetime.fromtimestamp(int(t), tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
