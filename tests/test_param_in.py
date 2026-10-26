"""`param_in`: a rule that reads a code the resource states, matched against a set.

The rule matches when each parameter it names carries a value in its set; a list matches
when any of its values does, as recipients do. A parameter the act does not carry, or a
value the SS cannot read as a code (an R3 digest object, a float, an object), leaves the
rule undecided, so `if_unknown` and the agent-data rules apply exactly as they do for the
other data rules.
"""
from __future__ import annotations

from typing import Any

import pytest

from aauth_supervision_server.adversarial import AGENT, SUB, build
from aauth_supervision_server.policy import Act, Policy, PolicyConfig

SHOP = "https://shop.example"
CODES = ["restricted", "1001"]
POLICY: dict[str, Any] = {
    "severity": ["unclassified", "purchase", "restricted"],
    "high_impact": ["restricted"],
    "rules": [
        {"resource": SHOP, "operation": "buy", "param_in": {"category": CODES},
         "class": "restricted"},
        {"resource": SHOP, "operation": "buy", "class": "purchase", "if_unknown": "restricted"},
        {"resource": SHOP, "class": "purchase", "if_unknown": "restricted"},
    ],
    "r3_member": "r3_proposal",
}


def classify(params: dict[str, Any] | None, provenance: str = "resource",
             **rule: Any) -> tuple[str, bool]:
    d = POLICY | {"rules": [POLICY["rules"][0] | rule, *POLICY["rules"][1:]]}
    c = Policy(PolicyConfig.from_dict(d)).classify(Act(
        "auth_token", "https://ps.example", SUB, AGENT, "m-1", SHOP, ["buy"],
        parameters=params, parameters_provenance=provenance))
    return c.cls, c.uncertain


@pytest.mark.parametrize("category", ["restricted", 1001, "1001", ["books", "restricted"], [1001]])
def test_a_value_in_the_set_matches(category: Any) -> None:
    assert classify({"category": category}) == ("restricted", False)


@pytest.mark.parametrize("category", ["books", 1002, "01001", "restricted ", "Restricted",
                                      ["books", "games"], []])
def test_a_value_outside_the_set_does_not(category: Any) -> None:
    assert classify({"category": category}) == ("purchase", False)


@pytest.mark.parametrize("params", [
    None,
    {"amount": 5000},
    {"category": {"s256": "abc"}},
    {"category": 1001.0},
    {"category": True},
    {"category": None},
    {"category": ["books", {"s256": "abc"}]},
])
def test_a_value_the_ss_cannot_read_leaves_the_rule_undecided(params: Any) -> None:
    assert classify(params) == ("restricted", True)


def test_every_parameter_it_names_must_match() -> None:
    both = {"param_in": {"category": CODES, "region": ["eu"]}}
    assert classify({"category": "restricted", "region": "eu"}, **both) == ("restricted", False)
    assert classify({"category": "restricted", "region": "us"}, **both) == ("purchase", False)
    assert classify({"category": "restricted"}, **both) == ("restricted", True)


def test_agent_asserted_codes_can_raise_the_class_but_never_lower_it() -> None:
    assert classify({"category": "restricted"}, "agent")[0] == "restricted"
    assert classify({"category": "books"}, "agent") == ("restricted", True)


@pytest.mark.parametrize("value", [{}, [], ["category"], {"category": []},
                                   {"category": "restricted"}, {"category": [1001]},
                                   {1: ["restricted"]}])
def test_the_loader_refuses_a_malformed_param_in(value: Any) -> None:
    with pytest.raises(ValueError, match=r"rules\[0\]\.param_in: must map parameter names to "
                                         r"non-empty arrays of strings"):
        PolicyConfig.from_dict({"severity": ["x"], "rules": [{"class": "x", "param_in": value}]})


@pytest.mark.parametrize("config, category, kind, decision", [
    ("apc/forwarded+issued", "books", "purchase", "allow"),
    # The resource stated the code in the proposal its token binds: the class rests on its word.
    ("apc/forwarded+issued", "restricted", "restricted", "allow"),
    # Supervision -00 as written: the SS has no proposal, so the class is assumed and the
    # high-impact act goes to the person.
    ("apc/current", "books", "restricted", "ask"),
])
def test_the_class_is_read_from_the_forwarded_r3_proposal(config: str, category: str, kind: str,
                                                          decision: str) -> None:
    ss, ps, _ = build(config, POLICY)
    ps.connect(ss, SUB)
    _, s256 = ps.propose_and_approve(ss, SUB, AGENT, "# Buy a book", [SHOP])
    sdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, SHOP, proposal={
        "operations": [{"operationId": "buy"}], "parameters": {"category": category}})
    assert r.json()["decision"] == decision
    assert ss.store.decisions[ss.store.k(ps.issuer, sdi)].kind == f"{kind}|{SHOP}"
