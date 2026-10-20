"""Conservative query-only proof that a validated policy cannot stop."""

from __future__ import annotations

from fannagent.api import FeatureValue, PolicyInput
from fannagent.api.primitives.interpreter import _evaluate_expression

UNKNOWN = object()
UNSAFE = object()


def _available(expression):
    if expression.get("op") == "is_available":
        return {expression["args"][0]["feature"]}
    if expression.get("op") == "and":
        return set().union(*(_available(a) for a in expression["args"]))
    return set()


def _value(expression, known, available):
    if "feature" in expression:
        name = expression["feature"]
        return known[name] if name in known else UNKNOWN if name in available else UNSAFE
    for literal in ("bool", "int", "float"):
        if literal in expression:
            return expression[literal]
    op = expression["op"]
    if op == "is_available":
        name = expression["args"][0]["feature"]
        return True if name in known or name in available else UNKNOWN
    values = [_value(a, known, available) for a in expression["args"]]
    if any(v is UNSAFE for v in values):
        return UNSAFE
    if any(v is UNKNOWN for v in values):
        # Unknown arithmetic might overflow or divide by zero. Eager Boolean
        # evaluation cannot discard an unsafe operand via short circuiting.
        return UNSAFE if op in {"add", "sub", "mul", "div"} else UNKNOWN
    try:
        inputs = PolicyInput(
            features={n: FeatureValue(available=True, value=v) for n, v in known.items()}
        )
        return _evaluate_expression(expression, inputs, frozenset())
    except (ValueError, TypeError, ArithmeticError):
        return UNSAFE


def cannot_stop(root, known):
    """Prove every reachable leaf continues; uncertainty always keeps the policy.

    Availability guards establish which dynamic comparisons are total. Query
    context is supplied only from the actual validated query, never its ID.
    """

    def visit(node, available):
        if isinstance(node, str):
            return node == "continue"
        value = _value(node["if"], known, available)
        if value is UNSAFE:
            return False
        if value is True:
            return visit(node["then"], available | _available(node["if"]))
        if value is False:
            return visit(node["else"], available)
        return visit(node["then"], available | _available(node["if"])) and visit(
            node["else"], available
        )

    return visit(root, set(known))
