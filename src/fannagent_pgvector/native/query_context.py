"""Strict extraction of the actual predicate scalar for the v1 study."""

from fannagent.api import AgentError


def predicate_threshold(query):
    predicate = query.get("filter")
    if predicate is None:
        return 0
    if not isinstance(predicate, dict) or set(predicate) != {"field", "op", "value"}:
        raise AgentError("predicate-context-v1 requires one m_000000 >= int64 predicate")
    value = predicate["value"]
    if (
        predicate["field"] != "m_000000"
        or predicate["op"] != "gte"
        or type(value) is not int
        or not 0 <= value < 2**63
    ):
        raise AgentError("predicate-context-v1 requires m_000000 >= nonnegative int64")
    return value
