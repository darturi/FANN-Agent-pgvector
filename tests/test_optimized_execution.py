"""Native bypass proofs, owned handles and two-exchange failure boundaries."""

from copy import deepcopy

import pytest
from fannagent.api import AgentError
from test_policy_transport import ClientCursor, Connection, Cursor, make_backend, policy

from fannagent_pgvector.native import fused
from fannagent_pgvector.optimized import (
    ExecutionHandle,
    OptimizedNativeBackend,
    OptimizedPredicateContextBackend,
    PreparedNativeBackend,
)
from fannagent_pgvector.routing import cannot_stop


def branch(condition, yes="stop", no="continue"):
    return {"if": condition, "then": yes, "else": no}


def compare(name, value):
    return {"op": "gte", "args": [{"feature": name}, {"int": value}]}


def guarded(root):
    return branch({"op": "is_available", "args": [{"feature": "completed_expansions"}]}, root)


def test_router_uses_actual_threshold_and_preserves_availability_errors():
    root = guarded(
        branch(
            compare("completed_expansions", 23),
            branch(compare("query_predicate_threshold", 108), "continue", "stop"),
        )
    )
    assert cannot_stop(root, {"query_predicate_threshold": 108})
    assert not cannot_stop(root, {"query_predicate_threshold": 32})
    assert not cannot_stop(root, {})
    assert not cannot_stop(branch(compare("completed_expansions", 23), "continue"), {})
    assert cannot_stop(guarded(branch(compare("completed_expansions", 23), "continue")), {})


@pytest.mark.parametrize("value", [0, 32, 108, 2**63 - 1])
def test_int64_query_context_proof(value):
    root = branch(
        {"op": "eq", "args": [{"feature": "query_predicate_threshold"}, {"int": value}]},
        "continue",
        "stop",
    )
    assert cannot_stop(root, {"query_predicate_threshold": value})
    assert not cannot_stop(
        root, {"query_predicate_threshold": value + 1 if value < 2**63 - 1 else value - 1}
    )


@pytest.mark.parametrize(
    "bad",
    [
        {"op": "div", "args": [{"int": 1}, {"int": 0}]},
        {"op": "add", "args": [{"int": 2**63 - 1}, {"int": 1}]},
        {"op": "div", "args": [{"int": 2**63 - 1}, {"int": 1}]},
        {"op": "mul", "args": [{"feature": "completed_expansions"}, {"int": 2}]},
    ],
)
def test_router_never_hides_arithmetic_failure(bad):
    condition = {"op": "gt", "args": [bad, {"float": 0.0} if bad["op"] == "div" else {"int": 0}]}
    assert not cannot_stop(guarded(branch(condition, "continue")), {})
    assert not cannot_stop(
        branch({"op": "and", "args": [{"bool": False}, condition]}, "continue"), {}
    )


class FusedCursor(ClientCursor):
    def execute(self, statement, params):
        text = statement.as_string() if hasattr(statement, "as_string") else statement
        if "search" not in text:
            return super().execute(statement, params)
        self.kind = "search"
        self.conn.events.append("batch_search_execute")
        if self.conn.fail == "batch_search_execute":
            raise RuntimeError("batch_search_execute")
        self.results = []
        offset = 0
        if "install_policy" in text:
            self.results.append(self.conn.execute("install_policy", params[:2]))
            offset = 2
        self.results += [
            self.conn.execute("BEGIN"),
            self.conn.execute("begin_execution", params[offset:]),
            self.conn.execute("search"),
        ]
        if self.conn.wrong == "missing_search":
            self.results.pop()
        if self.conn.wrong == "extra_search":
            self.results.append(Cursor(self.conn, "extra", None))

    @property
    def statusmessage(self):
        kind = self.results[self.position].kind
        if kind == "install_policy":
            return "SELECT 1"
        if kind == "search":
            return "SELECT " + str(
                len(self.conn.rows) + (1 if self.conn.wrong == "search_count" else 0)
            )
        return super().statusmessage

    @property
    def description(self):
        kind = self.results[self.position].kind
        if kind == "install_policy":
            return [object()]
        if kind == "search":
            return [object()] * (1 if self.conn.wrong == "search_shape" else 2)
        return super().description

    def fetchall(self):
        return self.results[self.position].fetchall()


@pytest.fixture(autouse=True)
def client_cursor(monkeypatch):
    monkeypatch.setattr(fused.psycopg, "ClientCursor", FusedCursor)


QUERY = {"id": "arbitrary-votes108", "vector": [1.0, 0.0], "k": 10, "filter": None}


def backend(kind=OptimizedNativeBackend, conn=None):
    old, conn, validations = make_backend(conn)
    new = kind(old.config, None)
    for name in ("conn", "_binding_conn", "_binding", "_snapshot", "_statement"):
        setattr(new, name, getattr(old, name))
    return new, conn, validations


def test_fused_activation_and_reuse_have_two_exchanges_and_actual_row_count():
    b, c, validation = backend()
    handle = b.prepare_execution(policy())
    for _ in range(2):
        r = b.execute_prepared(QUERY, handle)
        assert r.ids == [0, 1] and r.metadata["query_route"] == "policy"
    assert c.events.count("batch_search_execute") == c.events.count("batch_complete_execute") == 2
    assert c.events.count("install_policy") == 1 and c.events.count("search") == 2
    assert "batch_begin_execute" not in c.events and validation == [QUERY, QUERY]


@pytest.mark.parametrize("rows", [[], [(-5, 0.2)]])
def test_fused_completion_counts_partial_and_empty_results(rows):
    b, c, _ = backend(conn=Connection())
    c.rows = rows
    r = b.execute_prepared(QUERY, b.prepare_execution(policy()))
    assert len(r.ids) == len(rows) and "drained:complete" in c.events


@pytest.mark.parametrize(
    "wrong",
    [
        "install",
        "nonce",
        "telemetry",
        "binding",
        "search_shape",
        "search_count",
        "missing_search",
        "extra_search",
        "rollback",
        "commit_intrans",
        "begin_idle",
    ],
)
def test_bad_ack_never_accepts_fused_result_or_replays(wrong):
    b, c, _ = backend(conn=Connection(wrong=wrong))
    h = b.prepare_execution(policy())
    with pytest.raises(AgentError):
        b.execute_prepared(QUERY, h)
    assert c.closed and b._installed is None and b._binding is None and not b._executions
    assert c.events.count("search") <= 1


@pytest.mark.parametrize(
    "fail",
    [
        "install_policy",
        "BEGIN",
        "begin_execution",
        "search",
        "complete",
        "COMMIT",
        "batch_search_execute",
        "batch_search_nextset",
        "batch_complete_execute",
        "batch_complete_nextset",
        "batch_close",
    ],
)
def test_fused_error_closes_session_without_automatic_fallback(fail):
    b, c, _ = backend(conn=Connection(fail=fail))
    h = b.prepare_execution(policy())
    with pytest.raises(RuntimeError, match=fail):
        b.execute_prepared(QUERY, h)
    assert c.closed and not b._executions and c.events.count("search") <= 1


@pytest.mark.parametrize("routing", ["static", "unfiltered"])
def test_continue_bypass_does_no_policy_control_work(routing):
    b, c, v = backend()
    r = b.execute_prepared(QUERY, b.prepare_execution(policy(), routing=routing))
    assert r.metadata["query_route"] == "native_bypass" and r.metadata["ordinary_default"]
    assert c.events == ["search", "fetch:search"] and v == [QUERY]
    assert b._installed is None


def test_unfiltered_route_uses_predicate_not_id_and_handles_own_policy():
    b, c, _ = backend()
    raw = {**policy(), "root": "stop"}
    h = b.prepare_execution(raw, routing="unfiltered")
    raw["root"] = "continue"
    r = b.execute_prepared(QUERY, h)
    assert r.metadata["query_route"] == "policy"
    q = {
        **QUERY,
        "id": "arbitrary-unfiltered",
        "filter": {"field": "m_000000", "op": "gte", "value": 32},
    }
    r = b.execute_prepared(q, h)
    assert r.metadata["query_route"] == "native_bypass"
    assert c.events.count("begin_execution") == 1


def test_context_route_reads_actual_predicate_and_rejects_unsupported_before_search():
    b, c, _ = backend(OptimizedPredicateContextBackend)
    raw = {
        "name": "p",
        "feature_groups": ["query_context"],
        "root": branch(compare("query_predicate_threshold", 108), "continue", "stop"),
    }
    h = b.prepare_execution(raw, routing="static")
    q = {**QUERY, "filter": {"field": "m_000000", "op": "gte", "value": 108}}
    assert b.execute_prepared(q, h).metadata["query_route"] == "native_bypass"
    q["filter"]["value"] = 32
    assert b.execute_prepared(q, h).metadata["query_route"] == "policy"
    q["filter"]["value"] = True
    with pytest.raises(AgentError):
        b.execute_prepared(q, h)
    assert c.closed and c.events.count("search") == 2


def test_foreign_released_forged_and_closed_handles_are_rejected():
    for mode in ("foreign", "release", "forged", "closed"):
        b, c, _ = backend()
        h = b.prepare_execution(policy())
        if mode == "foreign":
            b, _, _ = backend()
        elif mode == "release":
            b.release_execution(h)
        elif mode == "forged":
            h = ExecutionHandle(h.policy_hash, h.routing)
        else:
            b.close()
        with pytest.raises(AgentError, match="handle"):
            b.execute_prepared(QUERY, h)
        assert not getattr(b, "_executions", {})


def test_mutating_handle_fields_does_not_change_private_execution_plan():
    b, c, _ = backend()
    h = b.prepare_execution(policy(), routing="off")
    object.__setattr__(h, "routing", "static")
    object.__setattr__(h, "policy_hash", "forged")
    r = b.execute_prepared(QUERY, h)
    assert r.metadata["query_route"] == "policy" and r.metadata["requested_policy_hash"] != "forged"


def test_handle_does_not_skip_mutated_query_validation():
    b, c, _ = backend()
    h = b.prepare_execution(policy(), routing="static")
    q = deepcopy(QUERY)
    b.execute_prepared(q, h)
    q["vector"].append(0.0)
    with pytest.raises(AgentError, match="dimensions"):
        b.execute_prepared(q, h)
    assert c.events.count("search") == 1


def test_unavailable_fused_transport_retains_acknowledged_sequential_execution():
    b, c, _ = backend()
    c.autocommit = False
    r = b.execute_prepared(QUERY, b.prepare_execution(policy()))
    assert r.metadata["transport_variant"] == "sequential"
    assert "transaction:enter" in c.events and "batch_search_execute" not in c.events


def test_preparation_is_bounded_and_never_accepts_public_prepared_object():
    b, _, _ = backend()
    with pytest.raises(AgentError):
        b.prepare_execution(b._prepare_policy(policy()))
    handles = [b.prepare_execution(policy(str(i))) for i in range(32)]
    with pytest.raises(AgentError, match="release"):
        b.prepare_execution(policy("extra"))
    b.release_execution(handles[0])
    b.prepare_execution(policy("extra"))


def test_prepared_only_control_reuses_private_handle_with_original_transport():
    # Use the ordinary control-batch cursor for this decomposition control.
    from unittest.mock import patch

    with patch.object(fused.psycopg, "ClientCursor", ClientCursor):
        b, c, _ = backend(PreparedNativeBackend)
        h = b.prepare_execution(policy())
        for _ in range(2):
            b.execute_prepared(QUERY, h)
        assert c.events.count("batch_begin_execute") == 2 and c.events.count("install_policy") == 1
        assert "batch_search_execute" not in c.events


def test_handle_is_minted_after_initial_connection_reset_and_rejected_after_reconnect():
    b, c, _ = backend()
    b.conn = None

    def connect():
        if b.conn is None:
            b.close()
            b.conn = b._binding_conn = c
            b._binding = {"index": {"oid": 8}}
        return b.conn

    b._connect = connect
    h = b.prepare_execution(policy())
    b.execute_prepared(QUERY, h)
    b.conn = None
    with pytest.raises(AgentError, match="handle"):
        b.execute_prepared(QUERY, h)
    assert c.events.count("search") == 1


def test_opt_in_serving_session_bypasses_and_returns_source_bigint_ids(monkeypatch):
    b, c, _ = backend()
    b._snapshot.id_to_source = {0: "-5", 1: str(2**63 - 1)}
    monkeypatch.setattr(b, "_check_security", lambda: None)
    session = b.open_policy_session(policy(), routing="static")
    result = session.query(QUERY, fallback=False)
    assert result.ids == [-5, 2**63 - 1]
    assert result.metadata["query_route"] == "native_bypass"
    assert c.events == ["search", "fetch:search"] and session.preparation_ms > 0
    session.close()
    assert not b._executions


def test_opt_in_serving_session_never_falls_back_without_authorization(monkeypatch):
    b, c, _ = backend(conn=Connection(fail="search"))
    monkeypatch.setattr(b, "_check_security", lambda: None)
    session = b.open_policy_session(policy(), routing="off")
    with pytest.raises(RuntimeError, match="search"):
        session.query(QUERY, fallback=False)
    assert c.events.count("search") == 1 and c.closed
