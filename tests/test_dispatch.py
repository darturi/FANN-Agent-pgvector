"""Validation parity, bounded query-only proof reuse and native failure boundaries."""

from copy import deepcopy
from types import SimpleNamespace

import numpy as np
import pytest
from fannagent.api import AgentError, ProbeResult
from fannagent.snapshot import Snapshot
from psycopg import pq
from test_optimized_execution import FusedCursor
from test_policy_transport import Connection

from fannagent_pgvector import dispatch
from fannagent_pgvector.dispatch import (
    DispatchNativeBackend,
    DispatchPredicateContextBackend,
    RoutedPredicateContextBackend,
    ValidatedPredicateContextBackend,
)
from fannagent_pgvector.native import fused
from fannagent_pgvector.optimized import ExecutionHandle
from fannagent_pgvector.profiles import DATA_PROFILE
from fannagent_pgvector.query_validation import validate_query

QUERY = {"id": "q", "vector": [1.0, 0.0], "k": 10}


def snapshot():
    return Snapshot(
        [
            {"source_id": i, "vector": [1.0, 0.0], "metadata": {"votes": 108}}
            for i in (-5, 2**63 - 1)
        ],
        [{"name": "votes", "type": "integer", "allowed_ops": ["eq", "in", "gte"]}],
        DATA_PROFILE,
    )


def backend(kind=DispatchPredicateContextBackend):
    b = kind(
        SimpleNamespace(
            copy=SimpleNamespace(trace_max_bytes=1024),
            target=SimpleNamespace(
                schema_name="public", resource="reviews", id_column="id", vector_column="embedding"
            ),
        ),
        None,
    )
    b.conn = b._binding_conn = Connection()
    b._binding = {"index": {"oid": 8}}
    b._snapshot = snapshot()
    return b, b.conn


@pytest.fixture(autouse=True)
def client(monkeypatch):
    class Cursor(FusedCursor):
        def execute(self, statement, params):
            return super().execute(
                statement.as_string() if hasattr(statement, "as_string") else statement, params
            )

    monkeypatch.setattr(fused.psycopg, "ClientCursor", Cursor)


def outcome(fn):
    try:
        return ("ok", fn())
    except Exception as exc:
        return (type(exc), str(exc), exc.__dict__)


@pytest.mark.parametrize(
    "change",
    [
        {},
        {"schema_version": 1},
        {"filter": None},
        {"k": "2"},
        {"vector": ["1", "0"]},
        {"vector": [True, False]},
        {"vector": [float("nan"), 0]},
        {"vector": [float("inf"), 0]},
        {"vector": [1e300, 0]},
        {"vector": [0, 0]},
        {"vector": [1, 2]},
        {"vector": [1, 0, 0]},
        {"vector": None},
        {"vector": (1, 0)},
        {"vector_ref": {"file": "x", "id": "y"}},
        {"extra": True},
        {"id": ""},
        {"id": 1},
        {"k": 0},
        {"k": 10001},
        {"k": 1000},
        {"k": True},
        *[
            {"filter": p}
            for p in [
                {},
                {"field": "votes", "op": "gte", "value": 32},
                {"field": "m_000000", "op": "in", "value": [1, 2]},
                {"field": "m_000000", "op": "gte", "value": True},
                {"field": "m_000000", "op": "gte", "value": 2**63},
                {"field": "m_000000", "op": "gte", "value": None},
                {"field": "m_000000", "op": "lt", "value": 32},
                {"field": "unknown", "op": "gte", "value": 32},
                {"field": "m_000000", "op": "eq", "value": float("nan")},
                {"field": "m_000000", "op": "is_null"},
                {"not": {"field": "votes", "op": "gte", "value": 32}},
                {"and": [{"field": "votes", "op": "gte", "value": 32}]},
                {"or": [None]},
            ]
        ],
    ],
)
def test_common_validator_matches_shared_values_and_errors(change):
    raw = {**QUERY, **change}
    s = snapshot()
    assert outcome(lambda: validate_query(s, raw)) == outcome(lambda: s.query(raw))


def test_validator_matches_float32_normalization_boundaries_and_random_vectors():
    s = snapshot()
    for norm in np.linspace(0.99997, 1.00003, 1001, dtype=np.float32):
        raw = {**QUERY, "vector": [float(norm), 0.0]}
        assert outcome(lambda: validate_query(s, raw)) == outcome(lambda: s.query(raw))
    rng = np.random.default_rng(17)
    for _ in range(150):
        vector = rng.normal(size=2)
        vector /= np.linalg.norm(vector)
        raw = {**QUERY, "vector": vector.tolist()}
        assert validate_query(s, raw) == s.query(raw)


def test_canonical_query_owns_vector_and_membership_values():
    raw = {
        **QUERY,
        "vector": [1.0, 0.0],
        "filter": {"field": "votes", "op": "in", "value": [32, 108]},
    }
    q = validate_query(snapshot(), raw)
    prior = deepcopy(q)
    raw["vector"][0] = 0
    raw["filter"]["value"].append(500)
    assert q == prior


def test_routing_cache_uses_validated_actual_context_and_rejects_mutation(monkeypatch):
    b, c = backend(RoutedPredicateContextBackend)
    b._statement = lambda query: ("search", [])
    raw = {
        "name": "context",
        "feature_groups": ["query_context"],
        "root": {
            "if": {"op": "gte", "args": [{"feature": "query_predicate_threshold"}, {"int": 108}]},
            "then": "continue",
            "else": "stop",
        },
    }
    h = b.prepare_execution(raw, routing="static")
    calls = []
    original = dispatch.cannot_stop

    def counted(root, known):
        calls.append(dict(known))
        return original(root, known)

    monkeypatch.setattr(dispatch, "cannot_stop", counted)
    query = {**QUERY, "filter": {"field": "votes", "op": "gte", "value": 108}}
    for qid in ("q1", "q2", "unfiltered-name"):
        assert (
            b.execute_prepared({**query, "id": qid}, h).metadata["query_route"] == "native_bypass"
        )
    assert len(calls) == 1
    query["filter"]["value"] = 32
    assert b.execute_prepared(query, h).metadata["query_route"] == "policy"
    assert len(calls) == 2
    query["filter"]["value"] = True
    with pytest.raises(Exception):
        b.execute_prepared(query, h)
    assert c.closed and c.events.count("search") == 4 and not b._routes


def test_caches_are_bounded_and_released_with_handles():
    b, _ = backend()
    h = b.prepare_execution({"name": "c", "root": "continue"}, routing="static")
    for value in range(45):
        b.execute_prepared({**QUERY, "filter": {"field": "votes", "op": "gte", "value": value}}, h)
    assert len(b._routes[h]) == 32 and len(b._statements) == 1
    b.release_execution(h)
    assert not b._routes
    b.close()
    assert not b._statements


@pytest.mark.parametrize(
    "kind",
    [
        ValidatedPredicateContextBackend,
        RoutedPredicateContextBackend,
        DispatchPredicateContextBackend,
    ],
)
@pytest.mark.parametrize("mode", ["foreign", "forged", "released", "closed"])
def test_owned_handle_boundaries(kind, mode):
    b, _ = backend(kind)
    h = b.prepare_execution({"name": "c", "root": "continue"}, routing="static")
    if mode == "foreign":
        b, _ = backend(kind)
    elif mode == "forged":
        h = ExecutionHandle(h.policy_hash, h.routing)
    elif mode == "released":
        b.release_execution(h)
    else:
        b.close()
    with pytest.raises(AgentError):
        b.execute_prepared(QUERY, h)


@pytest.mark.parametrize("flag", ["trace", "audit"])
def test_trace_and_audit_use_original_policy_path(monkeypatch, flag):
    b, _ = backend()
    h = b.prepare_execution({"name": "c", "root": "continue"}, routing="static")
    seen = []

    def policy(q, **kwargs):
        seen.append(kwargs)
        return ProbeResult([], [], 1, {})

    monkeypatch.setattr(b, "_execute_probe", policy)
    result = b.execute_prepared(QUERY, h, **{flag: True})
    assert seen[0]["mode"] == "policy" and seen[0][flag]
    assert result.metadata["routing_suppressed_for_trace"]


def test_direct_sql_matches_original_statement_and_rebinds_current_values():
    from fannagent_pgvector.backend import NativeBackend

    b, _ = backend(DispatchNativeBackend)
    for value in (32, 108, 500):
        q = b.snapshot().query({**QUERY, "filter": {"field": "votes", "op": "gte", "value": value}})
        old, oldparams = NativeBackend._statement(b, q)
        new, newparams = b._statement(q)
        assert new.as_string() == old.as_string() and newparams == oldparams
    assert len(b._statements) == 1


def test_c_vector_format_matches_frozen_formatter_for_every_current_value():
    b, _ = backend(DispatchNativeBackend)
    rng = np.random.default_rng(301)
    samples = [[0.0, -0.0, 1e-8, 1e-5, 1e5, 1e8, 1e-300, 1e300]]
    samples += [rng.normal(size=768).tolist() for _ in range(100)]
    samples += [
        (rng.uniform(-1, 1, 768) * 10.0 ** rng.integers(-300, 300)).tolist() for _ in range(50)
    ]
    for vector in samples:
        _, params = b._statement({**QUERY, "vector": vector})
        assert params[0] == "[" + ",".join(format(float(v), ".9g") for v in vector) + "]"


@pytest.mark.parametrize(
    "failure",
    [
        "autocommit",
        "binding",
        "transaction",
        "pipeline",
        "search",
        "row_shape",
        "row_count",
        "duplicate",
        "nonfinite",
        "unknown_id",
    ],
)
def test_direct_native_errors_close_without_replaying(failure):
    b, c = backend()
    h = b.prepare_execution({"name": "c", "root": "continue"}, routing="static")
    if failure == "autocommit":
        c.autocommit = False
    elif failure == "binding":
        b._binding_conn = None
    elif failure == "transaction":
        c.pgconn.transaction_status = pq.TransactionStatus.INTRANS
    elif failure == "pipeline":
        c.pgconn.pipeline_status = pq.PipelineStatus.ON
    elif failure == "search":
        c.fail = "search"
    elif failure == "row_shape":
        c.rows = [(-5, 0.2, 3)]
    elif failure == "row_count":
        c.rows = c.rows * 6
    elif failure == "duplicate":
        c.rows = [(-5, 0.2), (-5, 0.3)]
    elif failure == "nonfinite":
        c.rows = [(-5, float("nan"))]
    elif failure == "unknown_id":
        c.rows = [(42, 0.2)]
    with pytest.raises((AgentError, RuntimeError, KeyError)):
        b.execute_prepared(QUERY, h)
    assert c.closed and c.events.count("search") <= 1 and not b._executions
