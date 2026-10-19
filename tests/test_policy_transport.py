"""Client-only invariants: private preparation and acknowledged sequential batches."""

import json
from contextlib import contextmanager
from types import SimpleNamespace

import pytest
from fannagent.api import AgentError
from psycopg import pq

from fannagent_pgvector import backend as module
from fannagent_pgvector.backend import NativeBackend
from fannagent_pgvector.prepared import PreparedPolicyCache
from fannagent_pgvector.profiles import PROFILE


def policy(name="p"):
    return {"name": name, "root": "continue"}


def test_cache_hit_hash_bytecode_and_owned_nested_data():
    cache = PreparedPolicyCache(PROFILE)
    raw = {**policy(), "training_provenance": {"nested": [1]}, "feature_groups": []}
    first = cache.prepare(raw)
    assert cache.prepare(raw) is first
    assert first.policy_hash == module.validate_policy(raw, PROFILE).policy_hash
    assert first.bytecode == module.compile_policy(first.artifact)
    raw["training_provenance"]["nested"].append(2)
    changed = cache.prepare(raw)
    assert changed is not first
    assert first.artifact.training_provenance == {"nested": [1]}
    artifact = module.validate_policy(policy(), PROFILE)
    original = cache.prepare(artifact)
    artifact.feature_groups.append("invalid-group")
    with pytest.raises(AgentError):
        cache.prepare(artifact)
    assert original.groups == ()


def test_nested_tree_mutation_forces_full_validation():
    cache = PreparedPolicyCache(PROFILE)
    raw = {
        "name": "p",
        "root": {
            "if": {"op": "gte", "args": [{"feature": "checkpoint_index"}, {"int": 1}]},
            "then": "stop",
            "else": "continue",
        },
    }
    first = cache.prepare(raw)
    raw["root"]["if"]["args"][1]["int"] = 2
    assert cache.prepare(raw).policy_hash != first.policy_hash
    assert first.artifact.root["if"]["args"][1] == {"int": 1}
    raw["root"]["if"]["args"][1]["int"] = True
    with pytest.raises(AgentError):
        cache.prepare(raw)


def test_default_two_mib_budget_does_not_reject_large_valid_input():
    cache = PreparedPolicyCache(PROFILE)
    raw = {**policy(), "training_provenance": {"text": "x" * (2 * 1024 * 1024)}}
    prepared = cache.prepare(raw)
    assert prepared.policy_hash == module.validate_policy(raw, PROFILE).policy_hash
    assert not cache.entries and cache.bytes == 0


@pytest.mark.parametrize(
    "valid,invalid",
    [
        ({**policy(), "feature_groups": []}, {**policy(), "feature_groups": ()}),
        (
            {**policy(), "training_provenance": {"1": "value"}},
            {**policy(), "training_provenance": {1: "value"}},
        ),
        ({**policy(), "shape_model": {"1": "value"}}, {**policy(), "shape_model": {1: "value"}}),
    ],
)
def test_json_normalization_cannot_turn_invalid_input_into_cache_hit(valid, invalid):
    cache = PreparedPolicyCache(PROFILE)
    cached = cache.prepare(valid)
    with pytest.raises(AgentError):
        module.validate_policy(invalid, PROFILE)
    with pytest.raises(AgentError):
        cache.prepare(invalid)
    assert cache.prepare(valid) is cached


def test_valid_non_json_python_input_executes_uncached_and_is_owned():
    cache = PreparedPolicyCache(PROFILE)
    nested = [1]
    raw = {**policy(), "training_provenance": {"tuple": (nested,)}}
    first = cache.prepare(raw)
    assert first.policy_hash == module.validate_policy(raw, PROFILE).policy_hash
    assert cache.prepare(raw) is not first
    nested.append(2)
    assert first.artifact.training_provenance["tuple"] == ([1],)
    assert not cache.entries


def test_profile_identity_is_private_and_part_of_cache_key():
    profile = PROFILE.model_copy(deep=True)
    cache = PreparedPolicyCache(profile)
    profile.features.clear()
    first = cache.prepare(policy())
    assert first.artifact.runtime_profile_hash == cache.identity
    assert next(iter(cache.entries))[0] == cache.identity


def test_cache_miss_compiles_inside_installation_timer(monkeypatch):
    from fannagent_pgvector import prepared

    calls = []
    original = prepared.compile_tree
    monkeypatch.setattr(
        prepared, "compile_tree", lambda *a, **kw: (calls.append("compile"), original(*a, **kw))[1]
    )
    backend, _, _ = make_backend()
    value = backend._prepare_policy(policy())  # Adapter validation precedes backend timer.
    assert calls == []
    ticks = iter([0, 1000000])

    def clock():
        tick = next(ticks)
        assert calls == ([] if tick == 0 else ["compile"])
        return tick

    monkeypatch.setattr(module.time, "perf_counter_ns", clock)
    backend.execute_probe(QUERY, mode="policy", policy=value)
    assert value.bytecode and calls == ["compile"]


def test_lru_and_serialized_input_budget():
    cache = PreparedPolicyCache(PROFILE)
    entries = [cache.prepare(policy(str(n))) for n in range(16)]
    assert cache.prepare(policy("0")) is entries[0]
    cache.prepare(policy("16"))
    assert cache.prepare(policy("1")) is not entries[1]
    assert len(cache.entries) == 16
    small = PreparedPolicyCache(PROFILE, budget=100)
    oversized = {**policy(), "training_provenance": {"text": "a" * 200}}
    assert small.prepare(oversized).policy_hash == small.prepare(oversized).policy_hash
    assert not small.entries and small.bytes == 0
    for n in range(10):
        small.prepare(policy(str(n)))
        assert small.bytes <= 100


@pytest.mark.parametrize(
    "raw",
    [
        {"name": "p", "root": "bad"},
        {"name": "p", "root": "continue", "unexpected": 2},
        {"name": "p", "root": "continue", "runtime_profile_hash": "wrong"},
        {"name": "p", "root": "continue", "feature_groups": ["basic", "basic"]},
        {"name": "p", "root": "continue", "training_provenance": {"n": float("nan")}},
    ],
)
def test_invalid_input_never_cached(raw):
    cache = PreparedPolicyCache(PROFILE)
    with pytest.raises(AgentError):
        cache.prepare(raw)
    assert not cache.entries


def test_tree_bounds_precede_serialization(monkeypatch):
    from fannagent_pgvector import prepared

    cache = PreparedPolicyCache(PROFILE)
    root = "continue"
    for _ in range(20):
        root = {"if": {"bool": True}, "then": root, "else": "continue"}
    monkeypatch.setattr(prepared.json, "dumps", lambda *a, **k: pytest.fail("unbounded hashing"))
    with pytest.raises(AgentError, match="depth"):
        cache.prepare({"name": "p", "root": root})


class Cursor:
    def __init__(self, conn, kind, value):
        self.conn, self.kind, self.value = conn, kind, value

    def fetchone(self):
        self.conn.events.append("fetch:" + self.kind)
        return (self.value,)

    def fetchall(self):
        self.conn.events.append("fetch:" + self.kind)
        return self.value


class Connection:
    def __init__(self, fail=None, wrong=None):
        self.events, self.fail, self.wrong = [], fail, wrong
        self.closed, self.autocommit = False, True
        self.pgconn = SimpleNamespace(
            transaction_status=pq.TransactionStatus.IDLE, pipeline_status=pq.PipelineStatus.OFF
        )
        self.hash = None
        self.nonce = None
        self.rows = [(-5, 0.2), (2**63 - 1, 0.7)]

    def pipeline(self):
        pytest.fail("sequential candidate must not enter pipeline mode")

    @contextmanager
    def transaction(self):
        self.events.append("transaction:enter")
        yield
        self.events.append("transaction:exit")

    def execute(self, statement, params=None, **kwargs):
        text = str(statement)
        kind = next(
            (
                k
                for k in ("install_policy", "begin_execution", "complete", "COMMIT", "BEGIN")
                if k in text
            ),
            "search",
        )
        self.events.append(kind)
        if self.fail == kind:
            raise RuntimeError(kind)
        if kind == "install_policy":
            self.hash = params[0]
            value = "wrong" if self.wrong == "install" else self.hash
        elif kind == "begin_execution":
            self.nonce, self.mode = params[3], params[0]
            value = "wrong" if self.wrong == "nonce" else self.nonce
        elif kind == "complete":
            assert params == (self.nonce, len(self.rows))
            value = json.dumps(
                {
                    "request_nonce": "wrong" if self.wrong == "telemetry" else self.nonce,
                    "protocol": "same_execution_v4",
                    "policy_hash": self.hash,
                    "effective_mode": self.mode,
                    "policy_opportunity": True,
                    "policy_applied": True,
                    "target_index_oid": 9 if self.wrong == "binding" else 8,
                }
            )
        elif kind == "BEGIN":
            self.pgconn.transaction_status = (
                pq.TransactionStatus.IDLE
                if self.wrong == "begin_idle"
                else pq.TransactionStatus.INTRANS
            )
            value = None
        elif kind == "COMMIT":
            self.pgconn.transaction_status = (
                pq.TransactionStatus.INTRANS
                if self.wrong == "commit_intrans"
                else pq.TransactionStatus.IDLE
            )
            value = None
        else:
            value = self.rows
        return Cursor(self, kind, value)

    def close(self):
        self.closed = True
        self.events.append("close")


class ClientCursor:
    """Model the driver's fully collected result sets, including late errors."""

    def __init__(self, conn):
        self.conn = conn
        self.results = []
        self.position = 0
        self.fetched = False

    def __enter__(self):
        return self

    def __exit__(self, *args):
        if self.conn.fail == "batch_close":
            raise RuntimeError("batch_close")

    def execute(self, statement, params):
        self.kind = "begin" if statement.startswith("BEGIN;") else "complete"
        tag = "batch_" + self.kind + "_execute"
        self.conn.events.append(tag)
        if self.conn.fail == tag:
            raise RuntimeError(tag)
        if self.kind == "begin":
            self.results = [
                self.conn.execute("BEGIN"),
                self.conn.execute("begin_execution", params),
            ]
        else:
            self.results = [self.conn.execute("complete", params), self.conn.execute("COMMIT")]
        if self.conn.wrong == "missing_" + self.kind:
            self.results.pop()
        if self.conn.wrong == "extra_" + self.kind:
            self.results.append(Cursor(self.conn, "extra", None))

    @property
    def statusmessage(self):
        kind = self.results[self.position].kind
        if kind in ("begin_execution", "complete"):
            return "SELECT 1"
        if kind == "COMMIT" and self.conn.wrong == "rollback":
            return "ROLLBACK"
        return kind

    @property
    def description(self):
        kind = self.results[self.position].kind
        return [object()] if kind in ("begin_execution", "complete") else None

    def fetchone(self):
        if self.conn.wrong == "empty_" + self.kind:
            return None
        if self.conn.wrong == "wide_" + self.kind:
            return ("unexpected", "columns")
        if self.conn.wrong == "many_" + self.kind:
            return self.results[self.position].fetchone()
        if self.fetched:
            return None
        self.fetched = True
        return self.results[self.position].fetchone()

    def nextset(self):
        tag = "batch_" + self.kind + "_nextset"
        if self.conn.fail == tag:
            raise RuntimeError(tag)
        self.position += 1
        self.fetched = False
        if self.position >= len(self.results):
            self.conn.events.append("drained:" + self.kind)
            return None
        return True


@pytest.fixture(autouse=True)
def client_cursor(monkeypatch):
    monkeypatch.setattr(module.psycopg, "ClientCursor", ClientCursor)


def make_backend(conn=None):
    conn = conn or Connection()
    backend = NativeBackend(SimpleNamespace(copy=SimpleNamespace(trace_max_bytes=1024)), None)
    backend.conn = backend._binding_conn = conn
    backend._binding = {"index": {"oid": 8}}
    validations = []

    def query(raw):
        validations.append(raw)
        if len(raw["vector"]) != 2:
            raise AgentError("query dimensions invalid")
        return raw

    backend._snapshot = SimpleNamespace(query=query, source_to_id={"-5": 0, str(2**63 - 1): 1})
    backend._statement = lambda q: ("search", [])
    return backend, conn, validations


QUERY = {"id": "q", "k": 10, "vector": [1.0, 0.0]}


def test_batch_order_and_actual_count_every_query_validated():
    backend, conn, validations = make_backend()
    for _ in range(2):
        result = backend.execute_probe(QUERY, mode="policy", policy=policy())
        assert result.ids == [0, 1]
        assert result.metadata["application_source_ids"] == [-5, 2**63 - 1]
    assert validations == [QUERY, QUERY]
    assert conn.events[:13] == [
        "install_policy",
        "fetch:install_policy",
        "batch_begin_execute",
        "BEGIN",
        "begin_execution",
        "fetch:begin_execution",
        "drained:begin",
        "search",
        "fetch:search",
        "batch_complete_execute",
        "complete",
        "COMMIT",
        "fetch:complete",
    ]
    assert conn.events[13] == "drained:complete"
    assert conn.events.count("install_policy") == 1
    assert "transaction:enter" not in conn.events


@pytest.mark.parametrize("wrong", ["install", "nonce"])
def test_bad_ack_prevents_search(wrong):
    backend, conn, _ = make_backend(Connection(wrong=wrong))
    with pytest.raises(AgentError):
        backend.execute_probe(QUERY, mode="policy", policy=policy())
    assert "search" not in conn.events
    assert conn.closed and backend.conn is None and backend._binding is None
    assert not backend._policies.entries


@pytest.mark.parametrize(
    "fail",
    [
        "install_policy",
        "BEGIN",
        "begin_execution",
        "batch_begin_execute",
        "batch_begin_nextset",
        "search",
        "complete",
        "COMMIT",
        "batch_complete_execute",
        "batch_complete_nextset",
        "batch_close",
    ],
)
def test_failure_closes_clears_and_does_not_replay(fail):
    backend, conn, _ = make_backend(Connection(fail=fail))
    with pytest.raises(RuntimeError, match=fail):
        backend.execute_probe(QUERY, mode="policy", policy=policy())
    assert conn.closed and backend.conn is None and backend._binding is None
    assert backend._installed is None and not backend._policies.entries
    assert conn.events.count("search") <= 1


@pytest.mark.parametrize("wrong", ["telemetry", "binding"])
def test_post_commit_identity_failure_invalidates(wrong):
    backend, conn, _ = make_backend(Connection(wrong=wrong))
    with pytest.raises(AgentError):
        backend.execute_probe(QUERY, mode="policy", policy=policy())
    assert conn.closed and backend._binding is None


@pytest.mark.parametrize(
    "wrong",
    ["missing_begin", "extra_begin", "empty_begin", "wide_begin", "many_begin", "begin_idle"],
)
def test_malformed_initialization_batch_prevents_search(wrong):
    backend, conn, _ = make_backend(Connection(wrong=wrong))
    with pytest.raises(AgentError):
        backend.execute_probe(QUERY, mode="policy", policy=policy())
    assert "search" not in conn.events and conn.closed
    assert backend._binding is None and not backend._policies.entries


@pytest.mark.parametrize(
    "wrong",
    [
        "missing_complete",
        "extra_complete",
        "empty_complete",
        "wide_complete",
        "many_complete",
        "rollback",
        "commit_intrans",
    ],
)
def test_malformed_completion_batch_never_accepts_results(wrong):
    backend, conn, _ = make_backend(Connection(wrong=wrong))
    with pytest.raises(AgentError):
        backend.execute_probe(QUERY, mode="policy", policy=policy())
    assert conn.events.count("search") == 1 and conn.closed
    assert backend._binding is None and backend._installed is None


@pytest.mark.parametrize("rows", [[], [(-5, 0.2)]])
def test_completion_uses_zero_and_partial_row_counts(rows):
    conn = Connection()
    conn.rows = rows
    backend, _, _ = make_backend(conn)
    result = backend.execute_probe(QUERY, mode="policy", policy=policy())
    assert len(result.ids) == len(rows)
    assert "drained:complete" in conn.events


@pytest.mark.parametrize("fallback", [False, True])
def test_serving_native_fallback_remains_caller_controlled(monkeypatch, fallback):
    backend, conn, _ = make_backend(Connection(fail="search"))
    backend._snapshot.id_to_source = {0: "-5", 1: str(2**63 - 1)}
    monkeypatch.setattr(backend, "_check_security", lambda: None)
    session = backend.open_policy_session(policy())
    execute = backend.execute_probe
    calls = []

    def probe(query, *, mode="native", **kwargs):
        calls.append(mode)
        if mode == "native":
            new = Connection()
            backend.conn = backend._binding_conn = new
            backend._binding = {"index": {"oid": 8}}
        return execute(query, mode=mode, **kwargs)

    monkeypatch.setattr(backend, "execute_probe", probe)
    if fallback:
        result = session.query(QUERY, fallback=True)
        assert result.ids == [-5, 2**63 - 1]
        assert result.metadata["fallback"] == "ordinary_default"
        assert calls == ["policy", "native"]
    else:
        with pytest.raises(RuntimeError, match="search"):
            session.query(QUERY, fallback=False)
        assert calls == ["policy"]
    assert conn.closed and conn.events.count("search") == 1


@pytest.mark.parametrize(
    "condition", ["unsupported", "external", "transaction", "autocommit", "pipeline"]
)
def test_preconditions_choose_sequential_transport(monkeypatch, condition):
    backend, conn, _ = make_backend()
    if condition == "unsupported":
        monkeypatch.setattr(module.psycopg, "ClientCursor", None)
    elif condition == "external":
        backend._binding_conn = None
    elif condition == "transaction":
        conn.pgconn.transaction_status = pq.TransactionStatus.INTRANS
    elif condition == "autocommit":
        conn.autocommit = False
    else:
        conn.pgconn.pipeline_status = pq.PipelineStatus.ON
    backend.execute_probe(QUERY, mode="policy", policy=policy())
    assert "transaction:enter" in conn.events and "batch_begin_execute" not in conn.events


def test_unsupported_libpq_does_not_access_pipeline_status(monkeypatch):
    backend, conn, _ = make_backend()

    class OldLibpq:
        transaction_status = pq.TransactionStatus.IDLE

        @property
        def pipeline_status(self):
            pytest.fail("pipeline status is unavailable in old libpq")

    conn.pgconn = OldLibpq()
    monkeypatch.setattr(module.psycopg.capabilities, "has_pipeline", lambda: False)
    backend.execute_probe(QUERY, mode="policy", policy=policy())
    assert "batch_begin_execute" in conn.events and "transaction:enter" not in conn.events


def test_query_mutation_revalidated_on_policy_cache_hit():
    backend, conn, _ = make_backend()
    backend.execute_probe(QUERY, mode="policy", policy=policy())
    with pytest.raises(AgentError, match="dimensions"):
        backend.execute_probe({**QUERY, "vector": [1.0]}, mode="policy", policy=policy())
    assert conn.events.count("search") == 1 and conn.closed


def test_compatibility_failure_drops_facts(monkeypatch):
    backend, conn, _ = make_backend()
    monkeypatch.setattr(
        backend, "_compatibility", lambda: (_ for _ in ()).throw(AgentError("changed"))
    )
    with pytest.raises(AgentError):
        backend.compatibility()
    assert backend._binding is None and backend._binding_conn is None and conn.closed
    with pytest.raises(AgentError, match="failed compatibility"):
        backend.execute_probe(QUERY, mode="policy", policy=policy())
    monkeypatch.setattr(backend, "_compatibility", lambda: {"identity": "fresh"})
    assert backend.compatibility() == {"identity": "fresh"}
    assert not backend._compatibility_error


def test_installation_and_commit_inside_policy_timer(monkeypatch):
    backend, conn, _ = make_backend()
    ticks = iter([1000000, 12000000])

    def clock():
        tick = next(ticks)
        if tick == 1000000:
            assert not conn.events
        else:
            assert "COMMIT" in conn.events and "drained:complete" in conn.events
            assert "fetch:complete" in conn.events
        return tick

    monkeypatch.setattr(module.time, "perf_counter_ns", clock)
    assert backend.execute_probe(QUERY, mode="policy", policy=policy()).latency_ms == 11


def test_native_clock_still_starts_at_search(monkeypatch):
    backend, conn, _ = make_backend()
    ticks = iter([0, 1000000, 4000000])
    monkeypatch.setattr(module.time, "perf_counter_ns", lambda: next(ticks))
    assert backend.execute_probe(QUERY).latency_ms == 3
    assert conn.events == ["search", "fetch:search"]


def test_reconnect_refreshes_facts_and_installation(monkeypatch):
    backend, old, _ = make_backend()
    backend._policies.prepare(policy())
    backend._installed = "old"
    old.close()
    new = Connection()
    source = {"index": {"oid": 99}, "settings": {}}
    backend.store = SimpleNamespace(get=lambda key: source if key == "source_manifest" else {})
    monkeypatch.setattr(backend, "_check_security", lambda *a: None)
    monkeypatch.setattr(backend, "_connection_dsn", lambda: "disposable-fake")
    monkeypatch.setattr(module.psycopg, "connect", lambda *a, **kw: new)

    def bind(conn, saved):
        backend._binding = dict(saved)
        backend._binding_conn = conn

    monkeypatch.setattr(backend, "_bind", bind)
    assert backend._connect() is new
    assert backend._binding["index"]["oid"] == 99
    assert backend._installed is None and not backend._policies.entries
    backend.close()
    assert new.closed and backend._binding_conn is None


def test_bind_acknowledgement_required_before_caching(monkeypatch):
    backend, conn, _ = make_backend()
    backend.config.target = SimpleNamespace(
        schema_name="s", resource="t", id_column="id", vector_column="vector"
    )
    source = {"index": {"oid": 8, "relname": "hnsw"}, "settings": {}}
    monkeypatch.setattr(module.sql.Identifier, "as_string", lambda *a: "identifier")
    monkeypatch.setattr(backend, "_settings", lambda *a, **k: pytest.fail("settings after bad ack"))
    conn.execute = lambda *a, **k: Cursor(conn, "bind", 9)
    with pytest.raises(AgentError, match="binding acknowledgement"):
        backend._bind(conn, source)
    assert backend._binding is None and backend._binding_conn is None


def test_trace_retrieval_still_after_backend_timer(monkeypatch):
    backend, conn, _ = make_backend()
    original = conn.execute

    def execute(statement, *a, **kw):
        if "take_trace" in str(statement):
            conn.events.append("trace")
            return Cursor(conn, "trace", None)
        return original(statement, *a, **kw)

    conn.execute = execute
    ticks = iter([0, 1000000])

    def clock():
        assert "trace" not in conn.events
        return next(ticks)

    monkeypatch.setattr(module.time, "perf_counter_ns", clock)
    result = backend.execute_probe(QUERY, mode="policy", policy=policy(), trace=True)
    assert result.latency_ms == 1 and "trace" in conn.events
