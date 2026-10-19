import os
from pathlib import Path

import pytest
from fannagent.controller import open_run
from fannagent.evaluation import score

from fannagent_pgvector.native.features import FEATURE_REGISTRY_HASH
from fannagent_pgvector.native.transport import feature_set_hash

pytestmark = pytest.mark.integration


@pytest.fixture
def backend():
    root = os.environ.get("FANNAGENT_TEST_RUN")
    if not root:
        pytest.skip("set FANNAGENT_TEST_RUN to a disposable prepared pgvector fixture")
    config, store, backend = open_run(Path(root))
    assert store.get("prepared")["qualified"]
    yield backend.native
    backend.close()


def query(backend):
    return backend.snapshot().query(
        {
            "id": "integration-probe",
            "vector": backend.snapshot().rows[10]["vector"],
            "k": 10,
            "filter": {"field": "Category Value", "op": "is_not_null"},
        }
    )


def test_restored_native_search_matches_stock_source(backend):
    import psycopg

    source = os.environ.get("FANNAGENT_TEST_SOURCE_URL")
    if not source:
        pytest.skip("set the disposable stock source DSN for stock/native conformance")
    with psycopg.connect(source, autocommit=True) as conn:
        assert (
            conn.execute(
                "SELECT to_regprocedure('fannagent.bind_target(regclass,text,text,regclass)')"
            ).fetchone()[0]
            is None
        )
        for row in backend.snapshot().rows[:5]:
            q = backend.snapshot().query(
                {"id": "stock-conformance", "vector": row["vector"], "k": 10}
            )
            statement, params = backend._statement(q)
            expected = conn.execute(statement, params).fetchall()
            actual = backend.execute_probe(q)
            assert [backend.snapshot().id_to_source[i] for i in actual.ids] == [
                str(r[0]) for r in expected
            ]
            assert actual.distances == [float(r[1]) for r in expected]


def test_real_stop_custom_fields_and_signed_ids(backend):
    q = query(backend)
    policy = backend.validate_policy({"name": "integration-stop", "root": "stop"})
    stopped = backend.execute_probe(q, mode="policy", policy=policy, trace=True, audit=True)
    assert stopped.metadata["policy_hash"] == policy.policy_hash
    assert stopped.metadata["policy_applied"]
    assert stopped.metadata["stop_reason"] == "policy_stop"
    assert stopped.metadata["stop_scope"] == "hnsw_scan"
    assert stopped.metadata["returned_count_source"] == "client_reported"
    assert score(backend.exact_reference(q), stopped)["valid"]
    assert backend.snapshot().source_ids[0] == -(2**63)
    assert backend.snapshot().source_ids[-1] == 2**63 - 1
    assert stopped.evidence["membership_provenance"] == "offline_identity_predicate_reconstruction"


def test_continue_abort_reuse_and_bounded_trace(backend):
    q = query(backend)
    policy = backend.validate_policy({"name": "integration-continue", "root": "continue"})
    native = backend.execute_probe(q)
    continuing = backend.execute_probe(q, mode="policy", policy=policy, trace=True)
    assert native.ids == continuing.ids
    assert native.distances == continuing.distances
    invalid = {**q, "vector": [1.0, 0.0]}
    with pytest.raises(Exception):
        backend.execute_probe(invalid, mode="observation")
    assert backend.execute_probe(q).ids == native.ids
    backend.config.copy.trace_max_bytes = 1024
    bounded = backend.execute_probe(q, mode="observation", trace=True)
    assert bounded.evidence["truncated"]
    assert bounded.metadata["trace_descriptor"]["bytes"] <= 1024


def test_interpreter_failure_continues_and_timeout_resets(backend):
    q = query(backend)
    policy = backend.validate_policy(
        {
            "name": "arithmetic-fallback",
            "root": {
                "if": {
                    "op": "eq",
                    "args": [{"op": "div", "args": [{"int": 1}, {"int": 0}]}, {"float": 0.0}],
                },
                "then": "stop",
                "else": "continue",
            },
        }
    )
    result = backend.execute_probe(q, mode="policy", policy=policy)
    assert result.metadata["policy_fallback"]
    assert result.ids == backend.execute_probe(q).ids
    conn = backend._connect()
    with pytest.raises(Exception):
        with conn.transaction():
            conn.execute(
                "SELECT fannagent.begin_execution(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                (
                    "policy_noop",
                    None,
                    None,
                    "timeout-probe",
                    10,
                    0,
                    "off",
                    1024,
                    FEATURE_REGISTRY_HASH,
                    feature_set_hash(["basic"]),
                    "basic",
                    False,
                ),
            )
            conn.execute("SET LOCAL statement_timeout='1ms'")
            conn.execute("SELECT pg_sleep(.1)")
    assert backend.execute_probe(q, mode="observation").ids == result.ids


def test_empty_non_hnsw_route_is_truthful(backend):
    q = query(backend)
    q["filter"] = {"field": "m_000001", "op": "lt", "value": -1000000}
    policy = backend.validate_policy({"name": "stop-without-opportunity", "root": "stop"})
    result = backend.execute_probe(q, mode="policy", policy=policy, trace=True)
    assert not result.ids
    assert score(backend.exact_reference(q), result)["valid"]
    if result.metadata["executed_path"] == "postgresql_non_hnsw":
        assert not result.metadata["policy_opportunity"]
        assert not result.metadata["policy_applied"]


def test_background_checkpoint_does_not_invalidate_snapshot(backend):
    import psycopg

    before = backend.compatibility()
    with psycopg.connect(backend._connection_dsn(admin=True), autocommit=True) as admin:
        admin.execute("CHECKPOINT")
    assert backend.compatibility() == before


def test_control_transport_timeout_and_connection_loss(backend):
    """Faults belong exclusively to an explicitly disposable prepared fixture."""
    import psycopg

    q = query(backend)
    policy = backend.validate_policy({"name": "fault-continue", "root": "continue"})
    expected = backend.execute_probe(q)
    old_statement = backend._statement
    conn = backend._connect()
    assert backend._batch_ready(conn)
    conn.execute("SET statement_timeout='10ms'")
    backend._statement = lambda q: ("SELECT 1, 0.0 FROM pg_sleep(.2)", [])
    try:
        with pytest.raises(psycopg.errors.QueryCanceled):
            backend.execute_probe(q, mode="policy", policy=policy)
        assert backend.conn is None and backend._binding is None and backend._installed is None
    finally:
        backend._statement = old_statement
    assert backend.execute_probe(q, mode="policy", policy=policy).ids == expected.ids
    victim = backend._connect()
    pid = victim.info.backend_pid
    with psycopg.connect(backend._connection_dsn(admin=True), autocommit=True) as admin:
        assert admin.execute("SELECT pg_terminate_backend(%s)", (pid,)).fetchone()[0]
    with pytest.raises(psycopg.Error):
        backend.execute_probe(q, mode="policy", policy=policy)
    assert backend.conn is None and backend._binding is None
    assert backend.execute_probe(q, mode="policy", policy=policy).ids == expected.ids


def test_sequential_control_batches_escape_and_late_commit_error(backend):
    """Driver adaptation and late errors on an explicitly disposable copy only."""
    import json

    import psycopg
    from psycopg import pq

    from fannagent_pgvector.native.sequential import (
        begin_execution_batch,
        complete_execution_batch,
    )

    conn = backend._connect()
    nonce = "abcdef0123456789abcdef0123456789"
    groups = ["basic"]
    params = (
        "policy_noop",
        None,
        None,
        nonce,
        10,
        0,
        "off",
        1024,
        FEATURE_REGISTRY_HASH,
        feature_set_hash(groups),
        "basic",
        False,
    )
    ack = begin_execution_batch(
        conn,
        "SELECT fannagent.begin_execution(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
        params,
    )
    assert ack == nonce
    q = query(backend)
    statement, values = backend._statement(q)
    rows = conn.execute(statement, values).fetchall()
    completion = json.loads(complete_execution_batch(conn, nonce, len(rows)))
    assert completion["request_nonce"] == nonce
    assert completion["returned_count"] == len(rows)
    assert conn.pgconn.transaction_status == pq.TransactionStatus.IDLE

    # TEMP relations are confined to this disposable admin session. The earlier
    # scalar succeeds but COMMIT fails; ClientCursor.execute must report failure.
    with psycopg.connect(backend._connection_dsn(admin=True), autocommit=True) as admin:
        escaped_value = "quoted '; SELECT 654321; -- \\ newline\nvalue"
        assert begin_execution_batch(admin, "SELECT %s", (escaped_value,)) == escaped_value
        admin.execute("ROLLBACK")
        assert admin.pgconn.transaction_status == pq.TransactionStatus.IDLE
        admin.execute("CREATE TEMP TABLE batch_parent(id int PRIMARY KEY)")
        admin.execute(
            "CREATE TEMP TABLE batch_child(id int REFERENCES batch_parent(id) "
            "DEFERRABLE INITIALLY DEFERRED)"
        )
        with psycopg.ClientCursor(admin) as cursor:
            cursor.execute("BEGIN; INSERT INTO batch_child VALUES (%s)", (123,))
            with pytest.raises(psycopg.errors.ForeignKeyViolation):
                cursor.execute("SELECT %s; COMMIT", ("successful scalar",))
        assert admin.pgconn.transaction_status == pq.TransactionStatus.IDLE


def test_mutated_copy_cannot_be_used_for_policy_selection(backend):
    # Write only this explicit disposable snapshot, then reject stale evidence.
    backend._connect().execute(
        'UPDATE "agent fixture"."Documents" SET rating=rating+1 WHERE "Document Key"=-2000'
    )
    from fannagent.errors import AgentError

    with pytest.raises(AgentError, match="(snapshot|physical index) changed"):
        backend.compatibility()


def test_hot_visibility_duplicate_vectors_and_snapshot(backend):
    # Mutate only the explicitly disposable restored copy, never the source connection.
    conn = backend._connect()
    row = backend.snapshot().rows[-1]
    with conn.transaction():
        conn.execute(
            'UPDATE "agent fixture"."Documents" SET rating=rating+1 WHERE "Document Key"=%s',
            (row["source_id"],),
        )
    backend._snapshot = None
    q = backend.snapshot().query({"id": "hot-query", "vector": row["vector"], "k": 10})
    evidence = backend.execute_probe(q, mode="observation", trace=True, audit=True).evidence
    assert evidence["membership"]["capture_complete"]
    assert all(
        not c["observed_predicate_mismatches"] for c in evidence["membership"]["checkpoints"]
    )
    conn.execute(
        'INSERT INTO "agent fixture"."Documents" SELECT 100000,"Embedding Vector",'
        '"Category Value",rating FROM "agent fixture"."Documents" WHERE "Document Key"=%s',
        (row["source_id"],),
    )
    backend._snapshot = None
    truth = backend.exact_reference(q)
    assert score(truth, backend.execute_probe(q, mode="observation", trace=True, audit=True))[
        "valid"
    ]
    conn.execute('DELETE FROM "agent fixture"."Documents" WHERE "Document Key"=100000')
    backend._snapshot = None
