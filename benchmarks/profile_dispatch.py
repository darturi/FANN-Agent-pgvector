"""Synthetic 768-D CPU profile; the stub database performs no search or I/O."""

from __future__ import annotations

import argparse
import cProfile
import io
import json
import pstats
import time
from types import SimpleNamespace

import numpy as np
from fannagent.snapshot import Snapshot
from psycopg import pq

from fannagent_pgvector.optimized import OptimizedPredicateContextBackend
from fannagent_pgvector.profiles import DATA_PROFILE


class Connection:
    autocommit = True
    closed = False
    pgconn = SimpleNamespace(transaction_status=pq.TransactionStatus.IDLE)

    def execute(self, statement, params):
        assert "begin_execution" not in str(statement)
        return self

    def fetchall(self):
        return [(i, i / 10) for i in range(10)]

    def close(self):
        self.closed = True


def fixture(kind):
    vector = np.random.default_rng(72).normal(size=768).astype(np.float32)
    vector /= np.linalg.norm(vector)
    snapshot = Snapshot(
        [{"source_id": i, "vector": vector.tolist(), "metadata": {"votes": i}} for i in range(10)],
        [{"name": "votes", "type": "integer", "allowed_ops": ["gte"]}],
        DATA_PROFILE,
    )
    b = kind(
        SimpleNamespace(
            copy=SimpleNamespace(trace_max_bytes=4096),
            target=SimpleNamespace(
                schema_name="public", resource="reviews", id_column="id", vector_column="embedding"
            ),
        ),
        None,
    )
    b.conn = b._binding_conn = Connection()
    b._binding = {"index": {"oid": 8}}
    b._snapshot = snapshot
    policy = {
        "name": "synthetic-context",
        "feature_groups": ["basic", "work", "query_context"],
        "root": {
            "if": {"op": "is_available", "args": [{"feature": "completed_expansions"}]},
            "then": {
                "if": {
                    "op": "lt",
                    "args": [{"feature": "query_predicate_threshold"}, {"int": 108}],
                },
                "then": "stop",
                "else": "continue",
            },
            "else": "continue",
        },
    }
    handle = b.prepare_execution(policy, routing="static")
    query = {
        "id": "synthetic",
        "vector": vector.tolist(),
        "k": 10,
        "filter": {"field": "m_000000", "op": "gte", "value": 108},
    }
    return b, handle, query


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    parser.add_argument("--previous-only", action="store_true")
    parser.add_argument("--calls", type=int, default=1500)
    args = parser.parse_args()
    kinds = {"previous": OptimizedPredicateContextBackend}
    if not args.previous_only:
        from fannagent_pgvector.dispatch import (
            DispatchPredicateContextBackend,
            RoutedPredicateContextBackend,
            ValidatedPredicateContextBackend,
        )

        kinds.update(
            validation=ValidatedPredicateContextBackend,
            routing=RoutedPredicateContextBackend,
            dispatch=DispatchPredicateContextBackend,
        )
    results = {}
    for name, kind in kinds.items():
        backend, handle, query = fixture(kind)
        for _ in range(50):
            backend.execute_prepared(query, handle)
        samples = []
        for _ in range(7):
            start = time.perf_counter_ns()
            for _ in range(args.calls):
                backend.execute_prepared(query, handle)
            samples.append((time.perf_counter_ns() - start) / args.calls / 1000)
        profiler = cProfile.Profile()
        profiler.enable()
        for _ in range(args.calls):
            backend.execute_prepared(query, handle)
        profiler.disable()
        stream = io.StringIO()
        pstats.Stats(profiler, stream=stream).sort_stats("cumulative").print_stats(25)
        results[name] = {
            "median_cpu_us": float(np.median(samples)),
            "round_cpu_us": samples,
            "profile": stream.getvalue(),
        }
        backend.close()
    from pathlib import Path

    Path(args.output).write_text(
        json.dumps(
            {
                "scope": "synthetic 768-D CPU only; no database I/O or Reviews queries",
                "calls_per_round": args.calls,
                "rounds": 7,
                "results": results,
            },
            indent=2,
        )
        + "\n"
    )
    print(json.dumps({k: v["median_cpu_us"] for k, v in results.items()}))


if __name__ == "__main__":
    main()
