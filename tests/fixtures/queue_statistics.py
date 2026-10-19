"""Disposable native A/B qualification; synthetic vectors only, no external services.

Run inside the explicit fixture image with a read-only root, no network, and
writable tmpfs at /tmp and /usr/lib/postgresql/17/lib. Mount the sealed runner at
/opt/torch-reviews and this script at /checks. Both libraries run against the same
physical HNSW index, restarting PostgreSQL between versions.
"""

import hashlib
import importlib.util
import json
import math
import os
import shutil
import subprocess
from pathlib import Path
from statistics import mean

import numpy as np
import psycopg
from psycopg import sql
from psycopg.conninfo import make_conninfo


def run(*args):
    subprocess.run([str(x) for x in args], check=True)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    os.umask(0o077)
    spec = importlib.util.spec_from_file_location("frozen_reviews", "/opt/torch-reviews/runner.py")
    frozen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(frozen)
    libdir = Path("/usr/lib/postgresql/17/lib")
    # The tmpfs root belongs to root; copy its children without changing its mode.
    for source in Path("/opt/queue-fixture/baseline-lib").iterdir():
        target = libdir / source.name
        if source.is_dir():
            shutil.copytree(source, target)
        else:
            shutil.copy2(source, target)
    lib = libdir / "vector.so"
    original_lib = Path("/opt/queue-fixture/baseline-lib/vector.so")
    candidate_lib = Path("/opt/queue-fixture/candidate-vector.so")
    assert digest(original_lib) != digest(candidate_lib)
    work = Path("/tmp/queue-statistics-fixture")
    work.mkdir(mode=0o700)
    (work / "socket").mkdir(mode=0o700)
    (work / ".torch-owned").write_text("synthetic-only\n")
    frozen.initialize_auth(work)
    run(
        "initdb",
        "-D",
        work / "pgdata",
        "--username=torch_owner",
        "--pwfile=" + str(work / "admin.pw"),
        "--auth-local=scram-sha-256",
        "--auth-host=reject",
        "--encoding=UTF8",
        "--locale=C",
    )
    calls = 0
    running = False

    def start():
        nonlocal running
        run(
            "pg_ctl",
            "-D",
            work / "pgdata",
            "-l",
            work / "server.log",
            "-w",
            "-t",
            "60",
            "-o",
            "-c listen_addresses='' -c unix_socket_directories="
            + str(work / "socket")
            + " -c unix_socket_permissions=0700 -c hba_file="
            + str(work / "pg_hba.conf")
            + " -c shared_buffers=128MB -c max_connections=8 -c log_statement=none",
            "start",
        )
        running = True

    def stop():
        nonlocal running
        if running:
            run("pg_ctl", "-D", work / "pgdata", "-m", "fast", "-w", "stop")
            running = False

    rng = np.random.default_rng(20261019)
    vectors = rng.normal(size=(4004, 16)).astype(np.float32)
    vectors /= np.linalg.norm(vectors, axis=1, keepdims=True)
    queries = [
        {
            "id": "synthetic-" + str(i),
            "k": 10,
            "vector": v.tolist(),
            "filter": {"field": "m_000000", "op": "gte", "value": 32},
        }
        for i, v in enumerate(vectors[4000:])
    ]
    fingerprints, references, benchmark = {}, {}, []
    backend = None
    try:
        start()
        with psycopg.connect(frozen.job_connection(work, admin=True), autocommit=True) as conn:
            conn.execute("CREATE DATABASE torch_reviews")
        admin_dsn = make_conninfo(frozen.job_connection(work, admin=True), dbname="torch_reviews")
        with psycopg.connect(admin_dsn, autocommit=True) as conn:
            password = (work / "reader.pgpass").read_text().strip().rsplit(":", 1)[1]
            conn.execute(
                sql.SQL("CREATE ROLE torch_reader LOGIN PASSWORD {}").format(sql.Literal(password))
            )
            conn.execute("CREATE EXTENSION vector")
            conn.execute(
                "CREATE TABLE reviews(id bigint PRIMARY KEY,"
                "embedding vector(16),total_votes bigint)"
            )
            with conn.cursor().copy("COPY reviews FROM STDIN") as copy:
                for i, vector in enumerate(vectors[:4000]):
                    text = "[" + ",".join(format(float(v), ".9g") for v in vector) + "]"
                    copy.write_row((i, text, i % 100))
            conn.execute("SET max_parallel_maintenance_workers=0")
            conn.execute(
                "CREATE INDEX reviews_hnsw ON reviews USING hnsw(embedding vector_cosine_ops) "
                "WITH(m=16,ef_construction=64)"
            )
            conn.execute("ANALYZE reviews")
            conn.execute(frozen.FUNCTIONS)
            conn.execute("REVOKE ALL ON SCHEMA public FROM PUBLIC")
            conn.execute("REVOKE ALL ON ALL FUNCTIONS IN SCHEMA fannagent FROM PUBLIC")
            conn.execute("GRANT CONNECT ON DATABASE torch_reviews TO torch_reader")
            conn.execute("GRANT USAGE ON SCHEMA public,fannagent TO torch_reader")
            conn.execute("GRANT SELECT ON reviews TO torch_reader")
            conn.execute("GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA fannagent TO torch_reader")
            conn.execute("ALTER ROLE torch_reader SET default_transaction_read_only=on")
            conn.execute("CHECKPOINT")
            location, oid = conn.execute(
                "SELECT pg_relation_filepath('reviews_hnsw'),'reviews_hnsw'::regclass::oid"
            ).fetchone()
        index_path = work / "pgdata" / location
        index_hash = digest(index_path)
        (work / "database-identity.json").write_text(
            json.dumps(
                {
                    "index_oid": oid,
                    "index_identity": index_hash,
                }
            )
        )
        stop()

        def probe(query, **kwargs):
            nonlocal calls
            calls += 1
            if calls > 1500:
                raise RuntimeError("Synthetic qualification query allowance exceeded")
            result = backend.execute_probe(query, **kwargs)
            meta = result.metadata
            if kwargs.get("mode") == "policy":
                assert (
                    meta["policy_applied"]
                    and not meta.get("policy_runtime_error")
                    and not meta.get("policy_fallback")
                )
            return result

        def policy(name, feature, threshold=-1.0, quantiles=False, stop=False):
            return backend.validate_policy(
                {
                    "name": name,
                    "feature_groups": ["basic", "work", "queue"]
                    + (["queue_quantiles"] if quantiles else []),
                    "root": {
                        "if": {"op": "gte", "args": [{"feature": feature}, {"float": threshold}]},
                        "then": "stop" if stop else "continue",
                        "else": "continue",
                    },
                }
            )

        def fingerprint(result):
            work_counters = result.metadata.get("work_counters", {})
            physical = {
                k: v
                for k, v in work_counters.items()
                if not k.endswith("_ns") and not k.startswith("frontier_")
            }
            trace = result.evidence
            checkpoints = (
                [
                    (c["index"], c["actual_layer0_distances"], c["features"])
                    for c in trace["checkpoints"]
                ]
                if trace
                else None
            )
            return {
                "ids": result.ids,
                "distances": result.distances,
                "stop_reason": result.metadata.get("stop_reason"),
                "checkpoints": checkpoints,
                "work": physical,
            }

        for version, source in (("baseline", original_lib), ("optimized", candidate_lib)):
            shutil.copyfile(source, lib)
            assert digest(lib) == digest(source)
            start()
            for ef in (80, 320, 640):
                backend = frozen.TorchBackend(Path("/opt/torch-reviews"), work)
                backend.state["source_manifest"]["settings"]["hnsw.ef_search"] = str(ef)
                getter = backend.validate_policy(
                    {
                        "name": "all-getters",
                        "root": "continue",
                        "feature_groups": [
                            "basic",
                            "work",
                            "queue",
                            "queue_quantiles",
                            "distances",
                        ],
                    }
                )
                light = backend.validate_policy(
                    {
                        "name": "light-frontier",
                        "root": "continue",
                        "feature_groups": ["basic", "work", "queue"],
                    }
                )
                numeric = {
                    "mean": policy("numeric-mean", "frontier_distance_mean"),
                    "variance": policy("numeric-variance", "frontier_distance_variance"),
                    "percentile": policy(
                        "numeric-percentile", "frontier_distance_p75", quantiles=True
                    ),
                    "light": light,
                }
                for query in queries:
                    native = probe(query)
                    traced = probe(query, mode="policy", policy=getter, trace=True)
                    assert native.ids == traced.ids and native.distances == traced.distances
                    assert traced.evidence and not traced.evidence["truncated"]
                    key = (ef, query["id"], "trace")
                    current = fingerprint(traced)
                    if version == "baseline":
                        fingerprints[key] = current
                        references[(ef, query["id"])] = traced.evidence["checkpoints"][0][
                            "features"
                        ]
                    else:
                        assert current == fingerprints[key], (key, "trace differs")
                    for name, artifact in numeric.items():
                        result = probe(query, mode="policy", policy=artifact)
                        assert result.ids == native.ids and result.distances == native.distances
                        key = (ef, query["id"], name)
                        current = fingerprint(result)
                        if version == "baseline":
                            fingerprints[key] = current
                        else:
                            assert current == fingerprints[key], (
                                key,
                                "numeric result/work differs",
                            )
                            counters = result.metadata["work_counters"]
                            assert counters["frontier_sort_count"] == (
                                counters["frontier_snapshot_count"] if name == "percentile" else 0
                            )
                            if name == "light":
                                assert counters["frontier_snapshot_count"] == 0
                            else:
                                assert counters["frontier_snapshot_count"] > 0
                            if name != "percentile":
                                assert (
                                    counters["frontier_sort_ns"]
                                    == counters["frontier_quantile_ns"]
                                    == 0
                                )
                            assert (
                                sum(
                                    counters[k]
                                    for k in (
                                        "frontier_traversal_ns",
                                        "frontier_statistics_ns",
                                        "frontier_sort_ns",
                                        "frontier_quantile_ns",
                                    )
                                )
                                <= counters["feature_collection_ns"]
                            )
                    for feature in (
                        "frontier_distance_min",
                        "frontier_distance_max",
                        "frontier_distance_mean",
                        "frontier_distance_variance",
                        "frontier_distance_p75",
                    ):
                        value = references[(ef, query["id"])][feature]
                        for low in (True, False):
                            threshold = math.nextafter(value, -math.inf if low else math.inf)
                            artifact = policy(
                                "threshold",
                                feature,
                                threshold,
                                quantiles=feature.endswith("p75"),
                                stop=True,
                            )
                            result = probe(query, mode="policy", policy=artifact)
                            stopped_first = (
                                result.metadata["stop_reason"] == "policy_stop"
                                and result.metadata["checkpoint_count"] == 1
                            )
                            assert stopped_first == low, (feature, value, threshold)
                            key = (ef, query["id"], feature, low)
                            current = fingerprint(result)
                            if version == "baseline":
                                fingerprints[key] = current
                            else:
                                assert current == fingerprints[key], (
                                    key,
                                    "threshold decision differs",
                                )
                    for repetition in range(4):
                        for name in ("light", "variance", "percentile"):
                            ordinary = probe(query)
                            result = probe(query, mode="policy", policy=numeric[name])
                            assert (
                                ordinary.ids == result.ids
                                and ordinary.distances == result.distances
                            )
                            benchmark.append(
                                {
                                    "version": version,
                                    "ef_search": ef,
                                    "query": query["id"],
                                    "repetition": repetition,
                                    "candidate": name,
                                    "native_ms": ordinary.latency_ms,
                                    "policy_ms": result.latency_ms,
                                    "counters": result.metadata["work_counters"],
                                }
                            )
                backend.close()
                backend = None
            with psycopg.connect(admin_dsn, autocommit=True) as conn:
                conn.execute("CHECKPOINT")
            assert digest(index_path) == index_hash
            stop()
        summaries = []
        for ef in (80, 320, 640):
            for name in ("light", "variance", "percentile"):
                for version in ("baseline", "optimized"):
                    rows = [
                        r
                        for r in benchmark
                        if r["ef_search"] == ef
                        and r["candidate"] == name
                        and r["version"] == version
                    ]
                    summaries.append(
                        {
                            "ef_search": ef,
                            "candidate": name,
                            "version": version,
                            "collection_ms": mean(
                                r["counters"]["feature_collection_ns"] for r in rows
                            )
                            / 1e6,
                            "reported_gap_ms": mean(r["policy_ms"] - r["native_ms"] for r in rows),
                            "sorts_per_query": mean(
                                r["counters"].get("frontier_sort_count", 0) for r in rows
                            )
                            if version == "optimized"
                            else None,
                            "maximum_frontier": max(
                                r["counters"].get("frontier_maximum_count", 0) for r in rows
                            )
                            if version == "optimized"
                            else None,
                            "phase_ms": {
                                phase: mean(r["counters"][phase] for r in rows) / 1e6
                                for phase in (
                                    "frontier_traversal_ns",
                                    "frontier_statistics_ns",
                                    "frontier_sort_ns",
                                    "frontier_quantile_ns",
                                )
                            }
                            if version == "optimized"
                            else None,
                        }
                    )
        print(
            json.dumps(
                {
                    "status": "passed",
                    "synthetic_rows": 4000,
                    "dimension": 16,
                    "backend_queries": calls,
                    "maximum_backend_queries": 1500,
                    "Reviews_queries": 0,
                    "provider_calls": 0,
                    "baseline_library_sha256": digest(original_lib),
                    "optimized_library_sha256": digest(candidate_lib),
                    "physical_index_sha256": index_hash,
                    "baseline_cases_compared": len(fingerprints),
                    "checks": [
                        "same physical index",
                        "identical trace feature values",
                        "numeric mean/variance/percentile results",
                        "adjacent-float stopping thresholds",
                        "physical work equality",
                        "no lightweight snapshots",
                        "no variance-only sorts",
                        "percentile sorting retained",
                        "phase counters bounded by total",
                    ],
                    "performance_scope": (
                        "small synthetic ARM fixture; fixed baseline-then-optimized order, "
                        "no Torch performance claim"
                    ),
                    "summaries": summaries,
                    "benchmark_pairs": benchmark,
                }
            ),
            flush=True,
        )
    finally:
        if backend is not None:
            backend.close()
        stop()


if __name__ == "__main__":
    main()
