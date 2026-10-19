"""Fresh disposable ARM64 qualification. Invoke explicitly; never uses user databases."""

import importlib.util
import json
import os
import runpy
import subprocess
import time
import uuid
from pathlib import Path

import psycopg
from fannagent.api.conformance import check_observation
from fannagent.config import RunConfig
from fannagent.controller import open_run
from fannagent.study import Study
from psycopg import sql
from psycopg.conninfo import make_conninfo
from security_cases import (
    check_authentication,
    check_isolation,
    check_tamper_and_restart,
    check_udp_and_startup_failures,
)

from fannagent_pgvector.docker import docker

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent / ".qualification" / uuid.uuid4().hex[:10]
ROOT.mkdir(parents=True)
IMAGE = os.environ.get("FANNAGENT_PGVECTOR_IMAGE", "fannagent/pgvector:0.8.6-secure-v1")
label = "io.fannagent.qualification=" + ROOT.name
source = "fannagent-qual-source-" + ROOT.name
owned = {"container": source, "label": label}
(ROOT / "source-ownership.json").write_text(json.dumps(owned))
spec = importlib.util.spec_from_file_location("native_cases", HERE / "test_pgvector_integration.py")
cases = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cases)
records = []
previous_password = None
SOURCE_PASSWORD = "disposable-qualification-source-only"
QUERY_ROLE = 'Search " Role'
diskcheck = source + "-diskcheck"
try:
    # A stalled Docker exec/start must leave failure evidence, not an unbounded test run.
    output = subprocess.run(
        ["docker", "run", "--rm", "--name", diskcheck, "--label", label,
         "--network", "none", "--entrypoint", "df", "--tmpfs",
         "/var/lib/postgresql/data:size=64k", IMAGE, "-Pk", "/var/lib/postgresql"],
        capture_output=True, text=True, timeout=30, check=True,
    ).stdout
    free = int(output.splitlines()[-1].split()[3]) * 1024
except (subprocess.TimeoutExpired, subprocess.CalledProcessError) as exc:
    (ROOT / "results.json").write_text(json.dumps([
        {"case": "docker_diskcheck", "status": "blocked", "reason": type(exc).__name__,
         "container": diskcheck, "timeout_seconds": 30}
    ], indent=2) + "\n")
    print("qualification_artifacts", ROOT, flush=True)
    raise
finally:
    subprocess.run(["docker", "rm", "-f", diskcheck], capture_output=True, timeout=15)
if free < 1024**3:
    raise RuntimeError("native qualification requires at least 1 GiB free in Docker's filesystem")
try:
    docker(
        "run",
        "-d",
        "--name",
        source,
        "--label",
        label,
        "-e",
        "POSTGRES_PASSWORD=" + SOURCE_PASSWORD,
        "-p",
        "0.0.0.0::5432",
        "fannagent/pgvector-stock-fixture:0.8.6",
    )
    port = json.loads(docker("inspect", source))[0]["NetworkSettings"]["Ports"]["5432/tcp"][0][
        "HostPort"
    ]
    source_host, source_connection_port = "127.0.0.1", port
    if os.environ.get("FANNAGENT_CONTROLLER"):
        # Qualification-only disposable source and backup helper share the default
        # bridge. Use its daemon-side address rather than a Desktop host port.
        source_host = json.loads(docker("inspect", source))[0]["NetworkSettings"]["Networks"][
            "bridge"]["IPAddress"]
        source_connection_port = "5432"
    dsn = (
        f"host={source_host} port={source_connection_port} "
        "user=postgres dbname=postgres sslmode=disable "
        f"password={SOURCE_PASSWORD}"
    )
    for _ in range(240):
        try:
            with psycopg.connect(dsn, autocommit=True, connect_timeout=1) as connection:
                connection.execute("SELECT 1")
                time.sleep(1)
                connection.execute("SELECT 1")
                break
        except psycopg.OperationalError:
            time.sleep(0.25)
    else:
        raise RuntimeError("disposable source did not start; inspect source startup diagnostics")
    os.environ["FANNAGENT_FIXTURE_URL"] = dsn
    os.environ["FANNAGENT_TEST_SOURCE_URL"] = dsn
    os.environ["FANNAGENT_DATABASE_URL"] = dsn
    os.environ["FANNAGENT_REPLICATION_URL"] = dsn.replace("127.0.0.1", "host.docker.internal")
    runpy.run_path(str(HERE / "fixtures/initialize.py"))
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute("ALTER ROLE postgres SET hnsw.ef_search='80'")
        conn.execute("CREATE DATABASE unrelated_fixture")
        conn.execute("CREATE ROLE unrelated_role LOGIN PASSWORD 'disposable-unrelated-only'")
        conn.execute(sql.SQL("CREATE ROLE {} LOGIN PASSWORD {}").format(
            sql.Identifier(QUERY_ROLE), sql.Literal(SOURCE_PASSWORD)))
        conn.execute(sql.SQL('GRANT USAGE ON SCHEMA "agent fixture" TO {}').format(
            sql.Identifier(QUERY_ROLE)))
        conn.execute(sql.SQL('GRANT SELECT ON "agent fixture"."Documents" TO {}').format(
            sql.Identifier(QUERY_ROLE)))
        conn.execute(sql.SQL("GRANT EXECUTE ON FUNCTION pg_control_system() TO {}").format(
            sql.Identifier(QUERY_ROLE)))
        conn.execute(sql.SQL("ALTER ROLE {} SET hnsw.ef_search='80'").format(
            sql.Identifier(QUERY_ROLE)))
        conn.execute("CHECKPOINT")
        source_auth = conn.execute(
            "SELECT rolname,rolpassword FROM pg_authid WHERE rolname IN ('postgres',%s)",
            (QUERY_ROLE,),
        ).fetchall()
    docker(
        "exec",
        source,
        "sh",
        "-c",
        "echo 'host replication postgres 0.0.0.0/0 scram-sha-256' "
        ">> /var/lib/postgresql/data/pg_hba.conf",
    )
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute("SELECT pg_reload_conf()")
    backup = ROOT / "supplied-backup"
    backup.mkdir()
    docker(
        "run",
        "--rm",
        "--user",
        f"{os.getuid()}:{os.getgid()}",
        "-v",
        f"{backup}:/backup",
        "--entrypoint",
        "pg_basebackup",
        IMAGE,
        "-d",
        dsn.replace("127.0.0.1", "host.docker.internal"),
        "-D",
        "/backup",
        "-X",
        "stream",
        "--checkpoint=fast",
    )
    regular = [
        cases.test_restored_native_search_matches_stock_source,
        cases.test_real_stop_custom_fields_and_signed_ids,
        cases.test_continue_abort_reuse_and_bounded_trace,
        cases.test_interpreter_failure_continues_and_timeout_resets,
        cases.test_empty_non_hnsw_route_is_truthful,
        cases.test_background_checkpoint_does_not_invalidate_snapshot,
        cases.test_control_transport_timeout_and_connection_loss,
        cases.test_sequential_control_batches_escape_and_late_commit_error,
    ]
    for method in ("supplied", "streamed"):
        for group, tests in (
            ("regular", regular),
            ("invalidation", [cases.test_mutated_copy_cannot_be_used_for_policy_selection]),
            ("hot", [cases.test_hot_visibility_duplicate_vectors_and_snapshot]),
            ("query_role", [cases.test_restored_native_search_matches_stock_source]),
        ):
            os.environ["FANNAGENT_DATABASE_URL"] = (
                make_conninfo(dsn, user=QUERY_ROLE) if group == "query_role" else dsn
            )
            config = RunConfig(
                backend={
                    "name": "pgvector",
                    "options": {
                        "target": {
                            "resource": "Documents",
                            "schema_name": "agent fixture",
                            "id_column": "Document Key",
                            "vector_column": "Embedding Vector",
                            "index": "Vectors HNSW",
                        },
                        "copy": {
                            "image": IMAGE,
                            **(
                                {"backup": str(backup)}
                                if method == "supplied"
                                else {"replication_env": "FANNAGENT_REPLICATION_URL"}
                            ),
                        },
                    },
                },
                model={"ceiling_usd": "1"},
                resources={"cpus": 2, "memory_gib": 1},
                evidence={"max_bytes": 64 * 1024**2},
                workload={"count": 1000, "warmups": 0, "passes": 1},
            )
            _, store, backend = open_run(ROOT / f"{method}-{group}", config)
            try:
                prepared = backend.prepare_copy()
                store.set("prepared", prepared.serialize())
                before = backend.compatibility()
                check_authentication(backend.native, SOURCE_PASSWORD, previous_password)
                previous_password = json.loads(backend.native.store.secret("copy_auth"))[
                    "query_password"
                ]
                if group == "query_role":
                    check_authentication(backend.native, SOURCE_PASSWORD)
                    with psycopg.connect(backend.native._connection_dsn()) as connection:
                        assert connection.execute(
                            "SELECT rolsuper FROM pg_roles WHERE rolname=current_user"
                        ).fetchone() == (False,)
                    records.append(
                        {"method": method, "case": "source_query_role", "status": "passed"}
                    )
                for case in tests:
                    case(backend.native)
                    records.append({"method": method, "case": case.__name__, "status": "passed"})
                    print(method, case.__name__, "passed", flush=True)
                if group == "regular":
                    check_authentication(backend.native, SOURCE_PASSWORD)
                    check_isolation(backend.native, source, port)
                    check_udp_and_startup_failures(backend.native)
                    check_tamper_and_restart(backend.native)
                    records.append({"method": method, "case": "copy_security", "status": "passed"})
                    backend.native.config.copy.trace_max_bytes = config.evidence.trace_max_bytes
                    q = cases.query(backend.native)
                    check_observation(backend, q)
                    study = Study(config, store, backend)
                    labels = next(
                        (
                            value
                            for item in study.development[:100]
                            if (value := study.stop_labels(item["query"]))["labels"]
                        ),
                        None,
                    )
                    assert labels is not None
                    assert labels["cost"] is None or labels["cost"] >= 64
                    policy = backend.validate_policy({"name": "continue", "root": "continue"})
                    session = backend.open_policy_session(policy)
                    result = session.query(q)
                    assert all(type(i) is int for i in result.ids)
                    extreme = session.query(
                        {"id": "extreme", "vector": backend.snapshot().rows[0]["vector"], "k": 10}
                    )
                    assert -(2**63) in extreme.ids
                    session.close()
                    original = backend.native.execute_probe

                    def fail_policy(query, *, mode="native", **kwargs):
                        if mode == "policy":
                            raise RuntimeError("fixture policy failure")
                        return original(query, mode=mode, **kwargs)

                    backend.native.execute_probe = fail_policy
                    session = backend.open_policy_session(policy)
                    fallback = session.query(q)
                    assert fallback.metadata["fallback"] == "ordinary_default"
                    try:
                        session.query(q, fallback=False)
                    except RuntimeError:
                        pass
                    else:
                        raise AssertionError("disabled fallback hid the policy failure")
                    session.close()
                    backend.native.execute_probe = original
                    assert backend.compatibility() == before
                    records.append(
                        {
                            "method": method,
                            "case": "public_sdk_labels_serving_identity",
                            "status": "passed",
                        }
                    )
            finally:
                # Capture only disposable copy logs, with all private auth values redacted.
                auth = json.loads(backend.native.store.secret("copy_auth") or "{}")
                resources = backend.native.store.get("owned_resources") or {}
                for kind in ("container", "proxy"):
                    if resources.get(kind):
                        try:
                            process = subprocess.run(
                                ["docker", "logs", resources[kind]], capture_output=True, text=True
                            )
                            logs = process.stdout + process.stderr
                            for key, value in auth.items():
                                if key.endswith(("_password", "_verifier")):
                                    logs = logs.replace(value, "[redacted]")
                            (ROOT / f"{method}-{group}-{kind}.log").write_text(logs)
                        except Exception:
                            pass
                backend.cleanup()
                backend.cleanup()
                backend.close()
    with psycopg.connect(dsn, autocommit=True) as connection:
        assert connection.execute(
            "SELECT rolname,rolpassword FROM pg_authid WHERE rolname IN ('postgres',%s)",
            (QUERY_ROLE,),
        ).fetchall() == source_auth
finally:
    process = subprocess.run(["docker", "logs", source], capture_output=True, text=True)
    (ROOT / "source.log").write_text(process.stdout + process.stderr)
    item = json.loads(docker("inspect", source))[0]
    key, value = label.split("=", 1)
    assert item["Config"]["Labels"][key] == value
    docker("rm", "-fv", source)
    (ROOT / "results.json").write_text(json.dumps(records, indent=2))
    print("qualification_artifacts", ROOT, flush=True)
