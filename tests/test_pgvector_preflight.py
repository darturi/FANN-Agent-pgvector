import json
from types import SimpleNamespace

import pytest
from fannagent.config import RunConfig
from fannagent.controller import open_run
from fannagent.errors import AgentError, UnsupportedTarget

import fannagent_pgvector.backend as pg


def fixture(tmp_path, monkeypatch):
    backup = tmp_path / "backup"
    backup.mkdir()
    (backup / "PG_VERSION").write_text("17\n")
    (backup / "backup_manifest").write_text('{"System-Identifier":123}')
    config = RunConfig(
        backend={
            "name": "pgvector",
            "options": {"target": {"resource": "fixture"}, "copy": {"backup": str(backup)}},
        },
        model={"ceiling_usd": "1"},
    )
    _, _, wrapped = open_run(tmp_path / "run", config)
    backend = wrapped.native
    source = {
        "compatible": True,
        "issues": [],
        "architecture": "arm64",
        "cluster_bytes_estimate": 1024,
        "versions": {"system_identifier": "123", "database": "postgres", "role": "postgres"},
        "index": {"filepath": "base/5/100", "oid": 100},
    }
    monkeypatch.setattr(backend, "inspect_target", lambda: source)
    monkeypatch.setattr(pg.shutil, "disk_usage", lambda path: SimpleNamespace(free=2**40))
    calls = []

    def docker(*args):
        calls.append(args)
        if args[:2] == ("image", "inspect"):
            return json.dumps(
                [{"Architecture": "arm64", "Config": {"Labels": {
                    "io.fannagent.binding": "1", "io.fannagent.copy_security": "1",
                    "io.fannagent.copy_proxy": "1",
                }}}]
            )
        if args[0] == "version":
            return "29.6.1"
        if args[0] == "info":
            return json.dumps({"MemTotal": 2**40})
        if "df -Pk /var/lib/postgresql | awk 'NR==2 {print $4}'" in args:
            return str(2**40)
        if "pg_verifybackup" in args:
            raise AgentError("backup integrity or required WAL unavailable")
        if args[:2] == ("container", "inspect"):
            raise AgentError("No such container")
        raise AssertionError(f"unexpected mutation: {args[:2]}")

    monkeypatch.setattr(pg, "docker", docker)
    return backend, source, calls


def test_architecture_mismatch_refuses_physical_restore(tmp_path, monkeypatch):
    backend, source, calls = fixture(tmp_path, monkeypatch)
    source["architecture"] = "amd64"
    with pytest.raises(UnsupportedTarget, match="architecture"):
        backend.prepare_copy()
    assert len(calls) == 1


def test_wrong_backup_origin_never_creates_a_volume(tmp_path, monkeypatch):
    backend, source, calls = fixture(tmp_path, monkeypatch)
    source["versions"]["system_identifier"] = "456"
    with pytest.raises(UnsupportedTarget, match="system identifier"):
        backend.prepare_copy()
    assert all(call[0] != "volume" for call in calls)


def test_integrity_and_missing_wal_fail_before_restore(tmp_path, monkeypatch):
    backend, source, calls = fixture(tmp_path, monkeypatch)
    with pytest.raises(AgentError, match="integrity"):
        backend.prepare_copy()
    assert not backend.store.get("prepared")
    assert all(call[0] != "volume" for call in calls)


def test_insufficient_disk_fails_before_backup_copy(tmp_path, monkeypatch):
    backend, source, calls = fixture(tmp_path, monkeypatch)
    monkeypatch.setattr(pg.shutil, "disk_usage", lambda path: SimpleNamespace(free=1))
    with pytest.raises(UnsupportedTarget, match="insufficient"):
        backend.prepare_copy()
    assert not backend.store.get("owned_resources")


def test_exact_plan_checks_nodes_without_rejecting_quoted_identifier_names():
    sequential = [{"Plan": {"Node Type": "Seq Scan", "Relation Name": "Index Bitmap Documents"}}]
    assert not pg.uses_index(sequential)
    indexed = [{"Plan": {"Node Type": "Sort", "Plans": [{"Node Type": "Index Only Scan"}]}}]
    assert pg.uses_index(indexed)
    assert pg.uses_index({"Node Type": "Bitmap Heap Scan"})


def test_private_state_and_durable_resource_journal(tmp_path):
    config = RunConfig(
        backend={"name": "pgvector", "options": {"target": {"resource": "fixture"}}},
        model={"ceiling_usd": "1"},
    )
    _, store, backend = open_run(tmp_path / "run", config)
    assert backend.context.state.get("config") is None
    backend.native.store.set(
        "owned_resources",
        {"container": "owned", "volume": "owned-data", "label": "io.fannagent.run=123"},
    )
    assert len(backend.context.journal.resources()) == 2
    assert not store.get("owned_resources")
    _, _, reopened = open_run(store.root)
    assert reopened.context.journal.resources() == backend.context.journal.resources()


def test_cleanup_without_source_credentials_refuses_foreign_resources(tmp_path, monkeypatch):
    import fannagent_pgvector.integration as integration

    config = RunConfig(
        backend={"name": "pgvector", "options": {"target": {"resource": "fixture"}}},
        model={"ceiling_usd": "1"},
    )
    _, _, backend = open_run(tmp_path / "run", config)
    monkeypatch.delenv("FANNAGENT_DATABASE_URL", raising=False)
    backend.context.journal.record(
        {"kind": "volume", "name": "foreign", "label": "io.fannagent.run=123"}
    )
    calls = []

    def foreign(*args):
        calls.append(args)
        return json.dumps([{"Labels": {"io.fannagent.run": "other"}}])

    monkeypatch.setattr(integration, "docker", foreign)
    with pytest.raises(AgentError, match="ownership"):
        backend.cleanup()
    assert all(args[1] == "inspect" for args in calls)

    def missing(*args):
        raise AgentError("No such volume: foreign")

    monkeypatch.setattr(integration, "docker", missing)
    backend.cleanup()
    backend.cleanup()


def test_extension_imports_only_public_core_api():
    import ast
    from pathlib import Path

    for path in (Path(__file__).parents[1] / "src").rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.ImportFrom):
                name = node.module or ""
                assert not name.startswith("fannbench"), path
                if name.startswith("fannagent."):
                    assert name.startswith("fannagent.api"), (path, name)
