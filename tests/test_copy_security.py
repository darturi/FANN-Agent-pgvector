import copy
import json
from contextlib import nullcontext
from types import SimpleNamespace

import pytest
from fannagent.api import AgentError, UnsupportedTarget
from fannagent.config import RunConfig
from fannagent.controller import open_run
from psycopg.conninfo import conninfo_to_dict

from fannagent_pgvector import security
from fannagent_pgvector.docker import docker


def firewall():
    entries = [{"table": {"family": "inet", "name": "fannagent_copy"}}]
    for name in ("input", "output", "forward"):
        entries.append({"chain": {
            "family": "inet", "table": "fannagent_copy", "name": name,
            "type": "filter", "hook": name, "prio": 0, "policy": "drop",
        }})
    for chain, field, direction, states in (
        ("input", "dport", "original", ["new", "established"]),
        ("output", "sport", "reply", ["established"]),
    ):
        entries.append({"rule": {
            "family": "inet", "table": "fannagent_copy", "chain": chain, "expr": [
                {"match": {"op": "==", "left": {
                    "payload": {"protocol": "tcp", "field": field}}, "right": 5432}},
                {"match": {"op": "in", "left": {"ct": {"key": "state"}},
                           "right": {"set": states}}},
                {"match": {"op": "==", "left": {"ct": {"key": "direction"}},
                           "right": direction}},
                {"accept": None},
            ],
        }})
    return {"nftables": entries}


def test_hba_names_cannot_inject_rules_or_match_special_keywords():
    text = security.hba('all', 'q" +other', "replication")
    assert 'host "all" "q"" +other" 0.0.0.0/0 scram-sha-256' in text
    assert 'host "all" "replication" ::/0 scram-sha-256' in text
    assert "trust" not in text
    for value in ("", "db\nhost all all all trust", "role\rfoo", "role\0"):
        with pytest.raises(UnsupportedTarget):
            security.hba(value, "role", "admin")


def test_generated_auth_is_independent_and_bootstrap_contains_no_password():
    class Connection:
        info = SimpleNamespace(encoding="utf-8")
        pgconn = SimpleNamespace(encrypt_password=lambda *args: b"SCRAM-SHA-256$verifier")

        def execute(self, statement, args):
            return SimpleNamespace(fetchone=lambda: (True,) if "rolcanlogin" in statement else None)

    first = security.new_auth(Connection(), "db", 'query"; DROP ROLE postgres; --')
    second = security.new_auth(Connection(), "db", first["query_role"])
    passwords = [a[k] for a in (first, second) for k in ("query_password", "admin_password")]
    assert len(set(passwords)) == 4
    assert all(len(password) >= 43 for password in passwords)
    assert first["admin_role"] != second["admin_role"]
    text = security.bootstrap_sql(first)
    assert all(password not in text for password in passwords)
    assert '"query""; DROP ROLE postgres; --"' in text
    assert text.count("\n") == 2


def test_copy_dsn_ignores_source_and_environment_endpoints(monkeypatch):
    monkeypatch.setenv("PGHOSTADDR", "192.0.2.1")
    monkeypatch.setenv("PGDATABASE", "source-db")
    monkeypatch.setenv("PGUSER", "source-role")
    auth = {"database": "db", "query_role": "query", "admin_role": "admin",
            "query_password": "query-secret", "admin_password": "admin-secret"}
    for admin, role, password in (
        (False, "query", "query-secret"), (True, "admin", "admin-secret")
    ):
        params = conninfo_to_dict(security.copy_dsn(auth, 54321, admin=admin))
        assert params["host"] == params["hostaddr"] == "127.0.0.1"
        assert params["port"] == "54321"
        assert params["user"] == role and params["password"] == password
        assert params["require_auth"] == "scram-sha-256"
        assert "service" not in params and params["options"] == ""


@pytest.mark.parametrize("mutation", ["accept_default", "egress_new", "wrong_port", "extra_rule"])
def test_actual_firewall_cannot_weaken_policy(mutation):
    document = firewall()
    security.validate_firewall(json.dumps(document))
    changed = copy.deepcopy(document)
    if mutation == "accept_default":
        changed["nftables"][2]["chain"]["policy"] = "accept"
    elif mutation == "egress_new":
        changed["nftables"][-1]["rule"]["expr"][1]["match"]["right"] = {"set": ["new"]}
    elif mutation == "wrong_port":
        changed["nftables"][-1]["rule"]["expr"][0]["match"]["right"] = 80
    else:
        changed["nftables"].append(copy.deepcopy(changed["nftables"][-1]))
    with pytest.raises(AgentError):
        security.validate_firewall(json.dumps(changed))


def test_sensitive_bootstrap_detects_sql_errors_without_echoing_them(monkeypatch):
    import fannagent_pgvector.docker as module

    monkeypatch.setattr(module.subprocess, "run", lambda *args, **kwargs: SimpleNamespace(
        returncode=0, stdout="", stderr="ERROR: secret-verifier"))
    with pytest.raises(AgentError) as error:
        docker("run", input_text="private SQL", sensitive=True, postgres_errors=True)
    assert "secret-verifier" not in str(error.value)


def test_audit_docker_timeout_is_bounded_and_redacted(monkeypatch):
    import subprocess

    import fannagent_pgvector.docker as module

    calls = []
    def expire(command, **kwargs):
        calls.append(kwargs)
        raise subprocess.TimeoutExpired(
            command, 30, output="private output", stderr="secret-verifier"
        )
    monkeypatch.setattr(module.subprocess, "run", expire)
    with pytest.raises(AgentError, match="Docker exec timed out after 30 seconds") as error:
        docker("exec", "owned-container", "sha256sum", "/private/path", timeout_seconds=30)
    assert calls[0]["timeout"] == 30
    assert "secret" not in str(error.value) and "private" not in str(error.value)


def test_security_audit_bounds_commands_without_caching_a_refusal(monkeypatch):
    import fannagent_pgvector.backend as module
    from fannagent_pgvector.backend import NativeBackend

    backend = NativeBackend(SimpleNamespace(), SimpleNamespace(get=lambda name: {"version": 1}))
    calls = []
    def audit(prepared, resources, operation):
        operation("exec", "container", "sha256sum", "/etc/fannagent/pg_hba.conf")
    def timeout(*args, **kwargs):
        calls.append(kwargs)
        raise AgentError("Docker exec timed out after 30 seconds")
    monkeypatch.setattr(module.security, "validate_runtime", audit)
    monkeypatch.setattr(module, "docker", timeout)
    with pytest.raises(AgentError, match="timed out"):
        backend._check_security()
    assert calls == [{"timeout_seconds": 30}]
    assert backend._binding is None and backend.conn is None


def test_legacy_copy_refused_before_any_connection_or_docker_call():
    def forbidden(*args):
        raise AssertionError("legacy copy must not be contacted")

    with pytest.raises(AgentError, match="legacy"):
        security.validate_runtime({"qualified": True}, {}, forbidden)


def test_saved_secret_cannot_open_an_unmarked_or_unprepared_copy(tmp_path, monkeypatch):
    import fannagent_pgvector.backend as module

    config = RunConfig(backend={"name": "pgvector", "options": {"target": {"resource": "unused"}}},
                       model={"ceiling_usd": "1"})
    _, _, wrapper = open_run(tmp_path / "run", config)
    wrapper.native.store.secret("copy_dsn", "old unsecured connection string")

    def forbidden(*args, **kwargs):
        raise AssertionError("an unmarked copy must not be contacted")

    monkeypatch.setattr(module, "docker", forbidden)
    monkeypatch.setattr(module.psycopg, "connect", forbidden)
    with pytest.raises(AgentError, match="legacy"):
        wrapper.native._connect()


def test_journal_cleanup_orders_dependencies_and_checks_network_ownership(tmp_path, monkeypatch):
    import fannagent_pgvector.integration as integration

    config = RunConfig(backend={"name": "pgvector", "options": {"target": {"resource": "unused"}}},
                       model={"ceiling_usd": "1"})
    _, _, backend = open_run(tmp_path / "run", config)
    label = "io.fannagent.run=test"
    for kind in ("network", "volume", "container"):
        backend.context.journal.record({"kind": kind, "name": kind, "label": label})
    calls = []

    def operation(kind, action, *args):
        calls.append((kind, action))
        if action == "inspect":
            return json.dumps([{"Labels": {"io.fannagent.run": "test"}}])
        return ""

    monkeypatch.setattr(integration, "docker", operation)
    def forbidden_secret(*args):
        raise AssertionError("cleanup must not read credentials")

    monkeypatch.setattr(backend.context.secrets, "get", forbidden_secret)
    backend.cleanup()
    assert [kind for kind, action in calls if action == "rm"] == ["container", "volume", "network"]
    monkeypatch.setattr(integration, "docker", lambda *args: json.dumps([
        {"Labels": {"io.fannagent.run": "foreign"}}]))
    with pytest.raises(AgentError, match="ownership"):
        backend.cleanup()


@pytest.mark.parametrize("stage", ["foreign_volume", "bootstrap", "startup", "recovery"])
def test_failed_restore_stops_owned_listeners_and_never_mounts_foreign_volume(
    tmp_path, monkeypatch, stage
):
    import fannagent_pgvector.backend as module

    backup = tmp_path / "backup"
    (backup / "base/5").mkdir(parents=True)
    (backup / "PG_VERSION").write_text("17")
    (backup / "backup_manifest").write_text('{"System-Identifier":123}')
    (backup / "base/5/100").write_bytes(b"physical-index")
    config = RunConfig(
        backend={"name": "pgvector", "options": {
            "target": {"resource": "fixture"},
            "copy": {"backup": str(backup)},
        }}, model={"ceiling_usd": "1"},
    )
    _, _, wrapper = open_run(tmp_path / "run", config)
    backend = wrapper.native
    source = {
        "compatible": True, "issues": [], "architecture": "arm64",
        "cluster_bytes_estimate": 1024,
        "versions": {"system_identifier": "123", "database": "postgres", "role": "postgres"},
        "index": {"filepath": "base/5/100", "oid": 100},
        "columns": [{"attname": "embedding", "atttypmod": 12}],
        "relation": {"reltuples": 1}, "metadata": [], "settings": {},
    }
    auth = {
        "version": 1, "database": "postgres", "query_role": "postgres",
        "admin_role": "copy_admin", "query_password": "private-query-password",
        "admin_password": "private-admin-password", "query_verifier": "SCRAM-SHA-256$query",
        "admin_verifier": "SCRAM-SHA-256$admin",
    }
    monkeypatch.setattr(backend, "inspect_target", lambda: source)
    monkeypatch.setattr(backend, "_source", lambda: nullcontext(None))
    monkeypatch.setattr(module.security, "new_auth", lambda *args: auth)
    monkeypatch.setattr(module.shutil, "disk_usage", lambda p: SimpleNamespace(free=2**40))
    calls = []

    def operation(*args, **kwargs):
        calls.append((args, kwargs))
        assert all(auth[k] not in str(args) for k in ("query_password", "admin_password"))
        owned = backend.store.get("owned_resources", {})
        label = owned.get("label", "io.fannagent.run=test").split("=", 1)[1]
        if args[:2] == ("image", "inspect"):
            return json.dumps([{"Architecture": "arm64", "Id": "image",
                               "Config": {"Labels": {"io.fannagent.binding": "1",
                                                    "io.fannagent.copy_security": "1",
                                                    "io.fannagent.copy_proxy": "1"}}}])
        if args[0] == "version":
            return "29.6.1"
        if args[0] == "info":
            return json.dumps({"MemTotal": 2**40})
        if args[:2] == ("volume", "create"):
            return "volume"
        if args[:2] == ("volume", "inspect"):
            return json.dumps([{"Labels": {"io.fannagent.run":
                                          "foreign" if stage == "foreign_volume" else label}}])
        if args[:2] == ("network", "create"):
            return "network-id"
        if args[:2] == ("network", "ls"):
            return ""
        if args[:2] == ("network", "inspect"):
            return json.dumps([{"Labels": {"io.fannagent.run": label}}])
        if args[:2] == ("container", "inspect"):
            if args[2] == owned.get("bootstrap"):
                raise AgentError("No such container")
            return json.dumps([{"Config": {"Labels": {"io.fannagent.run": label}},
                                "State": {"Running": True}}])
        if args[:2] == ("container", "stop"):
            return ""
        if args[0] == "inspect":
            return json.dumps([{"NetworkSettings": {
                "Networks": {owned["network"]: {"IPAddress": "172.20.0.2"}},
                "Ports": {"5432/tcp": [{"HostPort": "54321"}]}}}])
        if args[0] == "run":
            if "df -Pk /var/lib/postgresql | awk 'NR==2 {print $4}'" in args:
                return str(2**40)
            if "--single" in args:
                assert "--network" in args and args[args.index("--network") + 1] == "none"
                assert args[args.index("--log-driver") + 1] == "none"
                assert kwargs["sensitive"] and kwargs["postgres_errors"]
                if stage == "bootstrap":
                    raise AgentError("private bootstrap failed")
            if "-d" in args and stage == "startup":
                raise AgentError("startup failed")
            return ""
        raise AssertionError(args)

    monkeypatch.setattr(module, "docker", operation)
    if stage == "recovery":
        monkeypatch.setattr(module.psycopg, "connect",
                            lambda *args, **kwargs: (_ for _ in ()).throw(
                                module.psycopg.OperationalError("unavailable")))
        ticks = iter((0, 100))
        monkeypatch.setattr(module.time, "monotonic", lambda: next(ticks))
    with pytest.raises(AgentError):
        backend.prepare_copy()
    assert not backend.store.get("prepared")
    assert any(args[:2] == ("container", "stop") for args, _ in calls)
    if stage == "foreign_volume":
        assert not any("cp -a /backup/. /copy/" in str(args) for args, _ in calls)
    if stage == "bootstrap":
        assert not any(args[:2] == ("network", "create") for args, _ in calls)


def test_small_networks_use_configured_pools_and_retry_concurrent_reservations():
    calls = []

    def operation(*args):
        calls.append(args)
        if args[:2] == ("network", "ls"):
            return "existing"
        if args[:2] == ("network", "inspect"):
            return json.dumps([{"IPAM": {"Config": [{"Subnet": "192.0.2.0/28"}]}}])
        if "192.0.2.16/28" in args:
            raise AgentError("Pool overlaps with other one on this address space")
        assert "192.0.2.32/28" in args and "--internal" in args
        return "reserved"

    assert security.create_network(
        operation, "owned", "io.fannagent.run=test", internal=True,
        address_pools=[{"Base": "192.0.2.0/24", "Size": 24}],
    ) == "reserved"
    assert len(calls) == 4


def test_exhausted_network_pools_fail_without_mutating_foreign_networks():
    def operation(*args):
        if args[:2] == ("network", "ls"):
            return "foreign"
        assert args[:2] == ("network", "inspect")
        return json.dumps([{"IPAM": {"Config": [{"Subnet": "192.0.2.0/24"}]}}])

    with pytest.raises(UnsupportedTarget, match="no free subnet"):
        security.create_network(
            operation, "owned", "io.fannagent.run=test", internal=False,
            address_pools=[{"Base": "192.0.2.0/24", "Size": 24}],
        )
