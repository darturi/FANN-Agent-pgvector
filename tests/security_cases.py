"""Adversarial checks for new, explicitly disposable qualification copies."""

import copy
import json
import subprocess
import time

import psycopg
from fannagent.api import AgentError
from psycopg.conninfo import conninfo_to_dict, make_conninfo

from fannagent_pgvector import security
from fannagent_pgvector.docker import docker


def reject_connection(dsn, **overrides):
    params = conninfo_to_dict(dsn)
    params.update(overrides, connect_timeout="2",
                  passfile="/nonexistent-fannagent-copy-password-file")
    try:
        with psycopg.connect(make_conninfo(**params), autocommit=True):
            raise AssertionError("unauthorized connection succeeded")
    except psycopg.OperationalError:
        pass


def refusal(operation):
    try:
        operation()
        raise AssertionError("insecure copy was accepted")
    except AgentError:
        pass


def container_logs(name):
    result = subprocess.run(["docker", "logs", name], capture_output=True, text=True, check=True)
    return result.stdout + result.stderr


def check_authentication(backend, source_password, previous_password=None):
    dsn = backend._connection_dsn()
    admin = backend._connection_dsn(admin=True)
    auth = json.loads(backend.store.secret("copy_auth"))
    assert auth["query_password"] != auth["admin_password"]
    assert source_password not in (auth["query_password"], auth["admin_password"])
    for connection in (dsn, admin):
        for password in ("", "wrong-copy-password", source_password):
            reject_connection(connection, password=password)
        if previous_password:
            reject_connection(connection, password=previous_password)
        reject_connection(connection, dbname="unrelated_fixture")
        reject_connection(connection, replication="true")
        reject_connection(connection, replication="database")
        reject_connection(connection, user="unrelated_role")
    with psycopg.connect(dsn, autocommit=True) as conn:
        assert conn.pgconn.used_password
        assert conn.execute("SELECT current_user").fetchone()[0] == auth["query_role"]
    prepared = backend.store.get("prepared")
    runtime = json.loads(docker("container", "inspect", prepared["container"]))[0]
    relay = json.loads(docker("inspect", prepared["security"]["proxy"]))[0]
    public = (
        json.dumps(runtime["Config"]) + container_logs(prepared["container"])
        + json.dumps(relay["Config"]) + container_logs(prepared["security"]["proxy"])
    )
    assert all(auth[key] not in public for key in (
        "query_password", "admin_password", "query_verifier", "admin_verifier"
    ))
    for path in backend.store.root.rglob("*"):
        if path.is_file():
            data = path.read_bytes()
            assert all(auth[key].encode() not in data for key in (
                "query_password", "admin_password", "query_verifier", "admin_verifier"
            ))
    backend._check_security()


def check_isolation(backend, source, source_port):
    prepared = backend.store.get("prepared")
    network = prepared["security"]["network"]
    runtime = json.loads(docker("inspect", prepared["container"]))[0]
    address = runtime["NetworkSettings"]["Networks"][network]["IPAddress"]
    image = backend.config.copy.image
    # This peer has no shared network: the original audit's unauthenticated attack.
    refusal(lambda: docker("run", "--rm", "--network", "bridge", "--entrypoint", "pg_isready",
                          image, "-h", address, "-p", "5432", "-t", "2"))
    docker("network", "connect", "--alias", "fannagent-egress-peer", network, source)
    try:
        peer = json.loads(docker("inspect", source))[0]["NetworkSettings"]["Networks"][network]
        # Even a deliberately attached peer cannot skip authentication.
        refusal(lambda: docker(
            "exec", source, "psql", "-w", "-h", address, "-U",
            json.loads(backend.store.secret("copy_auth"))["query_role"],
            "-d", "postgres", "-c", "SELECT current_user",
        ))
        # The same-network peer and gateway listener are reachable routes. Both NEW
        # connections must be dropped by the namespace firewall.
        gateway = json.loads(docker("network", "inspect", network))[0]["IPAM"]["Config"][0][
            "Gateway"
        ]
        for host, port in ((peer["IPAddress"], 5432), (gateway, source_port), ("127.0.0.1", 5432)):
            refusal(lambda host=host, port=port: docker(
                "exec", "--user", "postgres", prepared["container"], "pg_isready",
                "-h", host, "-p", str(port), "-t", "2",
            ))
        # The alias is real: NXDOMAIN must not be mistaken for DNS isolation.
        assert docker("exec", source, "getent", "hosts", "fannagent-egress-peer")
        for name in (prepared["container"], prepared["security"]["proxy"]):
            refusal(lambda name=name: docker(
                "exec", "--user", "postgres", name,
                "timeout", "3", "getent", "hosts", "fannagent-egress-peer",
            ))
        refusal(lambda: docker(
            "exec", "--user", "postgres", prepared["security"]["proxy"], "pg_isready",
            "-h", peer["IPAddress"], "-p", "5432", "-t", "2",
        ))
        # PostgreSQL cannot alter its firewall, even through COPY PROGRAM privileges.
        refusal(lambda: docker(
            "exec", "--user", "postgres", prepared["container"],
            "setpriv", "--bounding-set=-all", "--no-new-privs",
            "nft", "flush", "table", "inet", "fannagent_copy",
        ))
    finally:
        docker("network", "disconnect", network, source)
    backend._check_security()


def check_udp_and_startup_failures(backend):
    prepared = backend.store.get("prepared")
    resources = backend.store.get("owned_resources")
    peer = prepared["container"] + "-udp-test"
    backend.store.context.journal.record(
        {"kind": "container", "name": peer, "label": resources["label"]}
    )
    docker(
        "run", "-d", "--name", peer, "--label", resources["label"],
        "--network", resources["network"], "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges", "--tmpfs", "/var/lib/postgresql/data:size=64k",
        "--entrypoint", "socat", backend.config.copy.image,
        "UDP4-RECVFROM:5353,reuseaddr,fork", "EXEC:/bin/cat",
    )
    try:
        item = json.loads(docker("inspect", peer))[0]
        security.owned(item, resources["label"])
        address = item["NetworkSettings"]["Networks"][resources["network"]]["IPAddress"]

        def udp_probe(container, target):
            return docker(
                "exec", "--user", "postgres", container, "sh", "-c",
                "printf firewall-probe | timeout 3 socat -T2 - UDP4-DATAGRAM:" + target + ":5353",
            )

        assert udp_probe(peer, "127.0.0.1") == "firewall-probe"
        for container in (prepared["container"], resources["proxy"]):
            try:
                assert udp_probe(container, address) == ""
            except AgentError as exc:
                # Linux may report the namespace OUTPUT drop directly to sendto().
                assert "Operation not permitted" in str(exc)
    finally:
        security.owned(json.loads(docker("inspect", peer))[0], resources["label"])
        docker("rm", "-f", peer)

    # Reuse an already journalled, transient helper identity for startup fault injection.
    helper = resources["bootstrap"]
    base = (
        "run", "--rm", "--name", helper, "--label", resources["label"], "--network", "none",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--tmpfs", "/var/lib/postgresql/data:size=64k",
    )
    caps = tuple(arg for capability in security.CAPABILITIES for arg in ("--cap-add", capability))
    # Missing NET_ADMIN and malformed firewall must abort before even `postgres --version`.
    refusal(lambda: docker(*base, backend.config.copy.image, "postgres", "--version"))
    policy = backend.store.root / "private" / "invalid-firewall.nft"
    policy.write_text("deliberately invalid firewall syntax\n")
    try:
        refusal(lambda: docker(
            *base, *caps, "--mount",
            f"type=bind,source={policy},target={security.POLICY_PATH},readonly",
            backend.config.copy.image, "postgres", "--version",
        ))
    finally:
        policy.unlink()
    refusal(lambda: docker(
        *base, *caps, backend.config.copy.image, "postgres", "-D", "/nonexistent-fixture-data",
    ))
    backend._check_security()


def check_tamper_and_restart(backend):
    identity = backend.compatibility()
    prepared = backend.store.get("prepared")
    container = prepared["container"]
    saved = copy.deepcopy(prepared)
    for mutation in ("legacy", "port", "hba"):
        changed = copy.deepcopy(saved)
        if mutation == "legacy":
            changed.pop("security")
        elif mutation == "port":
            changed["security"]["port"] = "1"
        else:
            changed["security"]["hba_sha256"] = "0" * 64
        backend.store.set("prepared", changed)
        refusal(backend._check_security)
    backend.store.set("prepared", saved)
    # An extra default-bridge attachment must be detected with an already-open connection.
    docker("network", "connect", "bridge", container)
    try:
        refusal(backend.compatibility)
    finally:
        docker("network", "disconnect", "bridge", container)
    authentication = backend.store.root / "private" / "pg_hba.conf"
    contents = authentication.read_text()
    try:
        authentication.chmod(0o600)
        authentication.write_text("deliberately invalid authentication rule\n")
        authentication.chmod(0o444)
        refusal(backend._check_security)
    finally:
        authentication.chmod(0o600)
        authentication.write_text(contents)
        authentication.chmod(0o444)
    backend.close()
    docker("stop", "--time", "10", container)
    resources = backend.store.get("owned_resources")
    security.owned(json.loads(docker("volume", "inspect", resources["volume"]))[0],
                   resources["label"])
    refusal(lambda: docker(
        "run", "--rm", "--name", resources["bootstrap"], "--label", resources["label"],
        "--network", "none", "--user", "postgres", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges", "--entrypoint", "postgres", "-i",
        "-v", f'{resources["volume"]}:/var/lib/postgresql/data', backend.config.copy.image,
        "--single", "-j", "-D", "/var/lib/postgresql/data",
        *security.server_arguments("listen_addresses=", "unix_socket_directories="),
        "postgres", input_text="SELECT fannagent_missing_bootstrap_function();\n\n",
        sensitive=True, postgres_errors=True,
    ))
    reject_connection(backend._connection_dsn(admin=True))
    docker("restart", "--time", "10", container)
    for _ in range(60):
        try:
            with psycopg.connect(backend._connection_dsn(admin=True), connect_timeout=1):
                break
        except psycopg.OperationalError:
            time.sleep(0.25)
    backend._check_security()
    # Restoring the container does not authorize reuse of cached binding facts.
    # The failed compatibility check must remain blocking until a full recheck.
    refusal(backend._connect)
    assert backend._binding is None
    assert backend.compatibility() == identity
    assert backend._connect().execute("SELECT 1").fetchone() == (1,)
