"""Mandatory local-copy authentication and network policy (not query semantics)."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import secrets
from pathlib import Path

import psycopg
from fannagent.api import AgentError, UnsupportedTarget
from psycopg import sql
from psycopg.conninfo import make_conninfo

VERSION = 1
HBA_PATH = "/etc/fannagent/pg_hba.conf"
POLICY_PATH = "/usr/local/share/fannagent/copy.nft"
ENTRYPOINT = "/usr/local/bin/fannagent-copy-entrypoint"
CAPABILITIES = ("NET_ADMIN", "SETUID", "SETGID", "SETPCAP")
ENGINE = Path(__file__).parent / "engine"

# These override copied cluster settings before recovery or any preload can run.
SERVER_OPTIONS = (
    "primary_conninfo=",
    "restore_command=",
    "archive_mode=off",
    "archive_command=",
    "archive_library=",
    "shared_preload_libraries=",
    "session_preload_libraries=",
    "local_preload_libraries=",
    "max_logical_replication_workers=0",
    "max_wal_senders=0",
    "autovacuum=off",
    "ssl=off",
    "password_encryption=scram-sha-256",
    "logging_collector=off",
    "log_destination=stderr",
    "log_statement=none",
    "log_duration=off",
    "log_min_duration_statement=-1",
    "log_min_duration_sample=-1",
    "log_min_error_statement=panic",
    "lc_messages=C",
)


def server_arguments(*extra):
    return tuple(arg for setting in (*SERVER_OPTIONS, *extra) for arg in ("-c", setting))


def hba_name(name):
    if not isinstance(name, str) or not name or any(c in name for c in "\r\n\x00"):
        raise UnsupportedTarget("database and role names must be nonempty without line breaks")
    return '"' + name.replace('"', '""') + '"'


def hba(database, query_role, admin_role):
    database = hba_name(database)
    roles = (hba_name(query_role), hba_name(admin_role))
    rules = ["local all all reject"]
    for role in roles:
        for address in ("0.0.0.0/0", "::/0"):
            rules.append(f"host {database} {role} {address} scram-sha-256")
    for database in ("all", "replication"):
        for address in ("0.0.0.0/0", "::/0"):
            rules.append(f"host {database} all {address} reject")
    return "\n".join(rules) + "\n"


def new_auth(connection, database, query_role):
    hba_name(database)
    hba_name(query_role)
    if psycopg.pq.version() < 160000:
        raise UnsupportedTarget("copy security requires libpq 16+ with require_auth support")
    if connection.execute(
        "SELECT rolcanlogin FROM pg_roles WHERE rolname=%s", (query_role,)
    ).fetchone() != (True,):
        raise UnsupportedTarget("the inspected source query role must permit LOGIN")
    admin_role = "fannagent_copy_" + secrets.token_hex(16)
    if connection.execute(
        "SELECT 1 FROM pg_roles WHERE rolname=%s", (admin_role,)
    ).fetchone():
        raise AgentError("generated copy administration role conflicts with a source role")
    result = {"version": VERSION, "database": database, "query_role": query_role,
              "admin_role": admin_role}
    for kind, role in (("query", query_role), ("admin", admin_role)):
        password = secrets.token_urlsafe(32)
        result[kind + "_password"] = password
        # Explicit algorithm: libpq performs local encryption without a server query.
        result[kind + "_verifier"] = connection.pgconn.encrypt_password(
            password.encode(), role.encode(connection.info.encoding), b"scram-sha-256"
        ).decode()
    return result


def bootstrap_sql(auth):
    """A single atomic command entry; no cleartext password enters PostgreSQL SQL."""
    role = sql.Identifier(auth["query_role"])
    database = sql.Identifier(auth["database"])
    commands = [
        sql.SQL("CREATE ROLE {} LOGIN SUPERUSER PASSWORD {}").format(
            sql.Identifier(auth["admin_role"]), sql.Literal(auth["admin_verifier"])
        ),
        sql.SQL("ALTER ROLE {} PASSWORD {} VALID UNTIL 'infinity'").format(
            role, sql.Literal(auth["query_verifier"])
        ),
    ]
    # Role/database startup defaults otherwise override the server's preload defaults.
    for setting in ("session_preload_libraries", "local_preload_libraries"):
        commands.extend([
            sql.SQL("ALTER ROLE {} RESET {}").format(role, sql.Identifier(setting)),
            sql.SQL("ALTER ROLE {} IN DATABASE {} RESET {}").format(
                role, database, sql.Identifier(setting)
            ),
            sql.SQL("ALTER DATABASE {} RESET {}").format(database, sql.Identifier(setting)),
        ])
    return "; ".join(command.as_string() for command in commands) + ";\n\n"


def copy_dsn(auth, port, *, admin=False):
    return make_conninfo(
        host="127.0.0.1", hostaddr="127.0.0.1", port=str(port), dbname=auth["database"],
        user=auth["admin_role" if admin else "query_role"],
        password=auth["admin_password" if admin else "query_password"],
        require_auth="scram-sha-256", sslmode="disable", gssencmode="disable",
        channel_binding="disable", options="", connect_timeout="10",
        application_name="fannagent-copy",
    )


def controller_dsn(dsn, prepared, resources, docker):
    """Reach the authenticated relay from a trusted disposable controller.

    Saved credentials retain their host endpoint. Connection routing is launch-local
    and therefore never changes the frozen configuration or native compatibility.
    """
    controller = os.environ.get("FANNAGENT_CONTROLLER")
    if not controller:
        return dsn
    item = json.loads(docker("container", "inspect", controller))[0]
    if item.get("Config", {}).get("Labels", {}).get("io.fannagent.controller") != "1":
        raise AgentError("container launcher requires a labelled trusted controller")
    secure = prepared["security"]
    network = secure["ingress_network"]
    net = json.loads(docker("network", "inspect", secure["ingress_network_id"]))[0]
    owned(net, resources["label"])
    if net["Name"] != network:
        raise AgentError("controller ingress network identity changed")
    memberships = item["NetworkSettings"]["Networks"]
    if network not in memberships:
        docker("network", "connect", network, controller)
        item = json.loads(docker("container", "inspect", controller))[0]
    if item["NetworkSettings"]["Networks"][network]["NetworkID"] != secure["ingress_network_id"]:
        raise AgentError("controller ingress network membership changed")
    relay = json.loads(docker("container", "inspect", secure["proxy"]))[0]
    owned(relay, resources["label"])
    membership = relay["NetworkSettings"]["Networks"][network]
    if membership["NetworkID"] != secure["ingress_network_id"] or not membership["IPAddress"]:
        raise AgentError("relay ingress endpoint changed")
    address = membership["IPAddress"]
    return make_conninfo(dsn, host=address, hostaddr=address, port="5432")


def detach_controller(network, docker):
    controller = os.environ.get("FANNAGENT_CONTROLLER")
    if controller:
        item = json.loads(docker("container", "inspect", controller))[0]
        if item.get("Config", {}).get("Labels", {}).get("io.fannagent.controller") != "1":
            raise AgentError("unlabelled controller cannot detach from owned networks")
        if network in item["NetworkSettings"]["Networks"]:
            docker("network", "disconnect", network, controller)


def policy_hash(*, proxy=False):
    path = ENGINE / ("proxy.nft" if proxy else "copy.nft")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate_firewall(document, *, database_ip=None):
    """Validate actual rules, rather than trusting the image label or an attestation."""
    entries = json.loads(document)["nftables"]
    table_name = "fannagent_proxy" if database_ip else "fannagent_copy"
    chains, rules, tables = {}, {"input": [], "output": [], "forward": []}, []
    for entry in entries:
        if "metainfo" in entry:
            continue
        if "table" in entry:
            tables.append((entry["table"]["family"], entry["table"]["name"]))
        elif "chain" in entry:
            chain = entry["chain"]
            name = chain["name"]
            if name in chains:
                raise AgentError("copy firewall contains duplicate chains")
            chains[name] = (
                chain.get("family"), chain.get("table"), chain.get("type"),
                chain.get("hook"), chain.get("prio"), chain.get("policy"),
            )
        elif "rule" in entry:
            rule = entry["rule"]
            if (rule.get("family"), rule.get("table")) != ("inet", table_name):
                raise AgentError("copy firewall has an unexpected rule")
            if rule["chain"] not in rules:
                raise AgentError("copy firewall has an unexpected chain")
            rules[rule["chain"]].append(rule["expr"])
        else:
            raise AgentError("copy firewall contains unexpected objects")
    expected = {
        name: ("inet", table_name, "filter", name, 0, "drop") for name in rules
    }
    if tables != [("inet", table_name)] or chains != expected:
        raise AgentError("copy firewall must deny traffic by default")
    specs = [
        ("input", 0, "dport", "original", {"new", "established"}, None),
        ("output", 0, "sport", "reply", {"established"}, None),
    ]
    if database_ip:
        specs.extend([
            ("input", 1, "sport", "reply", {"established"}, "saddr"),
            ("output", 1, "dport", "original", {"new", "established"}, "daddr"),
        ])
    if any(len(rules[chain]) != (2 if database_ip else 1) for chain in ("input", "output")):
        raise AgentError("copy firewall rules changed")
    for chain, ordinal, field, direction, states, address in specs:
        matches = rules[chain][ordinal]
        if len(matches) != (5 if address else 4):
            raise AgentError("copy firewall rules changed")
        expected_left = [
            {"payload": {"protocol": "tcp", "field": field}},
            {"ct": {"key": "state"}},
            {"ct": {"key": "direction"}},
        ]
        if address:
            expected_left.append({"payload": {"protocol": "ip", "field": address}})
        for index, left in enumerate(expected_left):
            match = matches[index].get("match", {})
            if match.get("left") != left or match.get("op") not in ("==", "in"):
                raise AgentError("copy firewall rules changed")
            right = match.get("right")
            valid = (
                right == 5432 if index == 0 else
                (set(right["set"]) if isinstance(right, dict) else {right}) == states
                if index == 1 else right == direction if index == 2 else right == database_ip
            )
            if not valid:
                raise AgentError("copy firewall rules changed")
        if matches[-1] != {"accept": None}:
            raise AgentError("copy firewall rules changed")
    if rules["forward"]:
        raise AgentError("copy firewall must not forward traffic")


def owned(item, label):
    key, value = label.split("=", 1)
    labels = item.get("Labels") or item.get("Config", {}).get("Labels", {})
    if labels.get(key) != value:
        raise AgentError("resource ownership changed; operation refused")


def create_network(docker, name, label, *, internal, address_pools=None):
    """Reserve small bridges from Docker's pools without exhausting its /16 allocations."""
    identifiers = docker("network", "ls", "--quiet").split()
    networks = json.loads(docker("network", "inspect", *identifiers)) if identifiers else []
    occupied = [
        ipaddress.ip_network(config["Subnet"])
        for network in networks for config in network.get("IPAM", {}).get("Config") or []
        if config.get("Subnet") and ":" not in config["Subnet"]
    ]
    # Engine's built-in local pools when default-address-pools is not configured.
    bases = [pool["Base"] for pool in address_pools] if address_pools else [
        *(f"172.{ordinal}.0.0/16" for ordinal in range(17, 32)), "192.168.0.0/16",
    ]
    for base in bases:
        pool = ipaddress.ip_network(base)
        if pool.version != 4 or pool.prefixlen > 28:
            continue
        if any(pool.subnet_of(existing) for existing in occupied):
            continue
        for subnet in pool.subnets(new_prefix=28):
            if any(subnet.overlaps(existing) for existing in occupied):
                continue
            try:
                return docker(
                    "network", "create", "--driver", "bridge", "--subnet", str(subnet),
                    *(("--internal",) if internal else ()), "--label", label, name,
                )
            except AgentError as exc:
                # A concurrent preparation may have reserved this subnet after inspection.
                if "overlap" not in str(exc).lower():
                    raise
    raise UnsupportedTarget("Docker address pools have no free subnet for a secured copy")


def validate_process(item, prepared, resources, docker):
    owned(item, resources["label"])
    if (
        item["Image"] != prepared["image_id"]
        or item["Config"].get("Labels", {}).get("io.fannagent.copy_security") != str(VERSION)
        or not item["State"]["Running"] or item["Config"]["Entrypoint"] != [ENTRYPOINT]
    ):
        raise AgentError("secured copy image, entrypoint or running state changed")
    host = item["HostConfig"]

    def caps(values):
        return {v.removeprefix("CAP_") for v in values or []}

    if (
        host.get("Privileged") or caps(host.get("CapDrop")) != {"ALL"}
        or caps(host.get("CapAdd")) != set(CAPABILITIES)
        or not any(x in ("no-new-privileges", "no-new-privileges:true")
                   for x in host.get("SecurityOpt", []))
    ):
        raise AgentError("secured copy container privileges changed")
    status = dict(
        line.split(":", 1) for line in
        docker("exec", item["Id"], "cat", "/proc/1/status").splitlines() if ":" in line
    )
    uid = docker("exec", item["Id"], "id", "-u", "postgres")
    if (
        status["Uid"].split() != [uid] * 4 or status["NoNewPrivs"].strip() != "1"
        or any(int(status[name].strip(), 16) != 0
               for name in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"))
    ):
        raise AgentError("copy processes must run without root or Linux capabilities")


def validate_runtime(prepared, resources, docker):
    security = (prepared or {}).get("security", {})
    if security.get("version") != VERSION:
        raise AgentError(
            "unsecured or legacy prepared copy; clean this run and prepare a fresh secure run"
        )
    try:
        item = json.loads(docker("container", "inspect", prepared["container"]))[0]
        validate_process(item, prepared, resources, docker)
        host = item["HostConfig"]
        bindings = {"5432/tcp": [{"HostIp": "127.0.0.1", "HostPort": str(security["port"])}]}
        if host["PortBindings"] or any(item["NetworkSettings"]["Ports"].values()):
            raise AgentError("the private database must not publish ports")
        network = security["network"]
        memberships = item["NetworkSettings"]["Networks"]
        if (
            network != resources["network"] or set(memberships) != {network}
            or memberships[network]["NetworkID"] != security["network_id"]
            or memberships[network]["IPAddress"] != security["database_ip"]
            or host["NetworkMode"] not in (network, security["network_id"])
        ):
            raise AgentError("secured copy network membership changed")
        net = json.loads(docker("network", "inspect", security["network_id"]))[0]
        owned(net, resources["label"])
        if (
            net["Id"] != security["network_id"] or net["Name"] != network
            or net["Driver"] != "bridge" or not net["Internal"] or net["EnableIPv6"]
            or net.get("Options", {}).get("com.docker.network.bridge.gateway_mode_ipv4", "nat")
            != "nat"
            or net.get("Options", {}).get("com.docker.network.bridge.trusted_host_interfaces")
        ):
            raise AgentError("secured copy requires its private internal IPv4 bridge")
        volume = json.loads(docker("volume", "inspect", prepared["volume"]))[0]
        owned(volume, resources["label"])
        mounts = {m["Destination"]: m for m in item["Mounts"]}
        if (
            len(item["Mounts"]) != 2 or set(mounts) != {HBA_PATH, "/var/lib/postgresql/data"}
            or mounts[HBA_PATH]["RW"] or mounts[HBA_PATH]["Type"] != "bind"
            or mounts["/var/lib/postgresql/data"].get("Name") != resources["volume"]
        ):
            raise AgentError(
                "secured copy requires an owned volume and read-only authentication file"
            )
        command = item["Config"]["Cmd"]
        expected = ["postgres", *server_arguments(
            "listen_addresses=*", "unix_socket_directories=", "hba_file=" + HBA_PATH
        )]
        if command != expected:
            raise AgentError("secured copy server configuration changed")
        if docker("exec", prepared["container"], "sha256sum", HBA_PATH).split()[0] != security[
            "hba_sha256"
        ]:
            raise AgentError("secured copy authentication file changed")
        if (
            security["firewall_sha256"] != policy_hash()
            or docker("exec", prepared["container"], "sha256sum", POLICY_PATH).split()[0]
            != security["firewall_sha256"]
        ):
            raise AgentError("secured copy firewall policy changed")
        validate_firewall(
            docker("exec", prepared["container"], "nft", "--json", "list",
                   "table", "inet", "fannagent_copy")
        )
        relay = json.loads(docker("container", "inspect", security["proxy"]))[0]
        if security["proxy"] != resources["proxy"]:
            raise AgentError("secured relay ownership changed")
        validate_process(relay, prepared, resources, docker)
        if (
            relay["NetworkSettings"]["Ports"] != bindings
            or relay["HostConfig"]["PortBindings"] not in (
                bindings, {"5432/tcp": [{"HostIp": "127.0.0.1", "HostPort": ""}]}
            )
            or relay["Config"]["Cmd"] != ["--copy-proxy", security["database_ip"]]
            or relay["Mounts"]
            or relay["HostConfig"].get("Tmpfs") != {"/var/lib/postgresql/data": "size=64k"}
        ):
            raise AgentError("secured relay ports, destination or mounts changed")
        ingress = security["ingress_network"]
        if ingress != resources["ingress_network"]:
            raise AgentError("secured relay ingress ownership changed")
        memberships = relay["NetworkSettings"]["Networks"]
        if (
            set(memberships) != {network, ingress}
            or memberships[network]["NetworkID"] != security["network_id"]
            or memberships[ingress]["NetworkID"] != security["ingress_network_id"]
        ):
            raise AgentError("secured relay network membership changed")
        net = json.loads(docker("network", "inspect", security["ingress_network_id"]))[0]
        owned(net, resources["label"])
        if (net["Name"] != ingress or net["Driver"] != "bridge" or net["Internal"]
                or net["EnableIPv6"]
                or net.get("Options", {}).get("com.docker.network.bridge.gateway_mode_ipv4", "nat")
                != "nat"
                or net.get("Options", {}).get("com.docker.network.bridge.trusted_host_interfaces")):
            raise AgentError("secured relay ingress network changed")
        if (
            security["proxy_firewall_sha256"] != policy_hash(proxy=True)
            or docker("exec", security["proxy"], "sha256sum",
                      "/usr/local/share/fannagent/proxy.nft").split()[0]
            != security["proxy_firewall_sha256"]
        ):
            raise AgentError("secured relay firewall policy changed")
        validate_firewall(
            docker("exec", security["proxy"], "nft", "--json", "list",
                   "table", "inet", "fannagent_proxy"), database_ip=security["database_ip"]
        )
    except (KeyError, ValueError, TypeError, IndexError) as exc:
        raise AgentError("secured copy configuration is missing or malformed") from exc
