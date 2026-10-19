from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
import threading
import time
import uuid
from contextlib import nullcontext
from dataclasses import asdict
from pathlib import Path

import psycopg
from fannagent.api import (
    AgentError,
    Capabilities,
    ExactTruth,
    ProbeResult,
    Snapshot,
    UnsupportedTarget,
    digest,
    validate_policy,
)
from fannagent.api.primitives.audit import reconstruct_membership
from fannagent.api.primitives.compiler import compile_tree, predicate_leaf_count
from fannagent.api.primitives.data import Query
from psycopg import pq, sql
from psycopg.rows import dict_row

from . import security
from .docker import docker
from .native.context import ExecutionContext
from .native.features import ENGINE_CAPABILITIES, FEATURE_REGISTRY_HASH
from .native.filters import postgres_filter
from .native.sequential import begin_execution_batch, complete_execution_batch
from .native.transport import feature_set_hash, normalize_engine_trace
from .prepared import PreparedPolicy, PreparedPolicyCache
from .profiles import DATA_PROFILE, PROFILE


def compile_policy(policy):
    return compile_tree(policy, header="FANNBENCH_POLICY_V2\t64")


SETTINGS = (
    "hnsw.ef_search",
    "hnsw.iterative_scan",
    "hnsw.max_scan_tuples",
    "hnsw.scan_mem_multiplier",
    "work_mem",
    "enable_seqscan",
    "enable_indexscan",
    "enable_bitmapscan",
    "enable_indexonlyscan",
    "random_page_cost",
    "seq_page_cost",
    "effective_cache_size",
    "max_parallel_workers_per_gather",
    "jit",
)
SCALARS = {
    "int2": "integer",
    "int4": "integer",
    "int8": "integer",
    "float4": "float",
    "float8": "float",
    "text": "string",
    "varchar": "string",
    "bool": "boolean",
}
FUNCTIONS = """
CREATE SCHEMA IF NOT EXISTS fannagent;
CREATE OR REPLACE FUNCTION fannagent.bind_target(regclass,text,text,regclass) RETURNS oid
 AS '$libdir/vector','fannagent_bind_target' LANGUAGE C STRICT VOLATILE PARALLEL UNSAFE;
CREATE OR REPLACE FUNCTION fannagent.install_policy(text,text) RETURNS text
 AS '$libdir/vector','fannbench_install_policy' LANGUAGE C STRICT VOLATILE PARALLEL UNSAFE;
CREATE OR REPLACE FUNCTION fannagent.begin_execution(
 text,text,bigint,text,integer,integer,text,bigint,text,text,text,boolean)
 RETURNS text AS '$libdir/vector','fannbench_begin_execution' LANGUAGE C VOLATILE PARALLEL UNSAFE;
CREATE OR REPLACE FUNCTION fannagent.complete(text,integer) RETURNS text
 AS '$libdir/vector','fannbench_last_execution' LANGUAGE C STRICT VOLATILE PARALLEL UNSAFE;
CREATE OR REPLACE FUNCTION fannagent.take_trace(text) RETURNS text
 AS '$libdir/vector','fannagent_take_trace' LANGUAGE C STRICT VOLATILE PARALLEL UNSAFE;
GRANT USAGE ON SCHEMA fannagent TO PUBLIC;
"""


def uses_index(plan):
    if isinstance(plan, dict):
        node = plan.get("Node Type", "").lower()
        return "index" in node or "bitmap" in node or any(uses_index(v) for v in plan.values())
    if isinstance(plan, list):
        return any(uses_index(v) for v in plan)
    return False


class NativeBackend:
    def __init__(self, config, store):
        self.config, self.store = config, store
        self.conn = None
        self._snapshot = None
        self._installed = None
        self._inspection = None
        self._operation_lock = threading.RLock()
        self._policies = PreparedPolicyCache(PROFILE)
        self._binding = None
        self._binding_conn = None
        self._compatibility_error = False
        self._checking_compatibility = False

    @property
    def target(self):
        return self.config.target

    @property
    def relation(self):
        return sql.Identifier(self.target.schema_name, self.target.resource)

    def _source(self):
        value = os.environ.get(self.target.connection_env)
        if not value:
            raise AgentError(f"set credential reference {self.target.connection_env}")
        return psycopg.connect(value, autocommit=True, connect_timeout=10)

    def inspect_target(self):
        if self._inspection:
            return self._inspection
        if self.store.get("prepared"):
            self._inspection = self.store.get("source_manifest")
            return self._inspection
        with self._source() as conn:
            cursor = conn.cursor(row_factory=dict_row)
            cursor.execute(
                "SELECT version() AS version, current_setting('server_version') AS server_version, "
                "(SELECT extversion FROM pg_extension WHERE extname='vector') AS vector_version, "
                "current_database() AS database, current_user AS role"
            )
            versions = cursor.fetchone()
            try:
                cursor.execute("SELECT system_identifier::text FROM pg_control_system()")
                versions["system_identifier"] = cursor.fetchone()["system_identifier"]
            except psycopg.errors.InsufficientPrivilege:
                versions["system_identifier"] = None
            if versions["vector_version"] is not None:
                # Load extension GUC definitions without running an ANN query.
                cursor.execute("SELECT vector_dims('[1]'::vector)")
            cursor.execute(
                "SELECT c.oid,c.relkind,c.relrowsecurity,c.reltuples,c.relfilenode,"
                "pg_relation_size(c.oid) AS bytes FROM pg_class c "
                "JOIN pg_namespace n ON n.oid=c.relnamespace "
                "WHERE n.nspname=%s AND c.relname=%s",
                (self.target.schema_name, self.target.resource),
            )
            relation = cursor.fetchone()
            if not relation:
                raise UnsupportedTarget("selected relation does not exist")
            cursor.execute(
                "SELECT a.attname,t.typname,a.atttypmod,a.attnotnull,"
                "co.collisdeterministic FROM pg_attribute a "
                "JOIN pg_type t ON t.oid=a.atttypid "
                "LEFT JOIN pg_collation co ON co.oid=a.attcollation "
                "WHERE a.attrelid=%s AND a.attnum>0 "
                "AND NOT a.attisdropped ORDER BY a.attnum",
                (relation["oid"],),
            )
            columns = cursor.fetchall()
            cursor.execute(
                "SELECT c.oid,c.relname,c.relfilenode,pg_relation_filepath(c.oid) AS filepath,"
                "pg_relation_size(c.oid) AS bytes,pg_get_indexdef(c.oid) AS definition,"
                "i.indisvalid,i.indisready,i.indnkeyatts,i.indisunique,"
                "i.indpred IS NOT NULL AS partial,"
                "i.indexprs IS NOT NULL AS expression,am.amname,"
                "a.attname AS column_name,op.opcname FROM pg_index i "
                "JOIN pg_class c ON c.oid=i.indexrelid "
                "JOIN pg_am am ON am.oid=c.relam LEFT JOIN pg_attribute a ON a.attrelid=i.indrelid "
                "AND a.attnum=i.indkey[0] LEFT JOIN pg_opclass op ON op.oid=i.indclass[0] "
                "WHERE i.indrelid=%s",
                (relation["oid"],),
            )
            indexes = cursor.fetchall()
            cursor.execute(
                "SELECT name,setting,unit FROM pg_settings WHERE name=ANY(%s)", (list(SETTINGS),)
            )
            settings = {r["name"]: r["setting"] for r in cursor.fetchall()}
            cursor.execute("SELECT extname,extversion FROM pg_extension ORDER BY extname")
            extensions = cursor.fetchall()
            cursor.execute(
                "SELECT COALESCE(SUM(pg_database_size(oid)),0)::bigint AS bytes FROM pg_database"
            )
            cluster_bytes = cursor.fetchone()["bytes"]
            cursor.execute(
                "SELECT spcname FROM pg_tablespace WHERE spcname NOT IN ('pg_default','pg_global')"
            )
            tablespaces = cursor.fetchall()
        issues = []
        if versions["system_identifier"] is None:
            issues.append("inspection needs EXECUTE on pg_control_system() to verify backup origin")
        if (
            versions["server_version"].split()[0] != "17.11"
            or versions["vector_version"] != "0.8.6"
        ):
            issues.append("requires PostgreSQL 17.11 and pgvector 0.8.6")
        if relation["relkind"] != "r" or relation["relrowsecurity"]:
            issues.append("partitioning and row-level security are unsupported")
        if tablespaces:
            issues.append("external tablespace mapping is not supported in this release")
        if any(e["extname"] not in {"vector", "plpgsql"} for e in extensions):
            issues.append("cluster has unqualified extension dependencies")
        fields = {c["attname"]: c for c in columns}
        identifier, vector = (
            fields.get(self.target.id_column),
            fields.get(self.target.vector_column),
        )
        if not identifier or identifier["typname"] != "int8" or not identifier["attnotnull"]:
            issues.append("identifier must be a NOT NULL bigint")
        if not any(
            i["indisunique"]
            and i["indnkeyatts"] == 1
            and not i["partial"]
            and i["column_name"] == self.target.id_column
            for i in indexes
        ):
            issues.append("identifier needs a single-column unique index")
        if not vector or vector["typname"] != "vector" or not 1 <= vector["atttypmod"] <= 2000:
            issues.append("vector column must be vector(d), 1<=d<=2000")
        selected = [
            i
            for i in indexes
            if i["amname"] == "hnsw"
            and i["column_name"] == self.target.vector_column
            and (not self.target.index or i["relname"] == self.target.index)
        ]
        if len(selected) != 1:
            issues.append("select exactly one HNSW index")
        elif not (
            selected[0]["indisvalid"]
            and selected[0]["indisready"]
            and not selected[0]["partial"]
            and not selected[0]["expression"]
            and selected[0]["opcname"] == "vector_cosine_ops"
        ):
            issues.append(
                "requires a valid nonpartial cosine HNSW index on the selected vector column"
            )
        metadata = (
            self.target.metadata_columns
            if self.target.metadata_columns is not None
            else [
                n
                for n, c in fields.items()
                if n not in {self.target.id_column, self.target.vector_column}
                and c["typname"] in SCALARS
            ]
        )
        for name in metadata:
            if name not in fields or fields[name]["typname"] not in SCALARS:
                issues.append(f"unsupported scalar metadata field: {name}")
            elif (
                SCALARS[fields[name]["typname"]] == "string"
                and not fields[name]["collisdeterministic"]
            ):
                issues.append(f"nondeterministic string collation is unsupported: {name}")
        architecture = (
            "arm64"
            if "aarch64" in versions["version"]
            else "amd64"
            if "x86_64" in versions["version"]
            else None
        )
        if not architecture:
            issues.append("source architecture could not be established")
        result = {
            "backend": "pgvector",
            "compatible": not issues,
            "issues": issues,
            "versions": versions,
            "architecture": architecture,
            "relation": relation,
            "columns": columns,
            "index": selected[0] if len(selected) == 1 else None,
            "settings": settings,
            "extensions": extensions,
            "cluster_bytes_estimate": cluster_bytes,
            "metadata": [
                {
                    "name": n,
                    "type": SCALARS[fields[n]["typname"]],
                    "nullable": not fields[n]["attnotnull"],
                    "allowed_ops": (
                        ["eq", "in", "is_null", "is_not_null"]
                        if SCALARS[fields[n]["typname"]] == "string"
                        else ["eq", "in", "lt", "lte", "gt", "gte", "is_null", "is_not_null"]
                    ),
                }
                for n in metadata
                if n in fields and fields[n]["typname"] in SCALARS
            ],
            "prerequisites": [
                "full verified physical backup or replication role with streamed WAL",
                "matching architecture and instrumented image",
                "Docker storage for the entire cluster",
            ],
            "guidance": (
                "Initial graph search has no executor feedback. Default ef_search and "
                "iterative_scan are preserved; non-HNSW routes have no stopping opportunity."
            ),
        }
        self._inspection = result
        return result

    def describe_capabilities(self):
        return Capabilities(
            "pgvector",
            True,
            True,
            ("physical_backup", "pg_basebackup"),
            tuple(ENGINE_CAPABILITIES["pgvector"]["checkpoint_fields"]),
            ("postgresql_pgvector_hnsw", "postgresql_non_hnsw"),
            (
                "snapshot only",
                "single selected relation and index",
                "copy qualification required",
                "reconstructed membership is offline only",
            ),
            exact=True,
            snapshot=True,
            serving=True,
        )

    def validate_policy(self, raw):
        return validate_policy(raw, PROFILE)

    def _prepare_policy(self, raw):
        with self._operation_lock:
            return raw if isinstance(raw, PreparedPolicy) else self._policies.prepare(raw)

    def compatibility(self):
        with self._operation_lock:
            self._binding = self._binding_conn = None
            self._checking_compatibility = True
            try:
                result = self._compatibility()
                self._compatibility_error = False
                return result
            except BaseException:
                self._compatibility_error = True
                self._snapshot = None
                self.close()
                raise
            finally:
                self._checking_compatibility = False

    def _compatibility(self):
        prepared, source = self.store.get("prepared"), self.store.get("source_manifest")
        if not prepared or self.store.get("cleaned"):
            raise AgentError("a live prepared copy is required")
        self._check_security()
        conn = self._connect()
        self._bind(conn, source)
        # Checkpoint outside measured searches so index hashes include dirty buffers.
        # WAL itself can advance during ordinary background checkpoints on an unchanged copy.
        with psycopg.connect(self._connection_dsn(admin=True), autocommit=True) as admin:
            admin.execute("CHECKPOINT")
        index = conn.execute(
            "SELECT pg_relation_filepath(%s::oid),pg_relation_size(%s::oid)",
            (source["index"]["oid"], source["index"]["oid"]),
        ).fetchone()
        if index != (source["index"]["filepath"], prepared["index_bytes"]):
            raise AgentError("prepared physical index changed; use a new run")
        for path, expected in prepared["physical_index_files"].items():
            actual = docker(
                "exec",
                "--user",
                "postgres",
                prepared["container"],
                "sha256sum",
                "/var/lib/postgresql/data/" + path,
            ).split()[0]
            if actual != expected:
                raise AgentError("prepared physical index changed; use a new run")
        self._snapshot = None
        if self.snapshot().identity != prepared["dataset_identity"]:
            raise AgentError("the observation snapshot changed after preparation; use a new run")
        return {
            "backend": "pgvector",
            "index_identity": prepared["index_identity"],
            "architecture": prepared["architecture"],
            "image_id": prepared["image_id"],
            "settings": source["settings"],
            "dataset_hash": self.snapshot().identity,
            "copy_security_version": security.VERSION,
            "binding": {
                "schema": self.target.schema_name,
                "relation": self.target.resource,
                "identifier": self.target.id_column,
                "vector": self.target.vector_column,
                "metadata": source["metadata"],
                "index_oid": source["index"]["oid"],
            },
        }

    def prepare_copy(self):
        self.close()
        self._snapshot = self._inspection = None
        try:
            return self._prepare_copy()
        except BaseException:
            # An unsuccessful restore/qualification must not leave a live listener.
            if self.store.get("secure_preparation_started"):
                self.close()
                self._stop_owned_containers()
            raise

    def _stop_owned_containers(self):
        resources = self.store.get("owned_resources", {})
        failed = []
        for name in (
            resources.get("proxy"),
            resources.get("container"),
            resources.get("bootstrap"),
            resources.get("backup_helper"),
            resources.get("utility_helper"),
        ):
            if not name:
                continue
            try:
                item = json.loads(docker("container", "inspect", name))[0]
                security.owned(item, resources["label"])
                if item["State"]["Running"]:
                    docker("container", "stop", "--time", "10", name)
            except AgentError as exc:
                if "no such" not in str(exc).lower():
                    failed.append(name)
        if failed:
            raise AgentError(
                "secure preparation failed and owned containers could not be stopped: "
                + ", ".join(failed)
                + "; run cleanup"
            ) from None

    def _check_security(self, prepared=None):
        def audited_docker(*args, **kwargs):
            return docker(*args, **kwargs, timeout_seconds=30)

        security.validate_runtime(
            prepared or self.store.get("prepared"),
            self.store.get("owned_resources"),
            audited_docker,
        )

    def _prepare_copy(self):
        if self.store.get("cleaned"):
            raise AgentError("this run's resources were removed; prepare a new run")
        if self.store.get("prepared"):
            self._check_security()
            self._connect()
            if not self.store.get("prepared")["qualified"]:
                self._qualify()
            return self.store.get("prepared")
        if self.store.get("secure_preparation_started"):
            raise AgentError("interrupted preparation; clean this run and prepare a new run")
        source = self.inspect_target()
        if not source["compatible"]:
            raise UnsupportedTarget("; ".join(source["issues"]))
        image = json.loads(docker("image", "inspect", self.config.copy.image))[0]
        arch = image["Architecture"]
        if arch != source["architecture"] or (
            self.config.copy.architecture and arch != self.config.copy.architecture
        ):
            raise UnsupportedTarget(
                "physical backup architecture does not match instrumented image"
            )
        if image.get("Config", {}).get("Labels", {}).get("io.fannagent.binding") != "1":
            raise UnsupportedTarget("image lacks target binding protocol")
        if image.get("Config", {}).get("Labels", {}).get("io.fannagent.copy_security") != "1":
            raise UnsupportedTarget("image lacks mandatory copy security; build the secure image")
        if image.get("Config", {}).get("Labels", {}).get("io.fannagent.copy_proxy") != "1":
            raise UnsupportedTarget("image lacks the secure internal-network relay")
        version = docker("version", "--format", "{{.Server.Version}}")
        if int(version.split(".", 1)[0]) < 28:
            raise UnsupportedTarget("copy security requires Docker Engine 28 or newer")
        security.hba_name(source["versions"]["database"])
        security.hba_name(source["versions"]["role"])
        private = self.store.root / "private"
        private.mkdir(parents=True, exist_ok=True)
        staging = self.config.copy.backup or private / "backup"
        estimate = source["cluster_bytes_estimate"]
        required = (
            estimate * (1 if self.config.copy.backup else 2) + self.config.copy.max_evidence_bytes
        )
        disk = shutil.disk_usage(private).free
        info = json.loads(docker("info", "--format", "{{json .}}"))
        if (
            disk < required
            or info["MemTotal"] < self.config.copy.memory_gib * 1024**3 + 64 * 1024**2
        ):
            raise UnsupportedTarget(
                "insufficient configured memory or estimated staging/evidence storage"
            )
        run_id = digest(str(self.store.root))[:16]
        label = "io.fannagent.run=" + run_id
        container, volume = "fannagent-pg-" + run_id, "fannagent-data-" + run_id
        network, bootstrap = "fannagent-net-" + run_id, "fannagent-bootstrap-" + run_id
        proxy, ingress_network = "fannagent-proxy-" + run_id, "fannagent-ingress-" + run_id
        backup_helper, utility_helper = "fannagent-backup-" + run_id, "fannagent-utility-" + run_id
        self.store.set(
            "owned_resources",
            {
                "container": container,
                "bootstrap": bootstrap,
                "volume": volume,
                "network": network,
                "label": label,
                "proxy": proxy,
                "ingress_network": ingress_network,
                "backup_helper": backup_helper,
                "utility_helper": utility_helper,
            },
        )
        self.store.set("secure_preparation_started", True)
        # Also check the Docker filesystem, which can have a smaller disk than the host.
        free = (
            int(
                docker(
                    "run",
                    "--rm",
                    "--name",
                    utility_helper,
                    "--label",
                    label,
                    "--network",
                    "none",
                    "--tmpfs",
                    "/var/lib/postgresql/data:size=64k",
                    "--entrypoint",
                    "sh",
                    self.config.copy.image,
                    "-c",
                    "df -Pk /var/lib/postgresql | awk 'NR==2 {print $4}'",
                )
            )
            * 1024
        )
        if free < required:
            raise UnsupportedTarget("insufficient Docker filesystem space")
        self.store.set("source_manifest", source)
        if not self.config.copy.backup:
            if staging.exists():
                raise AgentError(
                    "interrupted backup exists; inspect or remove owned staging before retry"
                )
            staging.mkdir(mode=0o700)
            replication = os.environ.get(self.config.copy.replication_env or "")
            if not replication:
                raise AgentError("a full backup or replication credential reference is required")
            # Credentials use an ephemeral environment variable, never a model-visible argv/config.
            previous = os.environ.get("FANNAGENT_BACKUP_DSN")
            os.environ["FANNAGENT_BACKUP_DSN"] = replication
            try:
                docker(
                    "run",
                    "--rm",
                    "--name",
                    backup_helper,
                    "--tmpfs",
                    "/var/lib/postgresql/data:size=64k",
                    "--label",
                    label,
                    "--user",
                    f"{os.getuid()}:{os.getgid()}",
                    "--entrypoint",
                    "sh",
                    "-e",
                    "FANNAGENT_BACKUP_DSN",
                    "-v",
                    f"{staging}:/backup",
                    self.config.copy.image,
                    "-c",
                    'exec pg_basebackup --dbname="$FANNAGENT_BACKUP_DSN" -D /backup '
                    "-X stream --checkpoint=fast --manifest-checksums=SHA256",
                )
            finally:
                if previous is None:
                    os.environ.pop("FANNAGENT_BACKUP_DSN", None)
                else:
                    os.environ["FANNAGENT_BACKUP_DSN"] = previous
        if (
            not (staging / "backup_manifest").is_file()
            or not (staging / "PG_VERSION").is_file()
            or (staging / "PG_VERSION").read_text().strip() != "17"
        ):
            raise UnsupportedTarget("full PostgreSQL 17 backup with manifest required")
        backup_manifest = json.loads((staging / "backup_manifest").read_text())
        if str(backup_manifest.get("System-Identifier")) != source["versions"]["system_identifier"]:
            raise UnsupportedTarget("backup system identifier does not match the inspected source")
        if (staging / "standby.signal").exists() or (staging / "recovery.signal").exists():
            raise UnsupportedTarget("standby or custom recovery backup is not supported")
        docker(
            "run",
            "--rm",
            "--name",
            utility_helper,
            "--label",
            label,
            "--network",
            "none",
            "--tmpfs",
            "/var/lib/postgresql/data:size=64k",
            "--entrypoint",
            "pg_verifybackup",
            "-v",
            f"{staging}:/backup:ro",
            self.config.copy.image,
            "/backup",
        )
        control = docker(
            "run",
            "--rm",
            "--name",
            utility_helper,
            "--label",
            label,
            "--network",
            "none",
            "--tmpfs",
            "/var/lib/postgresql/data:size=64k",
            "--entrypoint",
            "pg_controldata",
            "-v",
            f"{staging}:/backup:ro",
            self.config.copy.image,
            "/backup",
        )
        manifest_hash = hashlib.sha256((staging / "backup_manifest").read_bytes()).hexdigest()
        backup_bytes = sum(p.stat().st_size for p in staging.rglob("*") if p.is_file())
        dimension = next(
            c["atttypmod"] for c in source["columns"] if c["attname"] == self.target.vector_column
        )
        rows_estimate = max(0, source["relation"]["reltuples"])
        sidecar_estimate = int(rows_estimate * (dimension * 4 + 8 + 128 * len(source["metadata"])))
        required = backup_bytes + sidecar_estimate + self.config.copy.max_evidence_bytes
        if (
            free < required
            or shutil.disk_usage(private).free
            < sidecar_estimate + self.config.copy.max_evidence_bytes
        ):
            raise UnsupportedTarget(
                "insufficient storage for verified backup, sidecar and evidence"
            )
        index_path = source["index"]["filepath"]
        index_files = sorted(staging.glob(index_path + "*"))
        if not index_files:
            raise UnsupportedTarget("backup does not contain selected physical index identity")
        hashes = {
            str(p.relative_to(staging)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in index_files
        }
        with self._source() as source_connection:
            auth = security.new_auth(
                source_connection, source["versions"]["database"], source["versions"]["role"]
            )
        # One atomic secret write precedes every catalog mutation.
        self.store.secret("copy_auth", json.dumps(auth))
        authentication = private / "pg_hba.conf"
        contents = security.hba(auth["database"], auth["query_role"], auth["admin_role"])
        authentication.write_text(contents)
        # The parent is private; the unprivileged container must be able to read this bind mount.
        authentication.chmod(0o444)
        docker("volume", "create", "--label", label, volume)
        security.owned(json.loads(docker("volume", "inspect", volume))[0], label)
        docker(
            "run",
            "--rm",
            "--name",
            utility_helper,
            "--label",
            label,
            "--network",
            "none",
            "--tmpfs",
            "/var/lib/postgresql/data:size=64k",
            "--entrypoint",
            "sh",
            "-v",
            f"{staging}:/backup:ro",
            "-v",
            f"{volume}:/copy",
            self.config.copy.image,
            "-c",
            'test -z "$(ls -A /copy)" && cp -a /backup/. /copy/ && '
            'printf "local all all reject\\nhost all all 0.0.0.0/0 reject\\n'
            'host all all ::/0 reject\\n" > /copy/pg_hba.conf && '
            "chown -R postgres:postgres /copy && chmod 700 /copy",
        )
        docker(
            "run",
            "--rm",
            "--name",
            bootstrap,
            "--label",
            label,
            "--network",
            "none",
            "--log-driver",
            "none",
            "--user",
            "postgres",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--entrypoint",
            "postgres",
            "-i",
            "-v",
            f"{volume}:/var/lib/postgresql/data",
            self.config.copy.image,
            "--single",
            "-j",
            "-D",
            "/var/lib/postgresql/data",
            *security.server_arguments(
                "listen_addresses=", "unix_socket_directories=", "client_encoding=UTF8"
            ),
            auth["database"],
            input_text=security.bootstrap_sql(auth),
            sensitive=True,
            postgres_errors=True,
        )
        network_id = security.create_network(
            docker, network, label, internal=True, address_pools=info.get("DefaultAddressPools")
        )
        security.owned(json.loads(docker("network", "inspect", network_id))[0], label)
        docker(
            "run",
            "-d",
            "--name",
            container,
            "--label",
            label,
            "--network",
            network,
            "--cap-drop",
            "ALL",
            *(arg for capability in security.CAPABILITIES for arg in ("--cap-add", capability)),
            "--security-opt",
            "no-new-privileges",
            "--cpus",
            self.config.copy.cpus,
            "--memory",
            f"{self.config.copy.memory_gib}g",
            "-v",
            f"{volume}:/var/lib/postgresql/data",
            "--mount",
            f"type=bind,source={authentication},target={security.HBA_PATH},readonly",
            self.config.copy.image,
            "postgres",
            *security.server_arguments(
                "listen_addresses=*", "unix_socket_directories=", "hba_file=" + security.HBA_PATH
            ),
        )
        item = json.loads(docker("inspect", container))[0]
        address = item["NetworkSettings"]["Networks"][network]["IPAddress"]
        ingress_id = security.create_network(
            docker,
            ingress_network,
            label,
            internal=False,
            address_pools=info.get("DefaultAddressPools"),
        )
        security.owned(json.loads(docker("network", "inspect", ingress_id))[0], label)
        docker(
            "run",
            "-d",
            "--name",
            proxy,
            "--label",
            label,
            "--network",
            ingress_network,
            "--network",
            network,
            "--cap-drop",
            "ALL",
            *(arg for capability in security.CAPABILITIES for arg in ("--cap-add", capability)),
            "--security-opt",
            "no-new-privileges",
            "--cpus",
            "0.25",
            "--memory",
            "64m",
            # Suppress the image's automatic anonymous PGDATA volume. No backup/data/secret mounts.
            "--tmpfs",
            "/var/lib/postgresql/data:size=64k",
            "-p",
            "127.0.0.1::5432",
            self.config.copy.image,
            "--copy-proxy",
            address,
        )
        port = json.loads(docker("inspect", proxy))[0]["NetworkSettings"]["Ports"]["5432/tcp"][0][
            "HostPort"
        ]
        dsn, admin = security.copy_dsn(auth, port), security.copy_dsn(auth, port, admin=True)
        secured = {
            "container": container,
            "volume": volume,
            "image_id": image["Id"],
            "security": {
                "version": security.VERSION,
                "network": network,
                "network_id": network_id,
                "port": port,
                "hba_sha256": hashlib.sha256(contents.encode()).hexdigest(),
                "firewall_sha256": security.policy_hash(),
                "database_ip": address,
                "proxy": proxy,
                "ingress_network": ingress_network,
                "ingress_network_id": ingress_id,
                "proxy_firewall_sha256": security.policy_hash(proxy=True),
            },
        }
        deadline = time.monotonic() + 90
        runtime_admin = security.controller_dsn(
            admin, secured, self.store.get("owned_resources"), docker
        )
        while True:
            try:
                with psycopg.connect(runtime_admin, autocommit=True, connect_timeout=2) as conn:
                    if conn.execute("SELECT pg_is_in_recovery()").fetchone()[0]:
                        raise psycopg.OperationalError("recovery incomplete")
                    self._check_security(secured)
                    if conn.execute(
                        "SELECT count(*) FROM pg_hba_file_rules WHERE error IS NOT NULL"
                    ).fetchone()[0]:
                        raise AgentError("secured copy authentication rules are invalid")
                    if conn.execute("SHOW hba_file").fetchone()[0] != security.HBA_PATH:
                        raise AgentError("secured copy authentication file was overridden")
                    conn.execute(FUNCTIONS)
                break
            except psycopg.OperationalError:
                for name in (container, proxy):
                    if not json.loads(docker("container", "inspect", name))[0]["State"]["Running"]:
                        raise AgentError("secured copy or relay exited during startup") from None
                if time.monotonic() > deadline:
                    raise AgentError("copy did not complete recovery") from None
                time.sleep(0.25)
        actual_hashes = {}
        for path in hashes:
            actual_hashes[path] = docker(
                "exec",
                "--user",
                "postgres",
                container,
                "sha256sum",
                "/var/lib/postgresql/data/" + path,
            ).split()[0]
        if hashes != actual_hashes:
            raise UnsupportedTarget("restored HNSW index bytes changed; no rebuilding is allowed")
        prepared = {
            "backend": "pgvector",
            "kind": "physical_backup",
            "qualified": False,
            "index_identity": digest(hashes),
            "physical_index_files": hashes,
            "backup_manifest_hash": manifest_hash,
            "control": control,
            "architecture": arch,
            "image_id": image["Id"],
            "settings": source["settings"],
            **secured,
            "snapshot": True,
            "resource_estimate": {
                "cluster_bytes": estimate,
                "additional_disk_bytes": required,
                "backup_bytes": backup_bytes,
                "sidecar_bytes_estimate": sidecar_estimate,
                "image_bytes": image.get("Size"),
                "host_analysis_bytes_estimate": sidecar_estimate * 8,
                "cpus": self.config.copy.cpus,
                "memory_gib": self.config.copy.memory_gib,
                "relay_cpus": 0.25,
                "relay_memory_bytes": 64 * 1024**2,
            },
        }
        self.store.secret("copy_dsn", dsn)
        self.store.secret("copy_admin_dsn", admin)
        self.store.set("prepared", prepared)
        self._connect()
        sidecar = private / "sidecar.parquet"
        self.snapshot().save(sidecar)
        with sidecar.open("rb") as handle:
            identity = hashlib.file_digest(handle, "sha256").hexdigest()
        addressed = private / "artifacts" / f"{identity}.parquet"
        addressed.parent.mkdir(mode=0o700, exist_ok=True)
        sidecar.replace(addressed)
        self.store.set(
            "sidecar",
            self.store.put(
                "sidecar_manifest",
                {
                    "hash": identity,
                    "path": str(addressed.relative_to(self.store.root)),
                    "bytes": addressed.stat().st_size,
                    "dataset_identity": self.snapshot().identity,
                    "vector_representation": "float32",
                },
            ),
        )
        self._qualify()
        return self.store.get("prepared")

    def _connection_dsn(self, *, admin=False):
        dsn = self.store.secret("copy_admin_dsn" if admin else "copy_dsn")
        if not dsn:
            raise AgentError("prepare the instrumented copy first")
        return security.controller_dsn(
            dsn, self.store.get("prepared"), self.store.get("owned_resources"), docker
        )

    def _connect(self):
        if self._compatibility_error and not self._checking_compatibility:
            raise AgentError(
                "prepared copy failed compatibility; successfully recheck before reuse"
            )
        if self.conn is None or self.conn.closed:
            self.close()
            try:
                prepared = self.store.get("prepared")
                if self.store.get("cleaned"):
                    raise AgentError("this run's resources were removed")
                self._check_security(prepared)
                dsn = self._connection_dsn()
                self.conn = psycopg.connect(dsn, autocommit=True, connect_timeout=10)
                self._bind(self.conn, self.store.get("source_manifest"))
            except BaseException:
                self.close()
                raise
        return self.conn

    def _bind(self, conn, source):
        self._binding = self._binding_conn = None
        ack = conn.execute(
            "SELECT fannagent.bind_target(%s::regclass,%s,%s,%s::regclass)",
            (
                self.relation.as_string(conn),
                self.target.id_column,
                self.target.vector_column,
                sql.Identifier(self.target.schema_name, source["index"]["relname"]).as_string(conn),
            ),
        ).fetchone()[0]
        if ack != source["index"]["oid"]:
            raise AgentError("target binding acknowledgement mismatch")
        self._settings(conn, local=False, source=source)
        self._binding = json.loads(json.dumps(source))
        self._binding_conn = conn

    def snapshot(self):
        if self._snapshot is None:
            conn = self._connect()
            fields = self.store.get("source_manifest")["metadata"]
            identifiers = [self.target.id_column, self.target.vector_column] + [
                f["name"] for f in fields
            ]
            statement = sql.SQL("SELECT {} FROM {} ORDER BY {}").format(
                sql.SQL(",").join(sql.Identifier(n) for n in identifiers),
                self.relation,
                sql.Identifier(self.target.id_column),
            )
            with conn.cursor() as cursor:
                cursor.execute(statement)
                rows = [
                    {
                        "source_id": r[0],
                        "vector": json.loads(r[1]),
                        "metadata": dict(zip([f["name"] for f in fields], r[2:])),
                    }
                    for r in cursor
                ]
            self._snapshot = Snapshot(rows, fields, DATA_PROFILE)
        return self._snapshot

    def _statement(self, query, *, exact=False):
        predicate, params = postgres_filter(query.get("filter"), self.snapshot().field_map)
        vector = "[" + ",".join(format(float(v), ".9g") for v in query["vector"]) + "]"
        # No id tie-breaker and no volatile wrapper: these change index selection.
        statement = sql.SQL(
            "SELECT {}, {} <=> %s::vector AS distance FROM {} WHERE {} ORDER BY {} <=> %s::vector{}"
        ).format(
            sql.Identifier(self.target.id_column),
            sql.Identifier(self.target.vector_column),
            self.relation,
            predicate,
            sql.Identifier(self.target.vector_column),
            sql.SQL("") if exact else sql.SQL(" LIMIT %s"),
        )
        return statement, [vector, *params, vector, *([] if exact else [query["k"]])]

    def _settings(self, conn, *, local=True, source=None):
        for name, value in (source or self.store.get("source_manifest"))["settings"].items():
            conn.execute("SELECT set_config(%s,%s,%s)", (name, value, local))
        conn.execute(
            "SELECT set_config('statement_timeout',%s,%s)",
            (str(int(self.config.query_timeout_seconds * 1000)), local),
        )

    def exact_reference(self, query):
        with self._operation_lock:
            return self._exact_reference(query)

    def _exact_reference(self, query):
        conn = self._connect()
        statement, params = self._statement(query, exact=True)
        with conn.transaction():
            self._settings(conn)
            for name in ("enable_indexscan", "enable_indexonlyscan", "enable_bitmapscan"):
                conn.execute("SELECT set_config(%s,'off',true)", (name,))
            plan = conn.execute(sql.SQL("EXPLAIN (FORMAT JSON) ") + statement, params).fetchone()[0]
            if uses_index(plan):
                raise AgentError("authoritative reference did not bypass index scans")
            rows = conn.execute(statement, params).fetchall()
        ids = [self.snapshot().source_to_id[str(r[0])] for r in rows]
        k = min(query["k"], len(rows))
        boundary = float(rows[k - 1][1]) if k else None
        strict = frozenset(
            i for i, r in zip(ids, rows) if boundary is not None and float(r[1]) < boundary
        )
        ties = frozenset(
            i for i, r in zip(ids, rows) if boundary is not None and float(r[1]) == boundary
        )
        return ExactTruth(len(ids), k, strict, ties, frozenset(ids))

    def install_policy(self, policy):
        with self._operation_lock:
            try:
                return self._install_policy(self._prepare_policy(policy))
            except BaseException:
                self.close()
                raise

    def _install_policy(self, policy):
        conn = self._connect()
        ack = conn.execute(
            "SELECT fannagent.install_policy(%s,%s)", (policy.policy_hash, policy.bytecode)
        ).fetchone()[0]
        if ack != policy.policy_hash:
            raise AgentError("policy installation hash mismatch")
        self._installed = policy.policy_hash
        return {"policy_hash": ack}

    def execute_probe(self, query, *, mode="native", policy=None, trace=False, audit=False):
        with self._operation_lock:
            try:
                return self._execute_probe(
                    query, mode=mode, policy=policy, trace=trace, audit=audit
                )
            except BaseException:
                # Never replay a failed policy execution. Session.query controls native fallback.
                self.close()
                raise

    def _batch_ready(self, conn):
        return (
            self._binding_conn is conn
            and self._binding is not None
            and conn.autocommit
            and not conn.closed
            and conn.pgconn.transaction_status == pq.TransactionStatus.IDLE
            and callable(getattr(psycopg, "ClientCursor", None))
            and (
                not psycopg.capabilities.has_pipeline()
                or conn.pgconn.pipeline_status == pq.PipelineStatus.OFF
            )
        )

    def _execute_probe(self, query, *, mode="native", policy=None, trace=False, audit=False):
        conn = self._connect()
        started = time.perf_counter_ns()
        policy = self._prepare_policy(policy) if policy is not None else None
        if mode == "policy":
            query = self.snapshot().query(query)
        statement, params = self._statement(query)
        nonce = uuid.uuid4().hex
        groups = (
            list(policy.groups)
            if policy
            else [
                "basic",
                "work",
                "filters",
                "progress",
                "queue",
                "queue_quantiles",
                "pgvector_executor",
            ]
        )
        context = ExecutionContext(
            mode="policy_agent" if mode == "policy" else "policy_noop",
            policy_hash=policy.policy_hash if policy else None,
            trace_level="checkpoints" if trace else "off",
            policy_role="treatment" if policy else None,
            policy_feature_profile="fann_features_v2",
            trace_max_bytes=self.config.copy.trace_max_bytes,
            feature_groups=groups,
            audit_membership=audit,
        )
        # Native timing is an ordinary autocommit SQL request. Policy timing includes
        # validation, initialization, transaction boundaries, transport and decoding.
        begin_params = (
            context.mode.value,
            context.policy_hash,
            None,
            nonce,
            query["k"],
            predicate_leaf_count(query.get("filter")),
            context.trace_level.value,
            context.trace_max_bytes,
            FEATURE_REGISTRY_HASH,
            policy.group_hash if policy else feature_set_hash(groups),
            policy.group_csv if policy else ",".join(sorted(groups)),
            audit,
        )
        begin_sql = "SELECT fannagent.begin_execution(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"
        # Select transport before sending execution commands. Installation is acknowledged
        # separately and remains inside this call's original policy timing boundary.
        batched = mode != "native" and self._batch_ready(conn)
        if batched:
            if policy and self._installed != policy.policy_hash:
                self._install_policy(policy)
            ack = begin_execution_batch(conn, begin_sql, begin_params)
            if ack != nonce:
                raise AgentError("query nonce acknowledgement mismatch")
            rows = conn.execute(statement, params).fetchall()
            # The final batch drains completion AND commit before accepting results.
            telemetry = json.loads(complete_execution_batch(conn, nonce, len(rows)))
            decoded = [(self.snapshot().source_to_id[str(r[0])], float(r[1])) for r in rows]
            if mode == "policy":
                telemetry["application_source_ids"] = [int(r[0]) for r in rows]
        else:
            with nullcontext() if mode == "native" else conn.transaction():
                if mode == "native":
                    started = time.perf_counter_ns()
                if mode != "native":
                    if policy and self._installed != policy.policy_hash:
                        self._install_policy(policy)
                    ack = conn.execute(
                        begin_sql,
                        begin_params,
                    ).fetchone()[0]
                    if ack != nonce:
                        raise AgentError("query nonce acknowledgement mismatch")
                rows = conn.execute(statement, params).fetchall()
                telemetry = (
                    json.loads(
                        conn.execute(
                            "SELECT fannagent.complete(%s,%s)", (nonce, len(rows))
                        ).fetchone()[0]
                    )
                    if mode != "native"
                    else {"ordinary_default": True}
                )
                decoded = [(self.snapshot().source_to_id[str(r[0])], float(r[1])) for r in rows]
                if mode == "policy":
                    telemetry["application_source_ids"] = [int(r[0]) for r in rows]
        if mode != "native":
            if (
                telemetry.get("request_nonce") != nonce
                or telemetry.get("protocol") != "same_execution_v4"
            ):
                raise AgentError("execution telemetry identity mismatch")
            if policy and telemetry.get("policy_hash") != policy.policy_hash:
                raise AgentError("executed policy hash mismatch")
            if telemetry.get("effective_mode") != context.mode.value:
                raise AgentError("execution mode acknowledgement mismatch")
            if (
                policy
                and telemetry.get("policy_opportunity")
                and not telemetry.get("policy_applied")
            ):
                raise AgentError("engine had a checkpoint but did not evaluate the policy")
            if (
                telemetry.get("target_index_oid")
                != (self._binding or self.store.get("source_manifest"))["index"]["oid"]
            ):
                raise AgentError("query bound index identity mismatch")
        elapsed = (time.perf_counter_ns() - started) / 1e6
        raw_trace = (
            conn.execute("SELECT fannagent.take_trace(%s)", (nonce,)).fetchone()[0]
            if trace and mode != "native"
            else None
        )
        evidence = None
        if raw_trace is not None:
            with tempfile.TemporaryDirectory() as folder:
                path = Path(folder) / f"{nonce}.jsonl"
                path.write_text(raw_trace)
                prepared = self.store.get("prepared")
                normalized = normalize_engine_trace(
                    path,
                    descriptor=telemetry["trace_descriptor"],
                    backend="pgvector",
                    query=Query.model_validate(query),
                    context=context,
                    nonce=nonce,
                    dataset_hash=self.snapshot().identity,
                    index_hash=prepared["index_identity"],
                    engine_build_hash=prepared["image_id"],
                    completion=telemetry,
                )
            for event in normalized.events:
                if "logical_ids" in event:
                    event["logical_ids"] = [
                        self.snapshot().source_to_id[str(v)] for v in event["logical_ids"]
                    ]
                for key in ("identity", "logical_id"):
                    if event.get(key) is not None:
                        event[key] = self.snapshot().source_to_id[str(event[key])]
            evidence = {
                "checkpoints": [
                    {
                        "index": c.index,
                        "actual_layer0_distances": c.actual_layer0_distances,
                        "component_id": c.component_id,
                        "features": {n: f.value for n, f in c.features.items() if f.available},
                    }
                    for c in normalized.checkpoints
                ],
                "terminal": normalized.terminal,
                "truncated": normalized.truncated,
                "collection_groups": groups,
                "normalized": asdict(normalized),
            }
            if audit:
                evidence["membership"] = reconstruct_membership(
                    self.snapshot().data, Query.model_validate(query), normalized
                )
                evidence["membership_provenance"] = "offline_identity_predicate_reconstruction"
        return ProbeResult(
            [r[0] for r in decoded], [r[1] for r in decoded], elapsed, telemetry, evidence
        )

    def collect_evidence(self, result):
        return result.evidence or {}

    def _qualify(self):
        self._check_security()
        snapshot = self.snapshot()
        policy = self.validate_policy({"name": "qualification-continue", "root": "continue"})
        for i, row in enumerate(snapshot.rows[:5]):
            query = snapshot.query({"id": f"qualification-{i}", "vector": row["vector"], "k": 10})
            native = self.execute_probe(query)
            noop = self.execute_probe(query, mode="observation", trace=True, audit=True)
            continuing = self.execute_probe(query, mode="policy", policy=policy)
            # Compare distances as well as eligibility; exact ties may choose different IDs.
            if native.distances != noop.distances or native.distances != continuing.distances:
                raise UnsupportedTarget("always-continue instrumentation changed default results")
        prepared = self.store.get("prepared")
        prepared["qualified"] = True
        prepared["dataset_identity"] = self.snapshot().identity
        prepared["index_bytes"] = (
            self._connect()
            .execute(
                "SELECT pg_relation_size(%s::oid)",
                (self.store.get("source_manifest")["index"]["oid"],),
            )
            .fetchone()[0]
        )
        prepared["qualification"] = (
            "physical index preserved; five anchor native/no-op/continue conformance probes"
        )
        self.store.set("prepared", prepared)

    def open_policy_session(self, policy):
        self._check_security()
        backend = self
        policy = self._prepare_policy(policy)
        self.install_policy(policy)

        class Session:
            def query(self, query, *, fallback=True):
                started = time.perf_counter_ns()
                try:
                    result = backend.execute_probe(query, mode="policy", policy=policy)
                except Exception:
                    if not fallback:
                        raise
                    validated = backend.snapshot().query(query)
                    result = backend.execute_probe(validated)
                    result.metadata["fallback"] = "ordinary_default"
                result.ids = result.metadata.pop("application_source_ids", None) or [
                    int(backend.snapshot().id_to_source[i]) for i in result.ids
                ]
                result.metadata["identifier_space"] = "source_bigint"
                result.latency_ms = (time.perf_counter_ns() - started) / 1e6
                return result

            def close(self):
                backend.close()

        return Session()

    def close(self):
        with self._operation_lock:
            conn, self.conn = self.conn, None
            self._installed = self._binding = self._binding_conn = None
            self._policies.clear()
            if conn is not None:
                conn.close()
