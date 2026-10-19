from __future__ import annotations

import json
from dataclasses import asdict
from types import SimpleNamespace

from fannagent.api import (
    AgentError,
    CheckpointRef,
    EvidenceCheckpoint,
    ExecutionEvidence,
    PreparedEnvironment,
    ProbeRequest,
    WorkMeasure,
    digest,
    validate_policy,
)

from .backend import NativeBackend
from .docker import docker
from .profiles import DATA_PROFILE, PROFILE


class ExtensionStorage:
    """Legacy native implementation's storage facade, restricted to its namespace."""

    def __init__(self, context):
        self.context, self.root = context, context.private_directory

    def get(self, key, default=None):
        return self.context.state.get(key, default)

    def set(self, key, value):
        if key == "owned_resources":
            # Persist recovery identity before any external creation.
            for field, kind in (
                ("container", "container"),
                ("bootstrap", "container"),
                ("proxy", "container"),
                ("backup_helper", "container"),
                ("utility_helper", "container"),
                ("volume", "volume"),
                ("network", "network"),
                ("ingress_network", "network"),
            ):
                if value.get(field):
                    self.context.journal.record(
                        {"kind": kind, "name": value[field], "label": value["label"]}
                    )
        self.context.state.set(key, value)

    def secret(self, key, value=None):
        if value is not None:
            self.context.secrets.set(key, value)
        return self.context.secrets.get(key)

    def put(self, *args, **kwargs):
        return self.context.artifacts.put(*args, **kwargs)


class PgvectorBackend:
    runtime_profile = PROFILE
    data_profile = DATA_PROFILE

    def __init__(self, options, context):
        self.context = context
        copy = SimpleNamespace(
            **options.copy.model_dump(),
            cpus=context.limits.cpus,
            memory_gib=context.limits.memory_gib,
            max_evidence_bytes=context.limits.max_evidence_bytes,
            trace_max_bytes=context.limits.trace_max_bytes,
        )
        config = SimpleNamespace(
            target=options.target,
            copy=copy,
            query_timeout_seconds=context.limits.query_timeout_seconds,
        )
        self.native = NativeBackend(config, ExtensionStorage(context))

    def inspect_target(self):
        inspection = self.native.inspect_target()
        target = self.native.target
        versions = inspection.get("versions", {})
        index = inspection.get("index")
        summary = {
            "target": {
                "schema": target.schema_name,
                "table": target.resource,
                "identifier_column": target.id_column,
                "vector_column": target.vector_column,
            },
            "versions": {
                k: versions[k] for k in ("server_version", "vector_version") if k in versions
            },
            "index": {
                name: index[key]
                for name, key in (
                    ("name", "relname"),
                    ("type", "amname"),
                    ("vector_column", "column_name"),
                    ("operator_class", "opcname"),
                    ("definition", "definition"),
                )
                if key in index
            }
            if index is not None
            else None,
            **{k: inspection[k] for k in ("settings", "guidance") if k in inspection},
        }
        return {**inspection, "startup_summary": summary}

    def describe_capabilities(self):
        return self.native.describe_capabilities()

    def snapshot(self):
        return self.native.snapshot()

    def exact_reference(self, query):
        return self.native.exact_reference(query)

    def compatibility(self):
        return {
            **self.native.compatibility(),
            "profile_hash": PROFILE.fingerprint,
            "data_profile_hash": digest(DATA_PROFILE.model_dump(mode="json")),
            "native_protocol": PROFILE.native_protocol,
            "native_registry_hash": PROFILE.native_registry_hash,
        }

    def prepare_copy(self):
        raw = self.native.prepare_copy()
        return PreparedEnvironment(
            "pgvector",
            raw["qualified"],
            self.compatibility(),
            ("copy_dsn", "copy_admin_dsn"),
            self.context.journal.resources(),
            raw,
        )

    def validate_policy(self, raw):
        return validate_policy(raw, PROFILE)

    def install_policy(self, policy):
        return self.native.install_policy(policy)

    def execute_probe(self, request: ProbeRequest):
        policy = request.policy
        if policy:
            policy = self.native._prepare_policy(policy)
        if request.intervention:
            c = request.intervention.checkpoint
            if c.scope != PROFILE.stopping_scope or c.token != str(c.ordinal):
                raise AgentError("checkpoint intervention scope/token is incompatible")
            policy = self.native._prepare_policy(
                {
                    "name": "stop-at-checkpoint",
                    "feature_groups": list(request.intervention.collection_groups),
                    "root": {
                        "if": {
                            "op": "gte",
                            "args": [{"feature": "checkpoint_index"}, {"int": c.ordinal}],
                        },
                        "then": "stop",
                        "else": "continue",
                    },
                }
            )
        result = self.native.execute_probe(
            request.query,
            mode=request.mode,
            policy=policy,
            trace=request.trace,
            audit=request.audit,
        )
        if result.evidence:
            raw = result.evidence
            checkpoints = tuple(
                EvidenceCheckpoint(
                    CheckpointRef(
                        c["component_id"], PROFILE.stopping_scope, c["index"], str(c["index"])
                    ),
                    WorkMeasure(c["actual_layer0_distances"], PROFILE.work_unit),
                    c["features"],
                    {
                        n: f.get("reason")
                        for n, f in native["features"].items()
                        if not f["available"]
                    },
                )
                for c, native in zip(raw["checkpoints"], raw["normalized"]["checkpoints"])
            )
            result.execution_id = raw["normalized"]["nonce"]
            normalized = ExecutionEvidence(
                result.execution_id,
                digest(self.snapshot().query(request.query)),
                PROFILE.fingerprint,
                PROFILE.stopping_scope,
                checkpoints,
                raw["terminal"],
                raw["truncated"],
                tuple(raw["collection_groups"]),
                {
                    "native": raw["normalized"],
                    "membership": raw.get("membership"),
                    "native_registry_hash": PROFILE.native_registry_hash,
                },
            )
            result.evidence = asdict(normalized)
        else:
            result.execution_id = result.metadata.get("request_nonce", "")
        return result

    def collect_evidence(self, result):
        raw = result.evidence
        if not raw:
            raise AgentError("execution did not return observation evidence")
        checkpoints = tuple(
            EvidenceCheckpoint(
                CheckpointRef(**c["reference"]),
                WorkMeasure(**c["work"]),
                c["features"],
                c["availability"],
                c["provenance"],
            )
            for c in raw["checkpoints"]
        )
        return ExecutionEvidence(**{**raw, "checkpoints": checkpoints})

    def open_policy_session(self, policy):
        return self.native.open_policy_session(policy)

    def close(self):
        self.native.close()

    def cleanup(self):
        self.close()
        removed = []
        order = {"container": 0, "volume": 1, "network": 2}
        for resource in sorted(self.context.journal.resources(), key=lambda r: order[r["kind"]]):
            kind, name = resource["kind"], resource["name"]
            try:
                item = json.loads(docker(kind, "inspect", name))[0]
            except AgentError as exc:
                if any(
                    x in str(exc).lower()
                    for x in (
                        "no such container",
                        "no such volume",
                        "no such object",
                        "no such network",
                    )
                ):
                    continue
                if kind == "network" and "not found" in str(exc).lower():
                    continue
                raise
            labels = item.get("Labels") or item.get("Config", {}).get("Labels", {})
            key, value = resource["label"].split("=", 1)
            if labels.get(key) != value:
                raise AgentError("resource ownership changed; cleanup refused")
            if kind == "network":
                from .security import detach_controller

                detach_controller(name, docker)
            docker(kind, "rm", *(["-f"] if kind == "container" else []), name)
            removed.append(resource)
        self.context.state.set("cleaned", True)
        return {"removed": removed, "artifacts_retained": str(self.context.private_directory)}
