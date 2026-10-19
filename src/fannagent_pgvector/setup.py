"""Read-only preflight for installed pgvector distributions."""

import json
import os
import shutil
import subprocess
from types import SimpleNamespace

import psycopg


def installation_checks(options, config, *, check_source=False):
    checks = []

    def add(name, ready, detail):
        checks.append({"name": name, "status": "ok" if ready else "fail", "detail": detail})

    add("libpq", psycopg.pq.version() >= 160000, "libpq 16+ required for SCRAM enforcement")
    add(
        "source_credential",
        bool(os.environ.get(options.target.connection_env)),
        f"set {options.target.connection_env} for source inspection",
    )
    if options.copy.backup:
        backup = options.copy.backup
        add(
            "backup",
            (backup / "backup_manifest").is_file() and (backup / "PG_VERSION").is_file(),
            "use a full PostgreSQL 17 physical backup with its manifest",
        )
    else:
        key = options.copy.replication_env or "FANNAGENT_REPLICATION_URL"
        add(
            "replication_credential",
            bool(os.environ.get(key)),
            f"set {key}; it must be reachable from the Docker backup helper",
        )
    daemon_ready = False
    try:
        process = subprocess.run(
            ["docker", "version", "--format", "{{.Server.Version}}"],
            capture_output=True,
            text=True,
            check=True,
            timeout=15,
        )
        daemon_ready = int(process.stdout.strip().split(".")[0]) >= 28
    except (OSError, ValueError, subprocess.SubprocessError):
        pass
    add("docker", daemon_ready, "start a local Docker Engine 28+ daemon")
    if daemon_ready:
        try:
            item = json.loads(
                subprocess.run(
                    ["docker", "image", "inspect", options.copy.image],
                    capture_output=True,
                    text=True,
                    check=True,
                    timeout=15,
                ).stdout
            )[0]
            labels = item["Config"].get("Labels") or {}
            add(
                "copy_image",
                all(
                    labels.get(k) == "1"
                    for k in (
                        "io.fannagent.binding",
                        "io.fannagent.copy_security",
                        "io.fannagent.copy_proxy",
                    )
                ),
                "build the secure instrumented image with fannagent-pgvector-build",
            )
            capacity = subprocess.run(
                [
                    "docker",
                    "run",
                    "--rm",
                    "--read-only",
                    "--network",
                    "none",
                    "--cap-drop",
                    "ALL",
                    "--label",
                    "io.fannagent.diagnostic=1",
                    "--tmpfs",
                    "/var/lib/postgresql/data:size=64k",
                    "--entrypoint",
                    "df",
                    options.copy.image,
                    "-Pk",
                    "/var/lib/postgresql",
                ],
                capture_output=True,
                text=True,
                check=True,
                timeout=15,
            )
            docker_free = int(capacity.stdout.splitlines()[-1].split()[3]) * 1024
            add(
                "docker_storage",
                docker_free >= config.evidence.max_bytes,
                f"Docker filesystem has {docker_free} bytes free; allocate evidence plus "
                "full cluster-copy headroom",
            )
            if options.copy.architecture:
                add(
                    "architecture",
                    item["Architecture"] == options.copy.architecture,
                    "image and configured source architecture must match",
                )
            info = json.loads(
                subprocess.run(
                    ["docker", "info", "--format", "{{json .}}"],
                    capture_output=True,
                    text=True,
                    check=True,
                    timeout=15,
                ).stdout
            )
            add(
                "docker_memory",
                info["MemTotal"] >= config.resources.memory_gib * 1024**3 + 64 * 1024**2,
                "allocate configured database memory plus relay and sandbox headroom to Docker",
            )
        except (OSError, KeyError, ValueError, subprocess.SubprocessError):
            add("copy_image", False, "copy image unavailable; run fannagent-pgvector-build")
    if check_source:
        from .backend import NativeBackend

        store = SimpleNamespace(get=lambda key, default=None: default)
        backend = NativeBackend(SimpleNamespace(target=options.target), store)
        try:
            result = backend.inspect_target()
            add("source", result["compatible"], "; ".join(result["issues"]) or "source compatible")
            required = result["cluster_bytes_estimate"] * (1 if options.copy.backup else 2)
            add(
                "host_storage",
                shutil.disk_usage(config.configuration_origin).free
                >= required + config.evidence.max_bytes,
                "space for the full cluster and evidence",
            )
            if daemon_ready and "docker_free" in locals():
                add(
                    "docker_copy_storage",
                    docker_free >= required + config.evidence.max_bytes,
                    "Docker needs full physical-copy and evidence headroom",
                )
            if daemon_ready and "item" in locals():
                add(
                    "source_architecture",
                    item["Architecture"] == result["architecture"],
                    "physical backups require the source image architecture",
                )
        except Exception:
            add(
                "source",
                False,
                "source inspection failed; check endpoint, credentials, "
                "permissions and controller reachability",
            )
        finally:
            backend.close()
    checks.append(
        {
            "name": "qualification",
            "status": "warning",
            "detail": "check this release's native qualification evidence for the installed "
            "controller and architecture; AMD64 and broader deployment profiles need "
            "separate qualification",
        }
    )
    return checks
