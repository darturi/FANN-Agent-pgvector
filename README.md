# FANNAgent pgvector extension

The core's [installation bundle](../agent/packaging/README.md) supplies host and
container launchers. `fannagent init --backend pgvector --output pgvector.yaml`
creates a packaged template, and `fannagent doctor pgvector.yaml --check-source`
performs source inspection and installation checks without creating a study.
In container mode the trusted controller joins the owned relay ingress network;
saved host credentials and frozen policy identities remain unchanged. Source DSNs
must be reachable from the controller, and replication DSNs from the backup helper.

Install with `pip install fannagent fannagent-pgvector`. See the core's extension API documentation for the package boundary. This package owns PostgreSQL configuration, physical copy preparation, native telemetry, exact truth, policy sessions, and cleanup.

Build the pinned instrumented image from an installed distribution using `fannagent-pgvector-build`. This builds PostgreSQL 17.11 and pgvector 0.8.6 from pinned upstream commits and the packaged patches. No harness checkout or harness base image is required.

## Configuration and workflow

Use `examples/pgvector.yaml` as a schema-v2 starting point. `backend.options.target` selects the quoted schema/table, identifier/vector fields, metadata fields, HNSW index and source credential environment reference. `backend.options.copy` selects a verified full PostgreSQL backup or a replication credential reference, image and architecture. Relative backup paths resolve against the configuration file's directory before storage. The replication DSN must be reachable from the backup container (use `host.docker.internal` for a local host source); the source inspection DSN must be reachable by the application process.

The initial profile requires PostgreSQL 17.11, pgvector 0.8.6, one ordinary selected relation/index, unique NOT NULL signed bigint identifiers, normalized float32 cosine vectors of 1–2000 dimensions and k up to 100. Metadata can be nullable. Physical copying preserves HNSW bytes and the inspected source-role search defaults. Exact references use authoritative SQL with ANN/index plans disabled and verified. The native protocol is `same_execution_v4`, with existing bounded bytecode and 64-distance checkpoints at completed expansion boundaries. The core's semantic profile fingerprint and the extension's native registry/build/index/settings identities are recorded separately.

Inspection is read-only on the source. Preparation journals ownership before creating external resources and retains partial recovery state on failure. `close()` releases connections; `cleanup()` verifies labels before deleting its own container/volume, works without source credentials or a database connection, and can be repeated. Artifacts and supplied backups remain. Pgvector owns source manifests, restore progress, secrets, bindings, SQL and database resources within its namespace. The core records preparation qualification and controls study selection, spending, evaluation and accepted deployments.

## Copy security

Preparation requires Docker Engine 28+, libpq 16+, and an image carrying
`io.fannagent.copy_security=1`. The default is `fannagent/pgvector:0.8.6-secure-v1`.
Security is mandatory; there is no trust-authentication or shared-network option.

The restore installs fresh, independent credentials for the original LOGIN query
role and a copy-only administration role in an offline, networkless single-user
bootstrap. The source and supplied backup are not modified. Credentials remain in
the private secret service and never enter copy-container arguments, environment,
logs or public artifacts. Source-role privileges and inspected search defaults are
preserved; the copy's password expiry and preload settings are reset.
Docker logging is disabled for the offline bootstrap, and its captured SQL output
is suppressed even on failure.

Each database uses its own labelled internal bridge and publishes no ports.
Docker does not allocate published ports on internal-only bridges, so a small
credential-free TCP relay connects that bridge to a separate per-run ingress
bridge and publishes only an allocated IPv4 loopback port. Its firewall permits
new connections only to the private database, and it has no backup, workspace or
credential mounts. A read-only authentication file permits SCRAM-SHA-256 for those
two roles in the selected database, rejecting other roles, databases, replication
and sockets. Clients require SCRAM rather than accepting skipped authentication.
WAL senders and logical replication workers are disabled, including logical
replication connections that use the selected database's ordinary HBA rule.
An IPv4/IPv6 nftables policy allows database requests and established replies and
blocks new outbound traffic, including DNS and host services. The startup wrapper
then drops every Linux capability and executes PostgreSQL and its relay as the OS user with
`no-new-privileges`. Firewall setup failure prevents PostgreSQL from starting.

Both bridges reserve small `/28` subnets from Docker's configured address pools
(Engine defaults when unset), avoiding existing allocations. Exhausted pools
fail preparation without deleting networks or changing daemon configuration.

Qualification, compatibility checks and new sessions validate the running image,
resource labels, network membership, port bindings, authentication/policy hashes,
actual firewall rules and PostgreSQL's process privileges. A failed preparation
stops owned listeners and retains its journal for cleanup. Cleanup removes
containers, volumes and networks in dependency order and can be repeated without
source credentials.

Existing copies without security version 1 are refused. They can still be reported
and cleaned: run `fannagent clean --run OLD_RUN`, rebuild the secure image, then
prepare a fresh run. Merely rejecting an old run does not stop an already-running
insecure container. Partial failed preparations also require cleanup and a new
run. The semantic policy profile remains unchanged, while compatibility records
the copy-security version and newly built image identity.

The host user and Docker administrators remain trusted. Database and role names
containing line breaks are unsupported. Native qualification is required on each
architecture; a host unable to install the namespace firewall fails closed.

Inspection supplies an optional compact `startup_summary` for fresh agent conversations, containing PostgreSQL/pgvector versions, schema/table and identifier/vector columns, the selected index and its definition, preserved search settings, and guidance. Prepared runs derive it from their saved source manifest and target configuration without reconnecting to the source or rewriting the manifest. Unrelated extension inventories, storage paths, and backup prerequisites remain in full inspection. Saved agent conversations retain their original context on resume.

```sh
fannagent inspect pgvector.yaml --run runs/pg
fannagent prepare pgvector.yaml --run runs/pg
fannagent run pgvector.yaml --run runs/pg
fannagent resume --run runs/pg
fannagent evaluate --run runs/pg
fannagent report --run runs/pg
fannagent clean --run runs/pg
```

`fannagent.client.open_session(run)` opens an accepted compatible connection-local policy session. Results retain original signed bigint values. Ordinary-query fallback carries `metadata['fallback'] == 'ordinary_default'`; pass `fallback=False` to surface the failure. Deploy only to an explicitly prepared compatible run with `fannagent deploy --run SOURCE --target TARGET`. Production traffic cutover, writes, replication and HA are separate operations.

## Development and qualification

```sh
uv sync --extra dev
uv run pytest -m 'not integration'
uv run ruff check src tests
uv build
```

The explicit driver `tests/qualify.py` creates only new labelled disposable sources/copies and retains results in `.qualification/`. It qualifies both supplied physical backups and agent-managed streamed-WAL backups. Mutating HOT/duplicate and invalidation tests use fresh restores. It also verifies original identifier handling, public checkpoint interventions, native/no-op/continue, actual stops, exact truth, timeouts, abort/reuse, bounded traces and fallback. Source-image setup is documented in `tests/fixtures/README.md`.

Security controls follow PostgreSQL's
[required-authentication semantics](https://www.postgresql.org/docs/17/libpq-connect.html#LIBPQ-CONNECT-REQUIRE-AUTH)
and account for Docker internal networks'
[gateway/host access](https://docs.docker.com/reference/cli/docker/network/create/#network-internal-mode---internal).

Native ARM64 qualification is recorded in `QUALIFICATION.md`. AMD64, public publication, paid-model smoke tests and broader engine/data qualification remain separate gates. This package makes no new performance claim.

### Frontier statistics collection

The current recipe also includes the Reviews demand-collection fix and a new
frontier collector optimization. With percentile collection disabled and tracing
off, minimum/maximum use a linear scan and mean/variance keep the original two-pass
calculation order. Sorting is retained when `queue_quantiles` is enabled or a
checkpoint trace needs percentile values. Numeric mean and variance policies still
compute their values; availability checks are not substituted for numeric statistics.
Checkpoint placement, the feature registry and the bounded policy language are unchanged.

Completion telemetry adds `frontier_snapshot_count`, `frontier_values_copied`,
`frontier_maximum_count`, `frontier_traversal_ns`, `frontier_statistics_ns`,
`frontier_sort_count`, `frontier_sort_ns` and `frontier_quantile_ns`. Snapshot counts
include active empty snapshot attempts. The phase timers cover traversal/copy,
arithmetic, sorting and percentile interpolation; their sum can be smaller than
`feature_collection_ns`, which also includes other collection work and bookkeeping.
These diagnostics are not policy features and do not change the registry identity.

`tests/test_frontier_statistics.py` compiles the actual packaged collector and its
baseline, checking bitwise feature equivalence and adjacent-float threshold decisions.
The explicit native fixture in `tests/fixtures/queue_statistics.py` runs both libraries
against the same disposable synthetic index. Its local ARM observations do not
establish a Reviews/Torch speedup. An x86 Torch A/B experiment remains to be run.

The experimental, separately versioned native predicate-context getter and its
qualification scope are documented in [PREDICATE_CONTEXT.md](docs/PREDICATE_CONTEXT.md).

The opt-in prepared execution, fused transport and query-level native bypass
are documented in [insertion-bypass.md](docs/insertion-bypass.md). The next Torch
package measures these paths against the frozen driver under the same per-filter
recall criteria; the registered default adapter is unchanged.
