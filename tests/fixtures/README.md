# Fresh disposable native fixtures

## Queue statistics A/B fixture

`queue_statistics.py` and `queue-statistics.Dockerfile` qualify the collector
optimization separately from the full copy-security driver below. Build the
Dockerfile's `fixture` target with a disposable checkout containing all six packaged
patches. The `runtime` target contains the optimized engine without fixture Python
dependencies; it retains the baseline PostgreSQL executable and security entrypoint.

Run the fixture with no network, a read-only root, user `65534:65534`, two CPUs,
4 GiB of RAM and temporary filesystems at `/tmp` and
`/usr/lib/postgresql/17/lib`. The library tmpfs needs `exec` so PostgreSQL can map
the test shared libraries. Mount this directory read-only at `/checks` and the
preserved Torch runner bundle read-only at `/opt/torch-reviews`, then execute
`python /checks/queue_statistics.py`. It changes only libraries copied into its
temporary filesystem, restarts its private PostgreSQL cluster between variants,
and never connects to an existing database.

The fixture generates 4,000 normalized 16-dimensional vectors and performs at most
1,500 synthetic backend queries (currently 960). It compares numeric feature and
stopping behavior, trace values, results, physical work and the unchanged physical
index. Its JSON output retains all 288 benchmark pairs and phase summaries.
The fixed baseline-then-optimized order and small ARM workload are qualification
limitations; this is not a substitute for the planned Torch comparison.

## Full copy-security qualification

The explicit driver `../qualify.py` creates a new labelled stock source and restores four copies for each backup method: regular conformance, invalidation, HOT/duplicate tests, and a quoted non-superuser query role. It verifies ownership before cleanup, retains run artifacts and supplied backups, and never uses an existing user database. It requires Docker and an explicitly built stock fixture image named `fannagent/pgvector-stock-fixture:0.8.6`.

Build that source image with the packaged `engine/Dockerfile.stock-fixture` and an unpatched archive of pgvector commit `8ee86c96f0fd72390f890aa8a336fda6d3ab4c6c` in `source/`. Its final stage uses pinned stock PostgreSQL 17.11. The stock source has no agent SQL functions.

`initialize.py` creates quoted fields, normalized float32 cosine vectors, nullable metadata, signed bigint extrema, and a physical cosine HNSW index. The driver sets source-role search defaults, enables replication solely for this fixture, and qualifies supplied and streamed-WAL backups. Replication must be reachable from the backup container.

The ordinary pytest integration cases can also run against an explicitly prepared disposable run by setting `FANNAGENT_TEST_RUN` and `FANNAGENT_TEST_SOURCE_URL`. Mutation cases require separate fresh restores. For complete ordered qualification, prefer the explicit driver.

The driver requires the secure copy image `fannagent/pgvector:0.8.6-secure-v1`.
Its synthetic stock source uses a fixture-only password and an allocated published
port so gateway egress can be tested. The source is removed in `finally`; it never
uses a user database. Security cases check missing/wrong/source passwords, denied
databases/roles/replication, peer-container isolation, namespace egress, privilege
dropping, secret redaction, tampering and restart. Source-role defaults, index
hashes and native conformance are verified for both backup methods.
