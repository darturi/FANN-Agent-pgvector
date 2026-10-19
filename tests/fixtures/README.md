# Fresh disposable native fixtures

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
