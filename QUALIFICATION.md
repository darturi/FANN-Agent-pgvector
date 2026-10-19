# ARM64 qualification — 2026-10-06

## Installed controller

The local installation release `43438c94e1dbdc86dd8f` passed all 24 native
qualification cases through the installed, non-root controller image
`sha256:73ac4a8da74eb9b586357eb92d4b112c43bf9716e12587a03e3b87f0c8882253`
and the pinned secure database image identified below. The exercised Docker
Engine version was 29.6.1 on ARM64.

Both supplied physical backups and streamed-WAL backups passed native result,
stopping, timeout/reuse, checkpoint, snapshot invalidation, duplicate/HOT,
quoted non-superuser role, public SDK and copy-security checks. The source role
verifiers and native compatibility fingerprints remained unchanged. Cleanup ran
twice per restore and removed the disposable source and copies; all 171
pre-existing volumes and 47 pre-existing containers remained intact.

Results are retained in `.qualification/2ec1a91bd9/results.json` and copied into
the local bundle's `validation/native-results.json`. Its `validation.json`
records the exact release, image IDs, test-driver hashes and separate release
gates. Native AMD64, broader deployment/data profiles and paid-provider testing
remain unverified; these tests make no performance-improvement claim.

## Earlier secure-copy qualification

The secure image is `fannagent/pgvector:0.8.6-secure-v1`, image ID
`sha256:7aceb4c82fc429df17b7eda410d3d7c5cd0aeb2f66d002a54898fe823641e82f`.
It was built from the self-contained pinned source recipe. Security version 1
adds offline SCRAM bootstrap, a strict read-only HBA file, per-run internal
networking with a loopback TCP relay, namespace nftables denial of new outbound
traffic, and capability-free PostgreSQL/relay processes with no-new-privileges.

The installed-wheel driver passed 24 scenarios across supplied and streamed-WAL
backups, including the existing native/SDK tests and a quoted non-superuser query
role. Final results are retained in `.qualification/c491d4562b/results.json`.
The ordinary source role's permissions and search defaults were preserved;
the source's role password verifiers were unchanged. Preparation and compatibility
verified unchanged physical HNSW hashes. The semantic profile fingerprint remains
`3d869e5b919b231f913209fe33ec6b829e7b990cf4666a632d092556ff51958d`.

Security checks accepted correct generated credentials and refused missing,
wrong, source and previous-run credentials, unrelated roles/databases, and
physical and logical replication. A default-bridge peer could not reach the
database, and a deliberately attached peer could not skip authentication. TCP, UDP with an echo
positive control, DNS for a known peer alias, gateway/host-service connections,
and relay egress to an unrelated peer were denied. The driver verified actual
firewall rules and zero PostgreSQL/relay capabilities, malformed HBA refusal,
extra-network and port/security-marker tampering, and restart.

Actual injected single-user SQL errors, missing firewall capabilities, invalid
firewall syntax and PostgreSQL startup errors aborted safely. Unit failure
injections also verified stopped owned listeners, retained recovery records,
foreign-volume refusal before mounting and dependency-ordered cleanup. Cleanup
ran twice per restore; unit tests also blocked secret access and removed source
credential references. Artifacts and supplied backups were retained.
Docker configuration/logs and extension artifacts contained no
generated credentials or SCRAM verifiers.
The offline bootstrap disables Docker's log driver; a separate disposable probe
confirmed captured output remains suppressed and SQL errors remain detectable.

The core/extension suite passed 75 tests (9 integration tests skipped without
their fixture environment); the explicit workspace-container integration test
passed separately. Ruff passed. Clean core-only, pgvector and independent-extension
wheel environments passed discovery, workflow, session/fallback, packaging and
cleanup smoke checks.

The exercised host used ARM64, Docker Engine 29.6.1 and libpq 18.6. Native AMD64 and
broader deployment/data qualification remain unverified. Existing unsecured
copies must be cleaned and replaced with fresh runs; these code changes do not
automatically stop old copies.

## Previous core-v2 qualification

The self-contained source recipe built `fannagent/pgvector:0.8.6-core-v2` as image `sha256:ea0c2c72530f269b2063661d544417100714beead9e224eb9f5d3fd02b010f89`, without a harness checkout or harness base image.

The explicit disposable driver passed 18 scenarios across both supplied full physical backups and agent-managed streamed-WAL backups. Each method passed stock/native result conformance, native/no-op/continue qualification, actual stopping, authoritative exact truth, quoted fields, nullable metadata, bigint extrema, bounded traces, abort/timeout/reuse, truthful non-HNSW outcomes, ordinary background checkpoints, snapshot invalidation, and HOT/duplicate identity audits. Mutating tests used separate fresh restores. Public SDK labeling and original-identifier serving passed, including ordinary fallback marking and failure propagation when fallback was disabled. Cleanup ran twice per restore and retained artifacts/backups.

Qualification was repeated using the final installed core and pgvector wheels from outside the repository. Raw local results are retained under `.qualification/769392a820/results.json`. Physical-index hashes and source-role search settings were recorded/verified by preparation and compatibility checks. The source fixture was independently stock PostgreSQL/pgvector, with its role's `hnsw.ef_search=80` preserved in the copies.

This qualifies the exercised local ARM64 fixture and existing data profile. Native AMD64, broader engine/data qualification, public publication, paid-model smoke testing, production cutover and performance-improvement claims remain outside this release.
