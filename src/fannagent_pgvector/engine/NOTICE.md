# Instrumented engine provenance and notices

This integration builds pgvector 0.8.6 at commit
`8ee86c96f0fd72390f890aa8a336fda6d3ab4c6c`, with three FANNBench evidence patches and
one agent target-binding/audit patch, the Reviews runtime fixes, and the
frontier-statistics collection optimization. It packages the PostgreSQL 17.11
executor build at commit `083ac033419f690758508e08c1736089384bbee8`.

The first three patches are copied unchanged from the harness. The fourth retains
that implementation and adds relation/key/vector/index binding, nonce-scoped trace
retrieval, client-count provenance, visible HOT identities, and identities for scored
nodes rejected from the retained heap. Ordinary searches keep the existing behavior
when evidence/policy collection is inactive. Binding falls back to the harness `id`
convention when no explicit target has been selected.

See `provenance.json` for patch hashes, the tested local image ID and qualification
limits. A local Docker image ID does not identify a published multi-platform manifest.
The source recipe has been checked by applying all six patches to a clean archive
of the pinned upstream commit and comparing all 29 resulting C/header files with
the native build source. Patch five preserves the tested entry-distance getter
and policy-demand gate used by the Torch baseline. Patch six keeps the two-pass
mean/variance reduction order, sorts frontier values only when percentile
collection or checkpoint tracing is enabled, and adds diagnostic phase counters.

License notices for pgvector/PostgreSQL, the FANNBench patch source and mini-swe-agent
are preserved in `licenses/`. mini-swe-agent is a separate Python dependency; its
agent/model/environment implementation is wrapped without vendoring a fork.
