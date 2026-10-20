# Experimental predicate-context-v1 getter

`PredicateContextBackend` in `fannagent_pgvector.predicate_context` is the explicit
research opt-in. The standard `pgvector` extension still advertises the original
profile. This adapter accepts an unfiltered query or exactly one
`m_000000 >= nonnegative int64` predicate. It reads the scalar from the actual
validated query, binds it alongside the nonce in the existing begin batch, and
makes it available through `query_predicate_threshold`. Unfiltered uses zero;
`predicate_leaf_count` distinguishes it from a filtered threshold of zero.
Unsupported fields, operators, compounds, booleans and out-of-range values fail.

The added SQL overload has a thirteenth bigint argument. The existing twelve
argument ABI remains available. The C getter and checkpoint trace field are
available only with the `query_context` collection group. Request initialization,
transaction abort and connection lifecycle reset the execution state. A policy
that may encounter an unavailable getter should use `is_available` guards.
There is no extra query round trip, index rebuild, executor-feedback dependency,
or feature inferred from a query identifier. Extraction and binding are inside
the policy clock; trace retrieval retains its previous timing boundary.

The profile fingerprint is
`013de92ffffa8e1d6a62d09586cb322bb0c2342b926c7e947a56a8535710ca14`,
matching the predeclared separate study. Its registry hash is
`bc772009a952c77b3a4c3d90c69ae62cea500b6f2c71ce06128ea498a974fc8b`.
The default profile and registry fingerprints remain unchanged. Traces validate
both the selected registry and equality with the actual query predicate.

## Qualification

See [the recorded result](../verification/predicate-context-v1.json). Local ARM
PostgreSQL 17.11 / pgvector 0.8.6 qualification used a synthetic 4,000-row,
16-dimensional database and one unchanged physical index. Forty cross-binary
and context-prefix comparisons, forty native true/false getter branches,
int64 boundaries, same-session disabled availability, invalid bindings and
rollback recovery passed. The paired timing diagnostic measures the full
adapter difference on this small fixture; it cannot establish Torch overhead.

Build and repeat locally using the cached toolchain and fixture images:

```bash
python tests/fixtures/prepare_predicate_context.py /private/tmp/predicate-fixture-build
# Run from the repository root; the source bundle is the existing sealed trial.
docker build --network none -f /private/tmp/predicate-fixture-build/PredicateContext.Dockerfile \
  -t fannagent/predicate-context-fixture:20261019 /private/tmp/predicate-fixture-build
mkdir -p .qualification/predicate-context-v1
# /usr/lib/.../lib needs executable tmpfs so PostgreSQL can load its libraries.
docker run --rm --network none --read-only \
  --tmpfs /tmp:rw,exec,mode=1777 \
  --tmpfs /usr/lib/postgresql/17/lib:rw,exec,mode=755 \
  -v "$PWD/../trials/torch-reviews-first:/opt/torch-reviews:ro" \
  -v "$PWD/src:/candidate:ro" -v "$PWD/tests/fixtures:/checks:ro" \
  -v "$PWD/.qualification/predicate-context-v1:/results:rw" \
  --entrypoint sh fannagent/predicate-context-fixture:20261019 \
  -c 'chown postgres:postgres /usr/lib/postgresql/17/lib /results; exec su postgres -s /bin/sh -c "PYTHONPATH=/opt/torch-reviews/sources python /checks/predicate_context.py"'
```

Native x86 qualification, full copy/deployment qualification, and a Reviews
predicate-context timing experiment remain required before using this getter
for a deployed policy or claiming its benefit. The next training-stop package
uses the previously verified Torch module and original lightweight profile to
fill the 49 missing outcomes. Predicate-context fitting remains a separate study;
this correctness result does not qualify a context-using policy.
