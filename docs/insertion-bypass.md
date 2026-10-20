# Opt-in insertion and query-routing study

`optimized.OptimizedNativeBackend` and `OptimizedPredicateContextBackend` add a
research execution path. The registered extension still creates the default
adapter. No native C patch or profile/registry change is introduced here.

`prepare_execution(policy, routing="off")` validates and owns the policy, then
returns an opaque connection-bound handle. `execute_prepared(query, handle)`
validates every query, including reused calls. Caller policy mutation, foreign
handles, release, close and reconnection cannot substitute another private plan.
Release handles with `release_execution`; at most 32 are live per backend.

The prepared-only classes retain the previous acknowledged transport. The fused
classes combine optional policy installation, BEGIN, execution initialization and
the unchanged ANN SELECT in one sequential PostgreSQL simple-query batch. All
result sets, policy and nonce acknowledgements, row shape/count and transaction
state must validate. Completion receives the actual row count and COMMIT is
acknowledged in a second exchange. Unsupported batching uses the existing
sequential path. Late errors close the connection; execution is never retried
implicitly by `execute_prepared`.

Routing is explicit:

- `off` always invokes the policy.
- `static` proves every reachable leaf continues using the actual predicate
  threshold and leaf count. Dynamic comparisons are considered total only under
  an availability guard. Unknown/unsafe arithmetic keeps policy execution.
- `unfiltered` additionally routes every filtered query to native search. This
  changes policy eligibility and is a separately declared study arm.

Bypass runs ordinary native SQL without policy installation, begin/complete
commands, transaction wrapping or checkpoint collection. It reports
`query_route=native_bypass`, the requested policy identity and no engine work
counters. Neither query IDs nor retrospective outcomes participate in routing.
Trace/audit requests suppress bypass to qualify the original policy path, with
that suppression marked explicitly.

The opt-in `open_policy_session(policy, routing="static")` exposes this route to
applications, preserving source bigint identifiers and caller-controlled native
fallback. Its `preparation_ms` records policy-handle setup separately. The Torch
cold regime charges preparation plus the complete first execution; reused timing
includes query validation, routing, database work, acknowledgement checks and
result decoding. Both backend and outer application clocks are retained.

The first study is `trials/torch-reviews-insertion-bypass-v1`: seven frozen seeds,
29 execution arms and 104,400 paired measurements across three allocations.
The earlier getter library is reused byte-for-byte. New execution qualification
on x86 precedes the measurement blocks. No fit, provider call or confirmation
query is allowed. Recall noninferiority remains a lower 95% vector-cluster bound
of at least -0.005 overall and in each filter, with native recall at least 0.95
per filter and complete valid results.

The returned x86 insertion/bypass experiment was independently verified. None
of its 29 arms met both timing and per-filter recall requirements. Its ordinary
native clock excludes statement construction/query validation; the retained
outer application clocks expose that difference. Both clocks remain reported.

`dispatch.py` adds separately opt-in `Validated*`, `Routed*` and `Dispatch*`
backends. They retain the opaque handle and connection lifecycle. The first uses
the shared Query model and filter checker for plain single-leaf input, avoids a
second vector serialization and scalar NumPy isclose, and delegates general or
invalid input to Snapshot.query with the original error details. Every input is
validated anew; input vectors and filters are owned before execution. Boundary
tests compare normalization acceptance and error/value parity with Snapshot.

The routing stage caches conservative cannot-stop proofs by actual validated
predicate leaf count/threshold inside the owned policy handle. It caches neither
query IDs nor outcomes. At most 32 proof keys per handle are retained; release,
close and reconnect clear the appropriate private state. Trace/audit suppress
bypass exactly as before.

The dispatch stage reaches ordinary SQL before constructing policy context,
nonce, feature hashes or begin/complete arguments. It requires the bound idle
autocommit connection and validates row shape/count, ID mapping, distance
finiteness and completion state. Failures close without replay. It caches at
most 32 SQL shapes, rebinding the current predicate value and k. The single
dimension-dependent C percent-format string preserves the original .9g vector
text byte-for-byte; query vectors/serialized vectors are never cached. Policy
and audit protocol acknowledgements remain on the original fused path.

The next separate study is `trials/torch-reviews-dispatch-overhead-v1`: five
frozen policies, six eligibility scenarios and four cumulative paths give 24
arms and 86,400 retained pairs. Cold costs include preparation, validation,
routing, vector serialization, SQL construction and execution. A separate
synthetic CPU profile accompanies native qualification and cannot affect policy
selection or the unchanged recall gates. No native C changes, fits, providers
or confirmation queries are introduced. Local ARM qualification passes; new
x86 dispatch qualification and Torch performance are pending.
