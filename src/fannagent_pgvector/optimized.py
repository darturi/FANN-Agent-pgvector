"""Opt-in insertion-cost and native-bypass study; default adapters are unchanged."""

from __future__ import annotations

import time
from copy import deepcopy
from dataclasses import dataclass

from fannagent.api import AgentError
from fannagent.api.primitives.compiler import predicate_leaf_count

from .backend import NativeBackend
from .native.fused import begin_search_batch
from .native.query_context import predicate_threshold
from .predicate_context import PredicateContextBackend
from .routing import cannot_stop


@dataclass(frozen=True, eq=False, slots=True)
class ExecutionHandle:
    """Opaque backend-owned identity; no mutable policy data leaves the backend."""

    policy_hash: str
    routing: str


class OptimizedExecution:
    fused_transport = True

    def open_policy_session(self, policy, *, routing="static"):
        self._check_security()
        backend = self
        owned = deepcopy(self.validate_policy(policy).serialize())
        started = time.perf_counter_ns()
        handle = self.prepare_execution(owned, routing=routing)
        setup_ms = (time.perf_counter_ns() - started) / 1e6

        class Session:
            # Cold experiment timings include this separate preparation cost.
            preparation_ms = setup_ms

            def query(self, query, *, fallback=True):
                nonlocal handle
                with backend._operation_lock:
                    started = time.perf_counter_ns()
                    try:
                        if handle is None:
                            handle = backend.prepare_execution(owned, routing=routing)
                        result = backend.execute_prepared(query, handle)
                    except Exception:
                        handle = None
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

    def prepare_execution(self, policy, *, routing="off"):
        if routing not in {"off", "static", "unfiltered"}:
            raise AgentError("unknown query routing mode")
        with self._operation_lock:
            # Initial connection discovery calls close() to reset session state.
            # Establish it before minting a handle tied to this connection.
            self._connect()
            if not hasattr(self, "_executions"):
                self._executions = {}
            if len(self._executions) >= 32:
                raise AgentError("release unused execution handles before preparing more")
            # Never accept a caller-created PreparedPolicy as trusted private state.
            prepared = self._policies.prepare(policy)
            handle = ExecutionHandle(prepared.policy_hash, routing)
            self._executions[handle] = (prepared, routing)
            return handle

    def release_execution(self, handle):
        with self._operation_lock:
            if hasattr(self, "_executions"):
                self._executions.pop(handle, None)

    def execute_prepared(self, query, handle, *, trace=False, audit=False):
        with self._operation_lock:
            started = time.perf_counter_ns()
            try:
                entry = getattr(self, "_executions", {}).get(handle)
                if entry is None:
                    raise AgentError("execution handle is foreign, released or closed")
                self._connect()
                if getattr(self, "_executions", {}).get(handle) is not entry:
                    raise AgentError("execution handle was invalidated by reconnect")
                prepared, routing = entry
                query = self.snapshot().query(query)
                known = {"predicate_leaf_count": predicate_leaf_count(query.get("filter"))}
                if "query_context" in self.runtime_profile.collection_groups:
                    known["query_predicate_threshold"] = predicate_threshold(query)
                bypass = not (trace or audit) and (
                    (routing == "unfiltered" and query.get("filter") is not None)
                    or (routing != "off" and cannot_stop(prepared.artifact.root, known))
                )
                result = self._execute_probe(
                    query,
                    mode="native" if bypass else "policy",
                    policy=None if bypass else prepared,
                    trace=trace,
                    audit=audit,
                    _validated_query=True,
                )
                result.metadata.update(
                    {
                        "query_route": "native_bypass" if bypass else "policy",
                        "routing_mode": routing,
                        "requested_policy_hash": prepared.policy_hash,
                        "routing_suppressed_for_trace": bool(trace or audit) and routing != "off",
                        "transport_variant": "fused"
                        if not bypass and self.fused_transport and self._batch_ready(self.conn)
                        else "ordinary"
                        if bypass
                        else "sequential",
                    }
                )
                # Includes handle lookup, validation, routing, native/policy work,
                # acknowledgement checks and result decoding on both branches.
                result.latency_ms = (time.perf_counter_ns() - started) / 1e6
                return result
            except BaseException:
                self.close()
                raise

    def _policy_search_batch(self, conn, policy, nonce, begin_sql, begin_params, statement, params):
        if not self.fused_transport:
            return super()._policy_search_batch(
                conn, policy, nonce, begin_sql, begin_params, statement, params
            )
        installing = policy is not None and self._installed != policy.policy_hash
        rows = begin_search_batch(
            conn,
            begin_sql,
            begin_params,
            statement,
            params,
            install=(policy.policy_hash, policy.bytecode) if installing else None,
        )
        if installing:
            self._installed = policy.policy_hash
        return rows

    def close(self):
        with self._operation_lock:
            if hasattr(self, "_executions"):
                self._executions.clear()
            super().close()


class OptimizedNativeBackend(OptimizedExecution, NativeBackend):
    pass


class OptimizedPredicateContextBackend(OptimizedExecution, PredicateContextBackend):
    pass


class PreparedNativeBackend(OptimizedNativeBackend):
    fused_transport = False


class PreparedPredicateContextBackend(OptimizedPredicateContextBackend):
    fused_transport = False
