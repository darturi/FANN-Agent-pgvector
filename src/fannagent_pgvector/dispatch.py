"""Opt-in decomposition of validation, routing-proof reuse and direct native SQL."""

from __future__ import annotations

import math
import time
from collections import OrderedDict

from fannagent.api import AgentError, ProbeResult
from fannagent.api.primitives.compiler import predicate_leaf_count
from psycopg import pq, sql

from .native.filters import postgres_filter
from .native.query_context import predicate_threshold
from .optimized import OptimizedNativeBackend, OptimizedPredicateContextBackend
from .query_validation import validate_query
from .routing import cannot_stop


class DispatchExecution:
    cache_routing = False
    direct_native = False
    dispatch_cache_limit = 32

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
                query = validate_query(self.snapshot(), query)
                known = {"predicate_leaf_count": predicate_leaf_count(query.get("filter"))}
                if "query_context" in self.runtime_profile.collection_groups:
                    known["query_predicate_threshold"] = predicate_threshold(query)
                bypass = False
                if not (trace or audit) and routing != "off":
                    if routing == "unfiltered" and query.get("filter") is not None:
                        bypass = True
                    elif self.cache_routing:
                        if not hasattr(self, "_routes"):
                            self._routes = {}
                        cache = self._routes.setdefault(handle, OrderedDict())
                        key = tuple(known.items())
                        if key not in cache:
                            decision = cannot_stop(prepared.artifact.root, known)
                            if len(cache) >= self.dispatch_cache_limit:
                                cache.popitem(last=False)
                            cache[key] = decision
                        bypass = cache[key]
                    else:
                        bypass = cannot_stop(prepared.artifact.root, known)
                result = (
                    self._execute_native_direct(query)
                    if bypass and self.direct_native
                    else self._execute_probe(
                        query,
                        mode="native" if bypass else "policy",
                        policy=None if bypass else prepared,
                        trace=trace,
                        audit=audit,
                        _validated_query=True,
                    )
                )
                result.metadata.update(
                    {
                        "query_route": "native_bypass" if bypass else "policy",
                        "routing_mode": routing,
                        "requested_policy_hash": prepared.policy_hash,
                        "routing_suppressed_for_trace": bool(trace or audit) and routing != "off",
                        "transport_variant": "ordinary"
                        if bypass
                        else "fused"
                        if self.fused_transport and self._batch_ready(self.conn)
                        else "sequential",
                    }
                )
                result.latency_ms = (time.perf_counter_ns() - started) / 1e6
                return result
            except BaseException:
                self.close()
                raise

    def _statement(self, query, *, exact=False):
        predicate = query.get("filter")
        if (
            not self.direct_native
            or exact
            or (predicate is not None and set(predicate) != {"field", "op", "value"})
        ):
            return super()._statement(query, exact=exact)
        snapshot = self.snapshot()
        target = self.target
        shape = (
            None if predicate is None else (snapshot.field_map[predicate["field"]], predicate["op"])
        )
        key = (target.schema_name, target.resource, target.id_column, target.vector_column, shape)
        if not hasattr(self, "_statements"):
            self._statements = OrderedDict()
        statement = self._statements.get(key)
        if statement is None:
            where, _ = postgres_filter(predicate, snapshot.field_map)
            statement = sql.SQL(
                "SELECT {}, {} <=> %s::vector AS distance FROM {} WHERE {} "
                "ORDER BY {} <=> %s::vector LIMIT %s"
            ).format(
                sql.Identifier(target.id_column),
                sql.Identifier(target.vector_column),
                self.relation,
                where,
                sql.Identifier(target.vector_column),
            )
            if len(self._statements) >= self.dispatch_cache_limit:
                self._statements.popitem(last=False)
            self._statements[key] = statement
        # The same .9g conversion runs in a single C formatting operation. Cache
        # only its dimension-dependent format, never query vectors or values.
        size = len(query["vector"])
        if getattr(self, "_vector_format", (None,))[0] != size:
            self._vector_format = (size, ",".join(["%.9g"] * size))
        vector = "[" + self._vector_format[1] % tuple(map(float, query["vector"])) + "]"
        return statement, [
            vector,
            *([] if predicate is None else [predicate["value"]]),
            vector,
            query["k"],
        ]

    def _execute_native_direct(self, query):
        conn = self.conn
        if (
            conn is not self._binding_conn
            or self._binding is None
            or not conn.autocommit
            or conn.closed
            or conn.pgconn.transaction_status != pq.TransactionStatus.IDLE
            or (
                hasattr(conn.pgconn, "pipeline_status")
                and conn.pgconn.pipeline_status != pq.PipelineStatus.OFF
            )
        ):
            raise AgentError("native dispatch requires an idle bound autocommit connection")
        statement, params = self._statement(query)
        rows = conn.execute(statement, params).fetchall()
        if conn.pgconn.transaction_status != pq.TransactionStatus.IDLE:
            raise AgentError("native dispatch did not finish in autocommit idle state")
        if len(rows) > query["k"] or any(len(row) != 2 for row in rows):
            raise AgentError("native dispatch returned invalid row shape/count")
        mapping = self.snapshot().source_to_id
        decoded = [(mapping[str(row[0])], float(row[1])) for row in rows]
        if len({r[0] for r in decoded}) != len(decoded) or any(
            not math.isfinite(r[1]) for r in decoded
        ):
            raise AgentError("native dispatch returned duplicate IDs or nonfinite distances")
        return ProbeResult(
            [r[0] for r in decoded], [r[1] for r in decoded], 0.0, {"ordinary_default": True}
        )

    def release_execution(self, handle):
        with self._operation_lock:
            if hasattr(self, "_routes"):
                self._routes.pop(handle, None)
            return super().release_execution(handle)

    def close(self):
        with self._operation_lock:
            if hasattr(self, "_routes"):
                self._routes.clear()
            if hasattr(self, "_statements"):
                self._statements.clear()
            self._vector_format = (None, "")
            super().close()


class ValidatedNativeBackend(DispatchExecution, OptimizedNativeBackend):
    pass


class ValidatedPredicateContextBackend(DispatchExecution, OptimizedPredicateContextBackend):
    pass


class RoutedNativeBackend(ValidatedNativeBackend):
    cache_routing = True


class RoutedPredicateContextBackend(ValidatedPredicateContextBackend):
    cache_routing = True


class DispatchNativeBackend(RoutedNativeBackend):
    direct_native = True


class DispatchPredicateContextBackend(RoutedPredicateContextBackend):
    direct_native = True
