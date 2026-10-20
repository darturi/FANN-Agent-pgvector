"""Opt-in native adapter for the separately versioned predicate-context-v1 study."""

from .backend import FUNCTIONS, NativeBackend
from .native.query_context import predicate_threshold
from .profiles import PREDICATE_CONTEXT_PROFILE

CONTEXT_FUNCTIONS = """
CREATE OR REPLACE FUNCTION fannagent.begin_execution(
 text,text,bigint,text,integer,integer,text,bigint,text,text,text,boolean,bigint)
 RETURNS text AS '$libdir/vector','fannbench_begin_execution'
 LANGUAGE C VOLATILE PARALLEL UNSAFE;
"""


class PredicateContextBackend(NativeBackend):
    runtime_profile = PREDICATE_CONTEXT_PROFILE
    functions = FUNCTIONS + CONTEXT_FUNCTIONS
    checkpoint_fields = (*NativeBackend.checkpoint_fields, "query_predicate_threshold")

    def _bind_query_context(self, query, statement, params):
        # Called inside _execute_probe's timer, before any server execution. The
        # validated scalar travels with the nonce in the existing begin batch.
        threshold = predicate_threshold(query)
        return statement[:-1] + ",%s::bigint)", (*params, threshold)
