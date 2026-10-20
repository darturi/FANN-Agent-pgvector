"""Predicate context is opt-in, bounded, and tied to the actual predicate."""

import json
from types import SimpleNamespace

import pytest
from fannagent.api import AgentError, validate_policy
from fannagent.api.primitives.data import Query
from fannagent.api.primitives.errors import ValidationError

from fannagent_pgvector.backend import NativeBackend
from fannagent_pgvector.native.context import ExecutionContext
from fannagent_pgvector.native.features import CONTEXT_REGISTRY_HASH, FEATURE_REGISTRY_HASH
from fannagent_pgvector.native.transport import feature_set_hash, normalize_engine_trace
from fannagent_pgvector.predicate_context import PredicateContextBackend, predicate_threshold
from fannagent_pgvector.profiles import PREDICATE_CONTEXT_PROFILE, PROFILE


def query(value=32):
    return {
        "id": "arbitrary-id",
        "vector": [1.0, 0.0],
        "k": 10,
        "filter": {"field": "m_000000", "op": "gte", "value": value},
    }


def test_profiles_and_default_registry_stay_pinned():
    assert PROFILE.fingerprint == "3d869e5b919b231f913209fe33ec6b829e7b990cf4666a632d092556ff51958d"
    assert (
        PREDICATE_CONTEXT_PROFILE.fingerprint
        == "013de92ffffa8e1d6a62d09586cb322bb0c2342b926c7e947a56a8535710ca14"
    )
    assert FEATURE_REGISTRY_HASH != CONTEXT_REGISTRY_HASH
    assert "query_predicate_threshold" not in PROFILE.features
    assert "query_predicate_threshold" not in NativeBackend.checkpoint_fields
    assert "query_predicate_threshold" in PredicateContextBackend.checkpoint_fields
    assert NativeBackend.functions != PredicateContextBackend.functions


@pytest.mark.parametrize("value", [0, 32, 108, 2**63 - 1])
def test_scalar_comes_from_predicate_not_id(value):
    assert predicate_threshold(query(value)) == value
    assert predicate_threshold({"id": "votes108", "filter": None}) == 0


@pytest.mark.parametrize(
    "predicate",
    [
        {},
        [],
        {"field": "m_000000", "op": "gte", "value": True},
        {"field": "m_000000", "op": "gte", "value": 32.0},
        {"field": "m_000000", "op": "gte", "value": -1},
        {"field": "m_000000", "op": "gte", "value": 2**63},
        {"field": "m_000001", "op": "gte", "value": 32},
        {"field": "m_000000", "op": "eq", "value": 32},
        {"and": [query()["filter"]]},
        {**query()["filter"], "extra": 0},
    ],
)
def test_rejects_unsupported_predicates(predicate):
    with pytest.raises(AgentError):
        predicate_threshold({"filter": predicate})


def test_policy_opt_in_and_atomic_binding():
    raw = {
        "name": "context",
        "feature_groups": ["query_context"],
        "root": {
            "if": {"op": "eq", "args": [{"feature": "query_predicate_threshold"}, {"int": 32}]},
            "then": "stop",
            "else": "continue",
        },
    }
    validate_policy(raw, PREDICATE_CONTEXT_PROFILE)
    with pytest.raises(AgentError):
        validate_policy(raw, PROFILE)
    backend = PredicateContextBackend(SimpleNamespace(), SimpleNamespace())
    statement, params = backend._bind_query_context(query(), "SELECT begin(%s)", ("nonce",))
    assert statement == "SELECT begin(%s,%s::bigint)" and params == ("nonce", 32)
    with pytest.raises(AgentError):
        backend._bind_query_context(query(True), statement, params)


@pytest.mark.parametrize(
    "actual,registry,accepted",
    [
        (32, CONTEXT_REGISTRY_HASH, True),
        (108, CONTEXT_REGISTRY_HASH, False),
        (True, CONTEXT_REGISTRY_HASH, False),
        (32, FEATURE_REGISTRY_HASH, False),
        (None, CONTEXT_REGISTRY_HASH, False),
    ],
)
def test_trace_registry_and_actual_predicate_parity(tmp_path, actual, registry, accepted):
    groups = ["basic", "query_context"]
    context = ExecutionContext(
        mode="policy_noop",
        feature_groups=groups,
        trace_level="checkpoints",
        policy_feature_profile="fann_features_v2",
    )
    cp = {
        "type": "checkpoint",
        "index": 1,
        "target": 64,
        "actual_layer0_distances": 64,
        "component_id": "hnsw",
        "route": "postgresql_pgvector_hnsw",
        "decision": "noop",
        "features": {"query_predicate_threshold": actual},
    }
    terminal = {"type": "terminal", "component_id": "request"}
    path = tmp_path / "nonce.jsonl"
    path.write_text(json.dumps(cp) + "\n" + json.dumps(terminal) + "\n")
    args = dict(
        descriptor={
            "file": "nonce.jsonl",
            "bytes": path.stat().st_size,
            "feature_registry_hash": registry,
            "feature_set_hash": feature_set_hash(groups),
        },
        backend="pgvector",
        query=Query.model_validate(query()),
        context=context,
        nonce="nonce",
        dataset_hash="dataset",
        index_hash="index",
        engine_build_hash="engine",
    )
    if accepted:
        result = normalize_engine_trace(path, **args)
        assert result.feature_registry_hash == CONTEXT_REGISTRY_HASH
    else:
        with pytest.raises(ValidationError):
            normalize_engine_trace(path, **args)
