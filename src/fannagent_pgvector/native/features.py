import json
from importlib.resources import files
from types import SimpleNamespace
from typing import Literal

from fannagent.api import FeatureDefinition, digest

FEATURE_PROFILE = "fann_features_v2"
AvailabilityReason = Literal[
    "not_observed_yet",
    "empty_population",
    "insufficient_results",
    "zero_denominator",
    "unsupported_population",
    "unsupported_by_engine",
    "route_not_applicable",
    "not_enabled",
    "incomplete_coverage",
    "incomplete_topk",
    "missing_identity",
    "truncated_capture",
]

_REGISTRY = json.loads(files(__package__).joinpath("registry.json").read_text())
FEATURE_REGISTRY_HASH = _REGISTRY["registry_hash"]
ENGINE_CAPABILITIES = _REGISTRY["capabilities"]
FEATURES = {n: SimpleNamespace(**f) for n, f in _REGISTRY["definitions"].items()}


# The existing registry and profile remain byte-for-byte compatible. This registry
# is selected only by the explicitly enabled predicate-context study.

CONTEXT_FEATURE = FeatureDefinition(
    name="query_predicate_threshold",
    kind="int",
    group="query_context",
    units="predicate_scalar",
    availability="pre_execution_query_constant",
    provenance="validated_query_predicate",
    collection_cost="must_be_measured_in_separate_ablation",
    source="query_context_v1",
    description="Actual m_000000 >= integer threshold; unfiltered uses 0 and leaf_count=0",
)
CONTEXT_REGISTRY_HASH = digest(
    {
        "base_registry_hash": FEATURE_REGISTRY_HASH,
        "study": "predicate-context-v1",
        "feature": CONTEXT_FEATURE.model_dump(mode="json"),
    }
)
CONTEXT_FEATURES = {
    **FEATURES,
    CONTEXT_FEATURE.name: SimpleNamespace(**{**CONTEXT_FEATURE.model_dump(), "stage": "runtime"}),
}


def registry_for(groups):
    if "query_context" in groups:
        return CONTEXT_REGISTRY_HASH, CONTEXT_FEATURES
    return FEATURE_REGISTRY_HASH, FEATURES
