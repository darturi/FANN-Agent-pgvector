from fannagent.api import DataProfile, FeatureDefinition, RuntimeProfile

from .native.features import (
    CONTEXT_FEATURE,
    CONTEXT_REGISTRY_HASH,
    ENGINE_CAPABILITIES,
    FEATURE_REGISTRY_HASH,
    FEATURES,
)

DATA_PROFILE = DataProfile(
    name="pgvector_normalized_cosine_f32/v1", identifier_representation="int64"
)
SUPPORTED = set(ENGINE_CAPABILITIES["pgvector"]["checkpoint_fields"])
PROFILE = RuntimeProfile(
    name="pgvector_same_execution_v4/v1",
    features={
        n: FeatureDefinition(**vars(f), provenance="server_observed")
        for n, f in FEATURES.items()
        if n in SUPPORTED
    },
    collection_groups=(
        "basic",
        "work",
        "filters",
        "progress",
        "queue",
        "queue_quantiles",
        "pgvector_executor",
        "distances",
    ),
    checkpoint_interval=64,
    checkpoint_semantics=(
        "multiples of 64 physical layer-zero distances at completed expansion boundaries"
    ),
    stopping_scope="selected_index_search",
    work_unit="physical_layer0_distances",
    native_protocol="same_execution_v4",
    native_registry_hash=FEATURE_REGISTRY_HASH,
    guidance=(
        "Preserve source search settings. Initial graph searches have no executor "
        "feedback. Non-HNSW routes have no stopping opportunity. Only available "
        "observations from the selected index may stop its search."
    ),
    scripted_policy={
        "name": "qualified-results",
        "root": {
            "if": {"op": "gte", "args": [{"feature": "qualified_topk_count"}, {"feature": "k"}]},
            "then": "stop",
            "else": "continue",
        },
    },
)


# Separately versioned ablation, matching the predeclared learning study fingerprint.

PREDICATE_CONTEXT_PROFILE = PROFILE.model_copy(
    update={
        "name": PROFILE.name + "/predicate-context-v1",
        "features": {**PROFILE.features, CONTEXT_FEATURE.name: CONTEXT_FEATURE},
        "collection_groups": (*PROFILE.collection_groups, "query_context"),
        "native_registry_hash": CONTEXT_REGISTRY_HASH,
    }
)
