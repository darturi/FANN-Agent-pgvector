import json
from importlib.resources import files
from types import SimpleNamespace
from typing import Literal

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
