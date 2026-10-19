from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any, Literal

from .features import FEATURE_REGISTRY_HASH, FEATURES


@dataclass(frozen=True)
class TraceFeature:
    available: bool
    value: int | float | None = None
    reason: str | None = None

    def __post_init__(self) -> None:
        if self.available != (self.value is not None):
            raise ValueError("available feature requires a value")
        if self.available and self.reason is not None:
            raise ValueError("available feature cannot have an unavailability reason")
        if not self.available and not self.reason:
            raise ValueError("unavailable feature requires a reason")
        if isinstance(self.value, float) and not math.isfinite(self.value):
            raise ValueError("nonfinite trace feature")


@dataclass(frozen=True)
class CheckpointRecord:
    index: int
    target: int
    actual_layer0_distances: int
    component_id: str
    route: str
    features: dict[str, TraceFeature]
    decision: Literal["continue", "stop", "noop", "fixed_budget"]
    sequence: int = 0
    observation_watermark: int = 0

    def __post_init__(self) -> None:
        if self.index <= 0 or self.target <= 0 or self.target % 64 != 0:
            raise ValueError("invalid checkpoint target")
        if self.actual_layer0_distances < self.target:
            raise ValueError("checkpoint precedes its target")
        for name in self.features:
            definition = FEATURES.get(name)
            if definition is None or definition.stage != "runtime":
                raise ValueError(f"invalid runtime trace feature: {name}")


@dataclass(frozen=True)
class ExecutionTrace:
    backend: str
    query_id: str
    nonce: str
    dataset_hash: str
    index_hash: str
    engine_build_hash: str
    feature_set_hash: str
    checkpoints: tuple[CheckpointRecord, ...]
    terminal: dict[str, Any]
    events: tuple[dict[str, Any], ...] = ()
    query_hash: str | None = None
    predicate_structure: dict[str, Any] = field(default_factory=dict)
    index_parameters: dict[str, Any] = field(default_factory=dict)
    mode: str | None = None
    feature_groups: tuple[str, ...] = ()
    truncated: bool = False
    feature_registry_hash: str = FEATURE_REGISTRY_HASH
    protocol: Literal["same_execution_v4"] = "same_execution_v4"
    configuration_fingerprint: str | None = None
    index_instance_id: str | None = None

    def __post_init__(self) -> None:
        if self.feature_registry_hash != FEATURE_REGISTRY_HASH:
            raise ValueError("trace feature registry hash mismatch")
        if not self.nonce or not self.dataset_hash or not self.index_hash:
            raise ValueError("trace is missing execution identity")
        previous = 0
        previous_target = 0
        previous_actual = 0
        previous_sequence = 0
        event_sequences = [event["sequence"] for event in self.events]
        if any(not isinstance(sequence, int) or sequence <= 0 for sequence in event_sequences):
            raise ValueError("trace event sequence must be a positive integer")
        if event_sequences != sorted(set(event_sequences)):
            raise ValueError("trace events are not strictly ordered")
        for record in self.checkpoints:
            if record.index <= previous or record.target <= previous_target:
                raise ValueError("trace checkpoints are not strictly ordered")
            if record.actual_layer0_distances < previous_actual:
                raise ValueError("trace layer-zero work decreased")
            if record.sequence and record.sequence <= previous_sequence:
                raise ValueError("checkpoint event sequence decreased")
            if record.observation_watermark > record.sequence:
                raise ValueError("checkpoint includes future observations")
            previous = record.index
            previous_target = record.target
            previous_actual = record.actual_layer0_distances
            previous_sequence = record.sequence
