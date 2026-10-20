"""Validate and normalize bounded JSONL traces retrieved from engine volumes."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, get_args

from fannagent.api.primitives.data import Query
from fannagent.api.primitives.descriptors import predicate_structure
from fannagent.api.primitives.errors import ValidationError
from fannagent.api.primitives.hashing import stable_hash

from .context import ExecutionContext
from .features import (
    ENGINE_CAPABILITIES,
    FEATURE_PROFILE,
    AvailabilityReason,
    registry_for,
)
from .query_context import predicate_threshold
from .trace import CheckpointRecord, ExecutionTrace, TraceFeature


def feature_set_hash(groups: list[str]) -> str:
    profile = (
        FEATURE_PROFILE + "/predicate-context-v1" if "query_context" in groups else FEATURE_PROFILE
    )
    return stable_hash({"profile": profile, "groups": sorted(groups)})


def normalize_engine_trace(
    path: Path,
    *,
    descriptor: dict[str, Any],
    backend: str,
    query: Query,
    context: ExecutionContext,
    nonce: str,
    dataset_hash: str,
    index_hash: str,
    engine_build_hash: str,
    index_parameters: dict[str, Any] | None = None,
    completion: dict[str, Any] | None = None,
) -> ExecutionTrace:
    registry_hash, definitions = registry_for(context.feature_groups)
    if descriptor.get("file") != f"{nonce}.jsonl":
        raise ValidationError("engine trace filename does not match the request nonce")
    if descriptor.get("feature_registry_hash") != registry_hash:
        raise ValidationError("engine trace registry hash mismatch")
    expected_set = feature_set_hash(context.feature_groups)
    if descriptor.get("feature_set_hash") != expected_set:
        raise ValidationError("engine trace feature set hash mismatch")
    size = path.stat().st_size
    if size != descriptor.get("bytes") or size > context.trace_max_bytes:
        raise ValidationError("engine trace size differs from its bounded descriptor")
    checkpoints: list[CheckpointRecord] = []
    terminal: dict[str, Any] | None = None
    events: list[dict[str, Any]] = []
    previous_sequence = 0
    previous_observation = 0
    for line_no, line in enumerate(path.read_text().splitlines(), start=1):
        try:
            record = json.loads(line)
            sequence = record.get("sequence", line_no)
            if (
                isinstance(sequence, bool)
                or not isinstance(sequence, int)
                or sequence <= previous_sequence
            ):
                raise ValueError("event sequence is not strictly increasing")
            previous_sequence = sequence
            if record.get("request_nonce", nonce) != nonce:
                raise ValueError("event request nonce mismatch")
            if record.get("feature_registry_hash", registry_hash) != registry_hash:
                raise ValueError("event feature registry mismatch")
            if record["type"] == "checkpoint":
                if terminal is not None:
                    raise ValueError("checkpoint follows terminal record")
                raw_features = record["features"]
                if not isinstance(raw_features, dict):
                    raise ValueError("checkpoint features must be an object")
                if "query_context" in context.feature_groups:
                    value = raw_features.get("query_predicate_threshold")
                    if type(value) is not int or value != predicate_threshold(query.model_dump()):
                        raise ValueError(
                            "native predicate threshold disagrees with the actual query"
                        )
                raw_availability = record.get("availability", {})
                if not isinstance(raw_availability, dict):
                    raise ValueError("availability reasons must be an object")
                available: dict[str, TraceFeature] = {}
                supported = set(ENGINE_CAPABILITIES[backend]["checkpoint_fields"])
                if "query_context" in context.feature_groups:
                    supported.add("query_predicate_threshold")
                for name, definition in definitions.items():
                    if definition.stage != "runtime":
                        continue
                    if name in raw_features:
                        if name in raw_availability:
                            raise ValueError(f"available feature {name} also has a reason")
                        value = raw_features[name]
                        if isinstance(value, bool) or not isinstance(value, (int, float)):
                            raise ValueError(f"feature {name} is not numeric")
                        if definition.kind == "int" and (not isinstance(value, int) or value < 0):
                            raise ValueError(f"feature {name} is not a nonnegative integer")
                        available[name] = TraceFeature(True, value)
                    else:
                        reason = raw_availability.get(name) or (
                            "not_enabled"
                            if definition.group not in context.feature_groups
                            else "unsupported_by_engine"
                            if name not in supported
                            else "route_not_applicable"
                            if name.startswith("acorn_") and "acorn" not in record["route"]
                            else "not_observed_yet"
                            if name.startswith("executor_tuple_") or name == "entry_distance"
                            else "not_observed_yet"
                            if name == "worst_topk_distance_improvement" and not checkpoints
                            else "incomplete_topk"
                            if name == "worst_topk_distance_improvement"
                            and (
                                raw_features.get("qualified_topk_count", 0) < query.k
                                or (checkpoints[-1].features["qualified_topk_count"].value or 0)
                                < query.k
                            )
                            else "not_observed_yet"
                            if name == "worst_topk_distance_improvement"
                            else "empty_population"
                            if name.startswith("frontier_distance_")
                            and raw_features.get("frontier_count") == 0
                            else "empty_population"
                            if name.startswith("qualified_topk_distance_")
                            and raw_features.get("qualified_topk_count") == 0
                            else "empty_population"
                            if name == "checked_match_fraction"
                            and raw_features.get("checked_unique_candidates") == 0
                            else "unsupported_population"
                        )
                        if reason not in get_args(AvailabilityReason):
                            raise ValueError(f"invalid unavailability reason for {name}: {reason}")
                        available[name] = TraceFeature(False, reason=reason)
                if set(raw_availability).difference(available):
                    raise ValueError("availability names contain unknown features")
                extra = set(raw_features).difference(available)
                if extra:
                    raise ValueError(f"unknown runtime trace features: {sorted(extra)}")
                index = int(record["index"])
                target = int(record["target"])
                actual = int(record["actual_layer0_distances"])
                for name, expected in (
                    ("checkpoint_index", index),
                    ("checkpoint_target", target),
                    ("checkpoint_overshoot", actual - target),
                    ("layer0_distance_evaluations", actual),
                ):
                    if name in raw_features and raw_features[name] != expected:
                        raise ValueError(f"{name} disagrees with checkpoint identity")
                checkpoints.append(
                    CheckpointRecord(
                        index=index,
                        target=target,
                        actual_layer0_distances=actual,
                        component_id=str(record["component_id"]),
                        route=str(record["route"]),
                        features=available,
                        decision=record["decision"],
                        sequence=sequence,
                        observation_watermark=int(
                            record.get("observation_watermark", previous_observation)
                        ),
                    )
                )
            elif record["type"] in {
                "component_start",
                "component_end",
                "final_merge",
                "executor_observation",
                "audit_discovery",
                "audit_membership",
                "audit_frontier_add",
                "audit_frontier_remove",
                "audit_frontier_reset",
                "audit_identity",
                "audit_tuple_membership",
                "audit_identity_status",
            }:
                if terminal is not None:
                    raise ValueError("observation follows terminal record")
                if not isinstance(record.get("component_id"), str) or not record["component_id"]:
                    raise ValueError("observation is missing component identity")
                if record["type"] == "executor_observation":
                    previous_observation = sequence
                events.append({**record, "sequence": sequence})
            elif record["type"] == "terminal":
                if terminal is not None:
                    raise ValueError("duplicate terminal record")
                terminal = record
            else:
                raise ValueError("unknown engine trace record")
        except (KeyError, TypeError, ValueError) as exc:
            raise ValidationError(f"invalid engine trace line {line_no}: {exc}") from exc
    truncated = descriptor.get("truncated") is True
    if terminal is None and not truncated:
        raise ValidationError("complete engine trace has no terminal record")
    if terminal is None:
        terminal = {
            "type": "terminal",
            "sequence": previous_sequence + 1,
            "request_nonce": nonce,
            "feature_registry_hash": registry_hash,
            "component_id": "request",
            "trace_truncated": True,
            "missing_due_to_truncation": True,
            "completion_source": "response_telemetry" if completion is not None else "unavailable",
            **(completion or {}),
        }
    return ExecutionTrace(
        feature_registry_hash=registry_hash,
        backend=backend,
        query_id=query.id,
        query_hash=stable_hash(query.model_dump(mode="json")),
        predicate_structure=predicate_structure(query.filter),
        index_parameters=index_parameters or {},
        mode=context.mode.value,
        feature_groups=tuple(context.feature_groups),
        nonce=nonce,
        dataset_hash=dataset_hash,
        index_hash=index_hash,
        engine_build_hash=engine_build_hash,
        feature_set_hash=expected_set,
        checkpoints=tuple(checkpoints),
        events=tuple(events),
        terminal=terminal,
        truncated=truncated,
    )
