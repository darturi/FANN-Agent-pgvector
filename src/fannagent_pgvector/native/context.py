from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class PolicyMode(StrEnum):
    STOCK_NATIVE = "stock_native"
    POLICY_PLACEHOLDER = "policy_placeholder"
    NATIVE = "native"
    POLICY_NOOP = "policy_noop"
    FIXED_BUDGET = "fixed_budget"
    POLICY_AGENT = "policy_agent"


class TraceLevel(StrEnum):
    OFF = "off"
    SUMMARY = "summary"
    CHECKPOINTS = "checkpoints"


class ObservationSource(StrEnum):
    ADAPTER_DECLARED = "adapter_declared"
    SERVER_OBSERVED = "server_observed"
    UNOBSERVED = "unobserved"


class ExecutionPath(StrEnum):
    STOCK_ROUTE_UNOBSERVED = "stock_route_unobserved"
    POSTGRESQL_PGVECTOR_HNSW = "postgresql_pgvector_hnsw"
    POSTGRESQL_NON_HNSW = "postgresql_non_hnsw"
    ELASTICSEARCH_LUCENE_HNSW = "elasticsearch_lucene_hnsw"
    ELASTICSEARCH_LUCENE_EXACT = "elasticsearch_lucene_exact"
    ELASTICSEARCH_LUCENE_MIXED = "elasticsearch_lucene_mixed"
    WEAVIATE_HNSW_SWEEPING = "weaviate_hnsw_sweeping"
    WEAVIATE_HNSW_ACORN = "weaviate_hnsw_acorn"
    WEAVIATE_FLAT = "weaviate_flat"
    WEAVIATE_MIXED = "weaviate_mixed"


class StopReason(StrEnum):
    NATIVE_REASON_UNOBSERVED = "native_reason_unobserved"
    NATIVE_CONVERGENCE = "native_convergence"
    NATIVE_LIMIT = "native_limit"
    POLICY_STOP = "policy_stop"
    FIXED_BUDGET_STOP = "fixed_budget_stop"
    EXHAUSTED = "exhausted"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"
    ERROR = "error"


class ExecutionContext(StrictModel):
    mode: PolicyMode = PolicyMode.STOCK_NATIVE
    feature_profile: Literal["portable_fann_v2"] = "portable_fann_v2"
    policy_hash: str | None = None
    policy_role: Literal["always_continue", "treatment"] | None = None
    fixed_budget: int | None = Field(default=None, gt=0)
    experiment_profile: Literal["main", "controlled_hnsw"] = "main"
    trace_level: TraceLevel = TraceLevel.OFF
    policy_feature_profile: Literal["fann_features_v1", "fann_features_v2"] | None = None
    feature_groups: list[str] = Field(default_factory=list)
    trace_max_bytes: int = Field(default=64 * 1024 * 1024, gt=0)
    audit_membership: bool = False

    @model_validator(mode="after")
    def validate_mode_settings(self) -> ExecutionContext:
        if self.mode == PolicyMode.POLICY_AGENT and self.policy_hash is None:
            raise ValueError("policy_agent mode requires policy_hash")
        if self.mode != PolicyMode.POLICY_AGENT and self.policy_hash is not None:
            raise ValueError("policy_hash is only valid in policy_agent mode")
        if self.mode == PolicyMode.POLICY_AGENT and self.policy_role is None:
            raise ValueError("policy_agent mode requires policy_role")
        if self.mode != PolicyMode.POLICY_AGENT and self.policy_role is not None:
            raise ValueError("policy_role is only valid in policy_agent mode")
        if self.mode == PolicyMode.FIXED_BUDGET and self.fixed_budget is None:
            raise ValueError("fixed_budget mode requires fixed_budget")
        if self.mode != PolicyMode.FIXED_BUDGET and self.fixed_budget is not None:
            raise ValueError("fixed_budget is only valid in fixed_budget mode")
        if self.feature_groups and self.policy_feature_profile is None:
            raise ValueError("feature_groups require a policy_feature_profile")
        if len(self.feature_groups) != len(set(self.feature_groups)):
            raise ValueError("feature_groups must be unique")
        if self.audit_membership and (
            self.mode == PolicyMode.NATIVE or self.trace_level != TraceLevel.CHECKPOINTS
        ):
            raise ValueError("membership audit requires an observed checkpoint trace")
        return self
