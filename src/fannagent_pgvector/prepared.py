"""Private, content-addressed preparation. Never retain caller-owned policy data."""

from __future__ import annotations

import hashlib
import json
from collections import OrderedDict
from copy import deepcopy
from dataclasses import dataclass, field

from fannagent.api import AgentError, validate_policy
from fannagent.api.policy import PolicyArtifact
from fannagent.api.primitives.compiler import compile_tree
from fannagent.api.primitives.policy_tree import validate_node

from .native.transport import feature_set_hash


@dataclass(frozen=True)
class PreparedPolicy:
    artifact: PolicyArtifact
    policy_hash: str
    groups: tuple[str, ...]
    group_hash: str
    group_csv: str
    _bytecode: str | None = field(default=None, repr=False)

    @property
    def bytecode(self):
        # Compilation on a miss belongs to installation, inside the existing call timer.
        # This object is private and accessed under the backend operation lock.
        if self._bytecode is None:
            object.__setattr__(
                self, "_bytecode", compile_tree(self.artifact, header="FANNBENCH_POLICY_V2\t64")
            )
        return self._bytecode


class PreparedPolicyCache:
    def __init__(self, profile, *, limit=16, budget=2 * 1024 * 1024):
        self.profile = profile.model_copy(deep=True)
        self.identity = self.profile.fingerprint
        self.kinds = {name: feature.kind for name, feature in self.profile.runtime_features.items()}
        self.limit, self.budget = limit, budget
        self.entries = OrderedDict()
        self.bytes = 0

    def clear(self):
        self.entries.clear()
        self.bytes = 0

    @staticmethod
    def _plain_json(value):
        # JSON encoding loses tuple/list and integer/string-key distinctions.
        # Such inputs must not hit an entry validated from a different Python type.
        stack = [value]
        while stack:
            item = stack.pop()
            if type(item) is dict:
                if any(type(key) is not str for key in item):
                    return False
                stack.extend(item.values())
            elif type(item) is list:
                stack.extend(item)
            elif type(item) not in (str, int, float, bool, type(None)):
                return False
        return True

    @staticmethod
    def _prepared(artifact):
        groups = tuple(artifact.feature_groups)
        return PreparedPolicy(
            artifact,
            artifact.policy_hash,
            groups,
            feature_set_hash(groups),
            ",".join(sorted(groups)),
        )

    def prepare(self, raw):
        if not isinstance(raw, (dict, PolicyArtifact)):
            raise AgentError("invalid policy: policy must be an object")
        # Check bounds on the original tree before model dumping, copying or hashing.
        root = raw.root if isinstance(raw, PolicyArtifact) else raw.get("root")
        try:
            if not isinstance(root, (dict, str)):
                raise ValueError("policy root is required")
            validate_node(root, feature_kinds=self.kinds)
            value = raw.model_dump(mode="python") if isinstance(raw, PolicyArtifact) else raw
            owned = deepcopy(value)
            validate_node(owned.get("root"), feature_kinds=self.kinds)
            serialized = json.dumps(
                owned, allow_nan=False, sort_keys=True, separators=(",", ":")
            ).encode()
        except RecursionError:
            raise AgentError("invalid policy: payload is too deeply nested") from None
        except (TypeError, ValueError, OverflowError) as exc:
            raise AgentError(f"invalid policy: {exc}") from None
        if not self._plain_json(owned):
            # Preserve the original validator's Python-type semantics and own its data.
            return self._prepared(validate_policy(owned, self.profile))
        key = (self.identity, hashlib.sha256(serialized).digest())
        if key in self.entries:
            self.entries.move_to_end(key)
            return self.entries[key][0]
        # Validation uses the private snapshot, including provenance and group lists.
        artifact = validate_policy(owned, self.profile)
        prepared = self._prepared(artifact)
        size = len(serialized)
        if size <= self.budget and self.limit > 0:
            while self.entries and (
                len(self.entries) >= self.limit or self.bytes + size > self.budget
            ):
                _, (_, removed_size) = self.entries.popitem(last=False)
                self.bytes -= removed_size
            self.entries[key] = (prepared, size)
            self.bytes += size
        return prepared
