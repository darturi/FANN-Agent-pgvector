"""Checked common-query path; general inputs retain the shared validator."""

from __future__ import annotations

import numpy as np
from fannagent.api.primitives.data import Query
from fannagent.api.primitives.errors import ValidationError
from fannagent.api.primitives.filters import validate_filter
from pydantic import ValidationError as ModelValidationError


def validate_query(snapshot, raw):
    # Specialize only inline vectors and plain, single-leaf JSON predicates.
    # Complex predicates, non-JSON Python objects and invalid inputs use the
    # original validator, including its exact error classification and details.
    if (
        type(raw) is not dict
        or set(raw) - {"schema_version", "id", "vector", "k", "filter"}
        or type(raw.get("vector")) is not list
    ):
        return snapshot.query(raw)
    predicate = raw.get("filter")
    if predicate is not None:
        if (
            type(predicate) is not dict
            or type(predicate.get("field")) is not str
            or type(predicate.get("op")) is not str
        ):
            return snapshot.query(raw)
        value = predicate.get("value")
        scalars = (str, int, float, bool, type(None))
        if type(value) not in scalars and not (
            type(value) is list and all(type(v) in scalars for v in value)
        ):
            return snapshot.query(raw)
        predicate = dict(predicate)
        predicate["field"] = snapshot.reverse_fields.get(predicate["field"], predicate["field"])
        if type(value) is list:
            predicate["value"] = list(value)
    try:
        query = Query.model_validate({"schema_version": 2, **raw, "filter": predicate})
        with np.errstate(over="ignore", invalid="ignore"):
            vector = np.asarray(query.vector, dtype=np.float32)
        if vector.shape != (snapshot.data.manifest.dimension,) or not np.isfinite(vector).all():
            return snapshot.query(raw)
        # Shared Snapshot.query uses np.isclose(norm, 1, atol=1e-5), with
        # NumPy's default rtol=1e-5: the allowed absolute error is 2e-5.
        # Keeping the same float32 norm avoids the scalar np.isclose machinery.
        if abs(float(np.linalg.norm(vector)) - 1.0) > 2e-5:
            return snapshot.query(raw)
        if query.k > snapshot.profile.max_k:
            return snapshot.query(raw)
        validate_filter(query.filter, snapshot.data.manifest)
        if predicate is not None:
            field = next(f for f in snapshot.fields if f["logical"] == predicate["field"])
            if field.get("allowed_ops") and predicate["op"] not in field["allowed_ops"]:
                return snapshot.query(raw)
    except (ModelValidationError, ValidationError):
        return snapshot.query(raw)
    # Query contains only primitive JSON values on this path. Own the vector
    # and predicate above without serializing/copying the numeric vector twice.
    result = {
        "schema_version": query.schema_version,
        "id": query.id,
        "vector": query.vector,
        "k": query.k,
    }
    if query.filter is not None:
        result["filter"] = query.filter
    return result
