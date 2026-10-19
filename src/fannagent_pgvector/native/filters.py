from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from psycopg import sql


def postgres_filter(
    expr: dict[str, Any] | None, physical_fields: Mapping[str, str]
) -> tuple[sql.Composable, list[Any]]:
    if expr is None:
        return sql.SQL("TRUE"), []
    if "and" in expr or "or" in expr:
        op = "and" if "and" in expr else "or"
        rendered = [postgres_filter(child, physical_fields) for child in expr[op]]
        glue = sql.SQL(" AND " if op == "and" else " OR ")
        return (
            sql.SQL("(") + glue.join(item[0] for item in rendered) + sql.SQL(")"),
            [value for item in rendered for value in item[1]],
        )
    if "not" in expr:
        rendered, params = postgres_filter(expr["not"], physical_fields)
        return sql.SQL("NOT (") + rendered + sql.SQL(")"), params
    operator = {
        "eq": sql.SQL("="),
        "lt": sql.SQL("<"),
        "lte": sql.SQL("<="),
        "gt": sql.SQL(">"),
        "gte": sql.SQL(">="),
    }
    identifier = sql.Identifier(physical_fields[expr["field"]])
    if expr["op"] in {"is_null", "is_not_null"}:
        return identifier + sql.SQL(" IS NULL" if expr["op"] == "is_null" else " IS NOT NULL"), []
    if expr["op"] == "in":
        return identifier + sql.SQL(" = ANY(%s)"), [expr["value"]]
    return identifier + sql.SQL(" ") + operator[expr["op"]] + sql.SQL(" %s"), [expr["value"]]
