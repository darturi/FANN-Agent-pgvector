"""Two-exchange policy transport; the ANN SELECT keeps its ordinary SQL shape."""

from __future__ import annotations

import psycopg
from fannagent.api import AgentError
from psycopg import pq, sql

from .sequential import _command, _scalar


def begin_search_batch(conn, begin_sql, begin_params, statement, params, *, install=None):
    """Drain installation, BEGIN, nonce and search results before accepting rows.

    The server executes these commands sequentially. A late error invalidates
    the whole response; the caller closes the connection without replaying it.
    Completion still receives the actual observed row count in a second batch.
    """
    prefix = ""
    values = ()
    if install is not None:
        prefix = "SELECT fannagent.install_policy(%s,%s); "
        values = tuple(install)
    query = sql.SQL(prefix + "BEGIN; " + begin_sql + "; ") + (
        sql.SQL(statement) if isinstance(statement, str) else statement
    )
    with psycopg.ClientCursor(conn) as cursor:
        cursor.execute(query, (*values, *begin_params, *params))
        if install is not None:
            if _scalar(cursor) != install[0]:
                raise AgentError("policy installation hash mismatch")
            if not cursor.nextset():
                raise AgentError("fused batch BEGIN acknowledgement missing")
        _command(cursor, "BEGIN")
        if not cursor.nextset() or _scalar(cursor) != begin_params[3]:
            raise AgentError("query nonce acknowledgement mismatch")
        if not cursor.nextset():
            raise AgentError("fused batch search result missing")
        if not cursor.description or len(cursor.description) != 2:
            raise AgentError("fused batch search result shape mismatch")
        rows = cursor.fetchall()
        if cursor.statusmessage != "SELECT " + str(len(rows)):
            raise AgentError("fused batch search count acknowledgement mismatch")
        if cursor.nextset():
            raise AgentError("fused batch has unexpected search results")
    if conn.pgconn.transaction_status != pq.TransactionStatus.INTRANS:
        raise AgentError("fused batch did not enter a transaction")
    return rows
