"""Acknowledged control batches using sequential PostgreSQL simple queries."""

from __future__ import annotations

import psycopg
from fannagent.api import AgentError
from psycopg import pq


def _command(cursor, expected):
    if cursor.statusmessage != expected or cursor.description is not None:
        raise AgentError("control batch command acknowledgement mismatch")


def _scalar(cursor):
    if cursor.statusmessage != "SELECT 1" or not cursor.description or len(cursor.description) != 1:
        raise AgentError("control batch scalar acknowledgement missing")
    row = cursor.fetchone()
    if row is None or len(row) != 1 or cursor.fetchone() is not None:
        raise AgentError("control batch scalar acknowledgement shape mismatch")
    return row[0]


def begin_execution_batch(conn, statement, params):
    # ClientCursor adapts values; never interpolate caller values into SQL text.
    # Only transaction control and the existing initialization SELECT are batched.
    with psycopg.ClientCursor(conn) as cursor:
        cursor.execute("BEGIN; " + statement, params)
        _command(cursor, "BEGIN")
        if not cursor.nextset():
            raise AgentError("control batch initialization acknowledgement missing")
        ack = _scalar(cursor)
        if cursor.nextset():
            raise AgentError("control batch has unexpected initialization results")
    if conn.pgconn.transaction_status != pq.TransactionStatus.INTRANS:
        raise AgentError("control batch did not enter a transaction")
    return ack


def complete_execution_batch(conn, nonce, count):
    with psycopg.ClientCursor(conn) as cursor:
        cursor.execute("SELECT fannagent.complete(%s,%s); COMMIT", (nonce, count))
        telemetry = _scalar(cursor)
        if not cursor.nextset():
            raise AgentError("control batch commit acknowledgement missing")
        _command(cursor, "COMMIT")
        if cursor.nextset():
            raise AgentError("control batch has unexpected completion results")
    if conn.pgconn.transaction_status != pq.TransactionStatus.IDLE:
        raise AgentError("control batch did not leave an idle connection")
    return telemetry
