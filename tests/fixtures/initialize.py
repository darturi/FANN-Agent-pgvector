"""Initialize ONLY a new disposable stock fixture via FANNAGENT_FIXTURE_URL."""

import os

import numpy as np
import psycopg

with psycopg.connect(os.environ["FANNAGENT_FIXTURE_URL"], autocommit=True) as conn:
    conn.execute("CREATE EXTENSION vector")
    conn.execute('CREATE SCHEMA "agent fixture"')
    conn.execute(
        'CREATE TABLE "agent fixture"."Documents" ('
        '"Document Key" bigint PRIMARY KEY, "Embedding Vector" vector(12) NOT NULL,'
        '"Category Value" text, rating integer)'
    )
    vectors = np.random.default_rng(11).normal(size=(3000, 12))
    vectors = (vectors / np.linalg.norm(vectors, axis=1)[:, None]).astype(np.float32)
    with conn.cursor().copy('COPY "agent fixture"."Documents" FROM STDIN') as copy:
        for i, vector in enumerate(vectors):
            copy.write_row(
                (
                    i - 2000,
                    "[" + ",".join(format(float(v), ".9g") for v in vector) + "]",
                    None if i % 17 == 0 else str(i % 5),
                    i,
                )
            )
    for identifier, vector in zip((-(2**63), 2**63 - 1), vectors[:2]):
        conn.execute(
            'INSERT INTO "agent fixture"."Documents" VALUES (%s,%s,NULL,0)',
            (identifier, "[" + ",".join(format(float(v), ".9g") for v in vector) + "]"),
        )
    conn.execute(
        'CREATE INDEX "Vectors HNSW" ON "agent fixture"."Documents" '
        'USING hnsw ("Embedding Vector" vector_cosine_ops)'
    )
    conn.execute('ANALYZE "agent fixture"."Documents"')
