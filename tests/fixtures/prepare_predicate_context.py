"""Assemble the pinned patch series for the cached, offline native fixture build."""

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

engine = Path(__file__).parents[2] / "src/fannagent_pgvector/engine"
target = Path(sys.argv[1]).resolve()
if target.exists():
    raise SystemExit("Use a new directory; existing qualification inputs are preserved")
(target / "engine-source").mkdir(parents=True)
for item in json.loads((engine / "provenance.json").read_text())["patches"]:
    path = engine / item["path"]
    assert hashlib.sha256(path.read_bytes()).hexdigest() == item["sha256"]
    subprocess.run(
        ["git", "apply", "--include=src/fannbench.c", "--include=src/fannbench.h", str(path)],
        cwd=target / "engine-source",
        env={**os.environ, "GIT_CEILING_DIRECTORIES": str(target)},
        check=True,
    )
(target / "PredicateContext.Dockerfile").write_bytes(
    (Path(__file__).with_name("predicate-context.Dockerfile")).read_bytes()
)
print(target)
