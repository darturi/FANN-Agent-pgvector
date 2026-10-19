from types import SimpleNamespace

import pytest
from fannagent.broker import Tools
from fannagent.budget import Budget
from fannagent.config import ResearchConfig, RunConfig
from fannagent.controller import open_run
from fannagent.snapshot import Snapshot


def prepared_inspector(tmp_path, monkeypatch, source):
    config = RunConfig(
        backend={
            "name": "pgvector",
            "options": {
                "target": {
                    "schema_name": "agent fixture",
                    "resource": "Documents",
                    "id_column": "Document Key",
                    "vector_column": "Embedding Value",
                }
            },
        },
        model={"ceiling_usd": "1"},
    )
    config, store, backend = open_run(tmp_path / "run", config)
    backend.native.store.set("source_manifest", source)
    backend.native.store.set("prepared", {"qualified": True})

    def unexpected_source():
        pytest.fail("prepared inspection must use the saved source manifest")

    monkeypatch.setattr(backend.native, "_source", unexpected_source)
    return config, store, backend


@pytest.mark.parametrize("mode", [None, "guided"])
def test_pgvector_startup_summary_from_saved_manifest(tmp_path, monkeypatch, mode):
    source = {
        "backend": "pgvector",
        "compatible": True,
        "versions": {
            "server_version": "17.11",
            "vector_version": "0.8.6",
            "system_identifier": "123",
            "role": "source-owner",
        },
        "index": {
            "relname": "documents_hnsw",
            "amname": "hnsw",
            "column_name": "Embedding Value",
            "opcname": "vector_cosine_ops",
            "definition": 'CREATE INDEX documents_hnsw ON "agent fixture"."Documents" '
            'USING hnsw ("Embedding Value" vector_cosine_ops) WITH (m=16)',
            "oid": 123,
            "filepath": "base/5/123",
            "bytes": 10000,
        },
        "settings": {"hnsw.ef_search": "40", "hnsw.iterative_scan": "strict_order"},
        "guidance": "Preserve default search settings.",
        "extensions": [{"extname": "unrelated", "extversion": "1"}],
        "prerequisites": ["physical backup"],
    }
    config, store, backend = prepared_inspector(tmp_path, monkeypatch, source)
    if mode:
        config.research = ResearchConfig(mode=mode)
        store.set("config", config.public())
    inspection = backend.inspect_target()
    summary = inspection["startup_summary"]
    assert summary == {
        "target": {
            "schema": "agent fixture",
            "table": "Documents",
            "identifier_column": "Document Key",
            "vector_column": "Embedding Value",
        },
        "versions": {"server_version": "17.11", "vector_version": "0.8.6"},
        "index": {
            "name": "documents_hnsw",
            "type": "hnsw",
            "vector_column": "Embedding Value",
            "operator_class": "vector_cosine_ops",
            "definition": source["index"]["definition"],
        },
        "settings": source["settings"],
        "guidance": source["guidance"],
    }
    assert {k: v for k, v in inspection.items() if k != "startup_summary"} == source
    assert backend.native.store.get("source_manifest") == source
    assert "startup_summary" not in backend.native._inspection
    assert backend.inspect_target() == inspection
    snapshot = Snapshot(
        [{"source_id": 7, "vector": [1.0, 0.0], "metadata": {"Category Value": "a"}}],
        [{"name": "Category Value", "type": "string"}],
        backend.data_profile,
    )
    study = SimpleNamespace(
        backend=backend,
        store=store,
        snapshot=snapshot,
        checkpoint_policy_hash=lambda: None,
        development=[],
        config=config,
    )
    tools = Tools(study, Budget(store, config.model))
    context = tools.startup_context()
    assert context["backend"] == "pgvector"
    assert context["target"] == summary
    assert context["dataset"]["fields"][0]["logical"] == "m_000000"
    assert (context.get("research") or {}).get("mode") == mode
    assert tools.call("artifact", {"hash": context["inspection_artifact"]})["target"] == inspection


@pytest.mark.parametrize("source", [{}, {"index": None}, {"index": {"relname": "hnsw"}}])
def test_pgvector_summary_handles_absent_optional_fields(tmp_path, monkeypatch, source):
    _, _, backend = prepared_inspector(tmp_path, monkeypatch, source)
    summary = backend.inspect_target()["startup_summary"]
    assert summary["versions"] == {}
    assert summary["index"] == ({"name": "hnsw"} if source.get("index") else None)
    assert "settings" not in summary
    assert "guidance" not in summary
