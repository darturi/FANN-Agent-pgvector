import json

import pytest
from fannagent.config import load_config
from fannagent.errors import AgentError
from fannagent.onboarding import initialize
from psycopg.conninfo import conninfo_to_dict

from fannagent_pgvector import security


def test_installed_template_is_valid_and_references_credentials(tmp_path):
    path = tmp_path / "pg.yaml"
    initialize("pgvector", path)
    config = load_config(path)
    assert config.backend.name == "pgvector"
    assert config.backend.options["target"]["connection_env"] == "FANNAGENT_DATABASE_URL"
    assert "password=" not in path.read_text()


def test_controller_routing_uses_owned_relay_without_rewriting_saved_dsn(monkeypatch):
    monkeypatch.setenv("FANNAGENT_CONTROLLER", "controller")
    label = "io.fannagent.run=run1"
    prepared = {
        "security": {"ingress_network": "ingress", "ingress_network_id": "net1", "proxy": "relay"}
    }
    memberships = {}
    calls = []

    def docker(*args):
        calls.append(args)
        if args[:2] == ("network", "connect"):
            memberships["ingress"] = {"NetworkID": "net1"}
            return ""
        if args[:2] == ("network", "inspect"):
            return json.dumps([{"Name": "ingress", "Labels": {"io.fannagent.run": "run1"}}])
        if args[-1] == "controller":
            return json.dumps(
                [
                    {
                        "Config": {"Labels": {"io.fannagent.controller": "1"}},
                        "NetworkSettings": {"Networks": memberships},
                    }
                ]
            )
        return json.dumps(
            [
                {
                    "Config": {"Labels": {"io.fannagent.run": "run1"}},
                    "NetworkSettings": {
                        "Networks": {"ingress": {"NetworkID": "net1", "IPAddress": "172.20.1.3"}}
                    },
                }
            ]
        )

    saved = (
        "host=127.0.0.1 hostaddr=127.0.0.1 port=12345 password=secret require_auth=scram-sha-256"
    )
    routed = security.controller_dsn(saved, prepared, {"label": label}, docker)
    values = conninfo_to_dict(routed)
    assert values["host"] == values["hostaddr"] == "172.20.1.3"
    assert values["port"] == "5432"
    assert values["require_auth"] == "scram-sha-256"
    assert conninfo_to_dict(saved)["port"] == "12345"
    assert ("network", "connect", "ingress", "controller") in calls


def test_unlabelled_controller_is_refused(monkeypatch):
    monkeypatch.setenv("FANNAGENT_CONTROLLER", "untrusted")
    with pytest.raises(AgentError, match="labelled"):
        security.controller_dsn(
            "host=127.0.0.1", {}, {}, lambda *args: json.dumps([{"Config": {"Labels": {}}}])
        )
