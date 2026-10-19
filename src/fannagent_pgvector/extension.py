from importlib.metadata import version
from pathlib import Path

from fannagent.api import ExtensionManifest

from .config import Options
from .profiles import DATA_PROFILE, PROFILE


class PgvectorExtension:
    def configuration_template(self):
        import os
        from importlib.resources import files

        content = files("fannagent_pgvector").joinpath("assets/pgvector.yaml").read_text()
        image = os.environ.get("FANNAGENT_PGVECTOR_IMAGE")
        if image:
            import yaml

            value = yaml.safe_load(content)
            value["backend"]["options"]["copy"]["image"] = image
            return yaml.safe_dump(value, sort_keys=False)
        return content

    def installation_checks(self, options, config, *, check_source=False):
        from .setup import installation_checks

        return installation_checks(options, config, check_source=check_source)

    def manifest(self):
        return ExtensionManifest(
            "pgvector",
            "fannagent-pgvector",
            version("fannagent-pgvector"),
            (1,),
            Options.model_json_schema(by_alias=True),
            DATA_PROFILE,
            PROFILE,
            (
                "snapshot only",
                "normalized cosine float32 in memory",
                "PostgreSQL 17.11 / pgvector 0.8.6",
                "local architecture requires native qualification",
                "mandatory SCRAM copy authentication and no outbound connections",
            ),
        )

    def normalize_options(self, options: dict, origin: Path):
        normalized = Options.model_validate(options)
        if normalized.copy.backup and not normalized.copy.backup.is_absolute():
            normalized.copy.backup = (origin / normalized.copy.backup).resolve()
        return normalized

    def create(self, options, context):
        from .integration import PgvectorBackend

        return PgvectorBackend(options, context)


extension = PgvectorExtension()
