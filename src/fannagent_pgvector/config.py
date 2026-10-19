from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Target(Strict):
    resource: str = Field(min_length=1)
    schema_name: str = "public"
    id_column: str = "id"
    vector_column: str = "embedding"
    metadata_columns: list[str] | None = None
    index: str | None = None
    connection_env: str = "FANNAGENT_DATABASE_URL"

    @property
    def backend(self):
        return "pgvector"


class Copy(Strict):
    backup: Path | None = None
    replication_env: str | None = None
    image: str = "fannagent/pgvector:0.8.6-secure-v1"
    architecture: Literal["arm64", "amd64"] | None = None


class Options(Strict):
    target: Target
    copy_config: Copy = Field(default_factory=Copy, alias="copy")

    @property
    def copy(self):
        return self.copy_config
