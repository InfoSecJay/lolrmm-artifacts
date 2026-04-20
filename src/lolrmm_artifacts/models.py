"""Pydantic models for LOLRMM YAML schema.

Designed to be permissive — LOLRMM YAMLs diverge from their published spec in
practice (e.g. Detections[] use `Sigma` not `Link`, PEMetadata may be dict or
list, Free/Verification are bool|str|''). Extra fields are kept to avoid
silently dropping data.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class _Base(BaseModel):
    model_config = ConfigDict(extra="allow", populate_by_name=True, str_strip_whitespace=True)


class PEMetadataEntry(_Base):
    Filename: str | None = None
    OriginalFileName: str | None = None
    Description: str | None = None
    Product: str | None = None


class ToolDetails(_Base):
    Website: str | None = None
    PEMetadata: list[PEMetadataEntry] = Field(default_factory=list)
    Privileges: str | None = None
    Free: bool | str | None = None
    Verification: bool | str | None = None
    SupportedOS: list[str] = Field(default_factory=list)
    Capabilities: list[str] = Field(default_factory=list)
    Vulnerabilities: list[str] = Field(default_factory=list)
    InstallationPaths: list[str] = Field(default_factory=list)

    @field_validator("PEMetadata", mode="before")
    @classmethod
    def _pe_metadata_any(cls, v: Any) -> list[Any]:
        if v is None or v == "":
            return []
        if isinstance(v, dict):
            return [v]
        if isinstance(v, list):
            return v
        return []

    @field_validator("SupportedOS", "Capabilities", "Vulnerabilities", "InstallationPaths", mode="before")
    @classmethod
    def _none_to_empty_list(cls, v: Any) -> list[Any]:
        if v is None or v == "":
            return []
        return v


class DiskArtifact(_Base):
    File: str
    Description: str | None = None
    OS: str | None = None
    Type: str | None = None  # 'Regex' sometimes appears
    Example: list[str] = Field(default_factory=list)

    @field_validator("Example", mode="before")
    @classmethod
    def _none_to_empty_list(cls, v: Any) -> list[Any]:
        return [] if v is None else v


class EventLogArtifact(_Base):
    EventID: int | str | None = None
    ProviderName: str | None = None
    LogFile: str | None = None
    ServiceName: str | None = None
    ImagePath: str | None = None
    CommandLine: str | None = None
    Description: str | None = None


class RegistryArtifact(_Base):
    Path: str
    Description: str | None = None


class NetworkArtifact(_Base):
    Description: str | None = None
    Domains: list[str] = Field(default_factory=list)
    Ports: list[int | str] = Field(default_factory=list)

    @field_validator("Domains", "Ports", mode="before")
    @classmethod
    def _none_to_empty_list(cls, v: Any) -> list[Any]:
        return [] if v is None else v


class OtherArtifact(_Base):
    Type: str | None = None
    Value: str | None = None


class ToolArtifacts(_Base):
    Disk: list[DiskArtifact] = Field(default_factory=list)
    EventLog: list[EventLogArtifact] = Field(default_factory=list)
    Registry: list[RegistryArtifact] = Field(default_factory=list)
    Network: list[NetworkArtifact] = Field(default_factory=list)
    Other: list[OtherArtifact] = Field(default_factory=list)

    @field_validator("Disk", "EventLog", "Registry", "Network", "Other", mode="before")
    @classmethod
    def _none_to_empty_list(cls, v: Any) -> list[Any]:
        return [] if v is None else v


class Detection(_Base):
    """LOLRMM YAMLs consistently use `Sigma` as the URL field; the official
    spec calls it `Link`. Accept either and expose `url`.
    """

    Sigma: str | None = None
    Link: str | None = None
    Name: str | None = None
    Description: str | None = None
    author: str | None = None

    @property
    def url(self) -> str | None:
        return self.Sigma or self.Link


class AcknowledgementEntry(_Base):
    Person: str | None = None
    Handle: str | None = None


class Tool(_Base):
    Name: str
    Category: str
    Description: str
    Author: str | None = None
    Created: str | None = None
    LastModified: str | None = None
    Details: ToolDetails = Field(default_factory=ToolDetails)
    Artifacts: ToolArtifacts = Field(default_factory=ToolArtifacts)
    Detections: list[Detection] = Field(default_factory=list)
    References: list[str] = Field(default_factory=list)
    Acknowledgement: list[AcknowledgementEntry] = Field(default_factory=list)

    # Populated by the loader so every record knows its source filename.
    source_file: str | None = None

    @field_validator("Details", mode="before")
    @classmethod
    def _details_default(cls, v: Any) -> Any:
        return v if v else {}

    @field_validator("Artifacts", mode="before")
    @classmethod
    def _artifacts_default(cls, v: Any) -> Any:
        return v if v else {}

    @field_validator("Detections", "References", "Acknowledgement", mode="before")
    @classmethod
    def _none_to_empty_list(cls, v: Any) -> list[Any]:
        return [] if v is None else v

    @property
    def slug(self) -> str:
        if self.source_file:
            return self.source_file.rsplit("/", 1)[-1].removesuffix(".yaml").removesuffix(".yml")
        return self.Name.lower().replace(" ", "_")
