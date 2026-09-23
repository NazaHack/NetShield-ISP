"""Schemas for the health and service-metadata endpoints."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class ComponentStatus(StrEnum):
    """Health of a single downstream dependency."""

    UP = "up"
    DOWN = "down"


class DependencyHealth(BaseModel):
    """Result of probing one downstream dependency."""

    model_config = ConfigDict(frozen=True)

    name: str = Field(description="Dependency identifier, e.g. 'postgresql'.")
    status: ComponentStatus = Field(description="Whether the dependency answered.")
    latency_ms: float = Field(ge=0, description="Round-trip time of the probe.")
    detail: str | None = Field(
        default=None,
        description="Failure detail. Never contains credentials or DSNs.",
    )


class LivenessResponse(BaseModel):
    """Answer to 'is this process alive?'. Probes nothing downstream."""

    model_config = ConfigDict(frozen=True)

    status: ComponentStatus
    service: str
    version: str
    timestamp: datetime


class ReadinessResponse(BaseModel):
    """Answer to 'can this process serve traffic?'. Probes every dependency."""

    model_config = ConfigDict(frozen=True)

    status: ComponentStatus
    service: str
    version: str
    environment: str
    timestamp: datetime
    dependencies: list[DependencyHealth]
