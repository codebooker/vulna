"""Schemas for system and health endpoints."""

from __future__ import annotations

from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    """Structured health payload."""

    status: str = Field(description="Overall health status", examples=["ok"])
    service: str = Field(description="Service name", examples=["VulnaDash"])
    version: str = Field(description="Running version", examples=["0.1.0"])


class SystemInfoResponse(BaseModel):
    """Non-sensitive information about the running service."""

    service: str = Field(description="Service name")
    version: str = Field(description="Running version")
    environment: str = Field(description="Deployment environment", examples=["development"])
    api_version: str = Field(description="REST API version", examples=["v1"])
