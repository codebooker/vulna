"""Shared schema types: pagination and error envelope."""

from __future__ import annotations

from typing import Generic, TypeVar

from pydantic import BaseModel, Field

T = TypeVar("T")


class Page(BaseModel, Generic[T]):
    """A page of results with total count and paging parameters."""

    items: list[T]
    total: int = Field(description="Total number of matching records")
    limit: int = Field(description="Maximum number of items in this page")
    offset: int = Field(description="Number of items skipped before this page")


class Message(BaseModel):
    """A simple message response."""

    detail: str
