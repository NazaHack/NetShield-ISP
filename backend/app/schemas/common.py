"""Schemas shared across resources."""

from __future__ import annotations

from typing import Annotated, Generic, TypeVar

from fastapi import Query
from pydantic import BaseModel, ConfigDict, Field

ItemT = TypeVar("ItemT")

#: Upper bound on a page size. A caller cannot ask for an unbounded result set,
#: which keeps one request from pinning a worker and a database connection.
MAX_PAGE_SIZE = 200
DEFAULT_PAGE_SIZE = 50


class Pagination(BaseModel):
    """Page window requested by the caller."""

    model_config = ConfigDict(frozen=True)

    limit: int = Field(default=DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE)
    offset: int = Field(default=0, ge=0)


def pagination_params(
    limit: Annotated[int, Query(ge=1, le=MAX_PAGE_SIZE, description="Rows per page.")] = (
        DEFAULT_PAGE_SIZE
    ),
    offset: Annotated[int, Query(ge=0, description="Rows to skip.")] = 0,
) -> Pagination:
    """FastAPI dependency turning query parameters into a bounded page window."""
    return Pagination(limit=limit, offset=offset)


class Page(BaseModel, Generic[ItemT]):
    """One page of results, with enough context to request the next."""

    model_config = ConfigDict(frozen=True)

    items: list[ItemT]
    total: int = Field(description="Rows matching the query, ignoring the page window.")
    limit: int
    offset: int
