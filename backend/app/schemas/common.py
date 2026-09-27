from typing import Generic, TypeVar

from pydantic import BaseModel, Field

T = TypeVar("T")


class PaginationParams(BaseModel):
    skip: int = Field(0, ge=0)
    limit: int = Field(50, ge=1, le=500)


class PaginatedResponse(BaseModel, Generic[T]):
    items: list[T]
    total: int
    page: int
    size: int
    pages: int


class MessageSchema(BaseModel):
    detail: str
