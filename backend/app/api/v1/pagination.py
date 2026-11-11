"""Pagination shared by every list endpoint: ?page=1&size=50 -> {items, total, page, size}."""
from dataclasses import dataclass

from fastapi import Query
from pydantic import BaseModel
from sqlalchemy import Select, func, select
from sqlalchemy.orm import Session

MAX_PAGE_SIZE = 200


@dataclass
class PageParams:
    page: int
    size: int


def page_params(
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=MAX_PAGE_SIZE),
) -> PageParams:
    return PageParams(page=page, size=size)


def paginate(db: Session, stmt: Select, params: PageParams, schema: type[BaseModel]) -> dict:
    """Run `stmt` (already filtered and ordered) for one page and count the full result."""
    total = db.execute(select(func.count()).select_from(stmt.order_by(None).subquery())).scalar_one()
    rows = db.execute(stmt.offset((params.page - 1) * params.size).limit(params.size)).scalars().all()
    return {
        "items": [schema.model_validate(r) for r in rows],
        "total": total,
        "page": params.page,
        "size": params.size,
    }
