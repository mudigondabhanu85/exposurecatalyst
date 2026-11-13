from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol

from sqlalchemy import select
from sqlalchemy.orm import Session

from exposurecatalyst.models import Cve, SourceState


@dataclass
class RunResult:
    records: int = 0
    detail: dict[str, Any] = field(default_factory=dict)


class Source(Protocol):
    name: str

    def run(self, db: Session, state: SourceState, now: datetime) -> RunResult: ...

    def close(self) -> None: ...


def chunked(items: Iterable, size: int) -> Iterator[list]:
    batch: list = []
    for item in items:
        batch.append(item)
        if len(batch) >= size:
            yield batch
            batch = []
    if batch:
        yield batch


def load_cves(db: Session, cve_ids: Iterable[str]) -> dict[str, Cve]:
    found: dict[str, Cve] = {}
    for batch in chunked(set(cve_ids), 500):  # stays under Oracle/SQL Server bind-parameter limits
        for cve in db.scalars(select(Cve).where(Cve.cve_id.in_(batch))):
            found[cve.cve_id] = cve
    return found
