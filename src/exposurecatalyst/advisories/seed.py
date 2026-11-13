from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from exposurecatalyst.advisories.render import DEFAULT_SUBJECT, DEFAULT_TEMPLATES, default_body
from exposurecatalyst.db.base import utcnow
from exposurecatalyst.models import AdvisoryTemplate, AdvisoryTemplateVersion
from exposurecatalyst.models.advisory import APPROVED


def seed_templates(db: Session) -> None:
    """Create the four system templates with an approved v1 if they don't exist (idempotent)."""
    existing = {t.kind for t in db.scalars(select(AdvisoryTemplate).where(AdvisoryTemplate.is_system.is_(True)))}
    for kind, (name, description) in DEFAULT_TEMPLATES.items():
        if kind in existing:
            continue
        tpl = AdvisoryTemplate(name=name, kind=kind, description=description, is_system=True)
        tpl.versions.append(AdvisoryTemplateVersion(
            version=1, status=APPROVED, subject_template=DEFAULT_SUBJECT, body_template=default_body(kind),
            change_note="Initial system template", submitted_at=utcnow(), approved_at=utcnow()))
        db.add(tpl)
    db.flush()
