"""Global ATT&CK technique catalog endpoint (read-only, no tenant filter)."""
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import AttackTechnique
from app.db.session import get_db

router = APIRouter()


class TechniqueOut(BaseModel):
    id: str
    mitre_id: str
    name: str
    tactic: str | None

    model_config = {"from_attributes": True}


@router.get("/attack/techniques", response_model=list[TechniqueOut])
def list_techniques(db: Session = Depends(get_db)):
    rows = db.execute(
        select(AttackTechnique).order_by(AttackTechnique.tactic, AttackTechnique.mitre_id)
    ).scalars().all()
    return [TechniqueOut(id=str(r.id), mitre_id=r.mitre_id, name=r.name, tactic=r.tactic) for r in rows]
