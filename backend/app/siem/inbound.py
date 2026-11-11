import os

from fastapi import APIRouter, Header, HTTPException, status
from pydantic import BaseModel

from app.streams.streams import publish

router = APIRouter(prefix="/siem", tags=["siem"])


class FeedbackPayload(BaseModel):
    event_type: str
    payload: dict
    tenant_id: str | None = None


@router.post("/feedback", status_code=200)
def siem_feedback(
    body: FeedbackPayload,
    x_siem_key: str | None = Header(default=None, alias="X-SIEM-KEY"),
) -> dict:
    expected = os.getenv("SIEM_INBOUND_KEY", "")
    if not expected or x_siem_key != expected:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid SIEM key")
    msg_id = publish("feedback-events", body.model_dump())
    return {"accepted": True, "msg_id": msg_id}
