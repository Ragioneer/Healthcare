# app/routers/receptionist.py

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from datetime import datetime
from typing import List
from app.db.mongo import reception_requests_collection
from app.services.kommo import push_receptionist_request_to_kommo

router = APIRouter(tags=["receptionist"])

class ReceptionRequest(BaseModel):
    user_id: str = Field(..., description="Unique user making the request")
    name: str = Field(..., description="Patient’s name")
    phone: str = Field(..., description="Contact phone number")
    reason: str = Field(..., description="Reason for contacting reception")

@router.post("/request", summary="Connect to a human receptionist")
async def connect_receptionist(req: ReceptionRequest):
    doc = req.dict()
    doc["created_at"] = datetime.utcnow()
    await reception_requests_collection.insert_one(doc)

    # Push to Kommo
    push_receptionist_request_to_kommo(doc)

    return {"message": "Request received. Our agent will call you shortly."}

@router.get("/request", response_model=List[ReceptionRequest])
async def list_receptionist_requests(user_id: str):
    docs = await reception_requests_collection.find({"user_id": user_id}).to_list(100)
    return docs

