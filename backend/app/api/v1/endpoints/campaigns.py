from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from app.core.database import get_db
from app.schemas.threat_intelligence import (
    ThreatCampaign, ThreatCampaignCreate, ThreatCampaignUpdate
)
from app.models.threat_intelligence import ThreatCampaign

router = APIRouter()


@router.get("/", response_model=List[ThreatCampaign])
async def get_campaigns(
    active_only: bool = True,
    db: Session = Depends(get_db)
):
    """Get all threat campaigns"""
    query = db.query(ThreatCampaign)
    if active_only:
        query = query.filter(ThreatCampaign.is_active == True)
    return query.all()


@router.get("/{campaign_id}", response_model=ThreatCampaign)
async def get_campaign(
    campaign_id: int,
    db: Session = Depends(get_db)
):
    """Get a specific threat campaign"""
    campaign = db.query(ThreatCampaign).filter(ThreatCampaign.id == campaign_id).first()
    
    if not campaign:
        raise HTTPException(status_code=404, detail="Threat campaign not found")
    
    return campaign


@router.post("/", response_model=ThreatCampaign)
async def create_campaign(
    campaign_data: ThreatCampaignCreate,
    db: Session = Depends(get_db)
):
    """Create a new threat campaign"""
    campaign = ThreatCampaign(**campaign_data.dict())
    db.add(campaign)
    db.commit()
    db.refresh(campaign)
    return campaign


@router.put("/{campaign_id}", response_model=ThreatCampaign)
async def update_campaign(
    campaign_id: int,
    update_data: ThreatCampaignUpdate,
    db: Session = Depends(get_db)
):
    """Update a threat campaign"""
    campaign = db.query(ThreatCampaign).filter(ThreatCampaign.id == campaign_id).first()
    
    if not campaign:
        raise HTTPException(status_code=404, detail="Threat campaign not found")
    
    for field, value in update_data.dict(exclude_unset=True).items():
        setattr(campaign, field, value)
    
    db.commit()
    db.refresh(campaign)
    return campaign


@router.delete("/{campaign_id}")
async def delete_campaign(
    campaign_id: int,
    db: Session = Depends(get_db)
):
    """Delete a threat campaign"""
    campaign = db.query(ThreatCampaign).filter(ThreatCampaign.id == campaign_id).first()
    
    if not campaign:
        raise HTTPException(status_code=404, detail="Threat campaign not found")
    
    db.delete(campaign)
    db.commit()
    
    return {"message": "Threat campaign deleted successfully"}
