from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from app.core.database import get_db
from app.services.threat_intelligence import ThreatIntelligenceService
from app.schemas.threat_intelligence import (
    ThreatSource, ThreatSourceCreate, ThreatSourceUpdate
)

router = APIRouter()


@router.get("/", response_model=List[ThreatSource])
async def get_sources(
    active_only: bool = True,
    db: Session = Depends(get_db)
):
    """Get all threat sources"""
    service = ThreatIntelligenceService(db)
    return service.get_sources(active_only=active_only)


@router.get("/{source_id}", response_model=ThreatSource)
async def get_source(
    source_id: int,
    db: Session = Depends(get_db)
):
    """Get a specific threat source"""
    source = db.query(ThreatSource).filter(ThreatSource.id == source_id).first()
    
    if not source:
        raise HTTPException(status_code=404, detail="Threat source not found")
    
    return source


@router.post("/", response_model=ThreatSource)
async def create_source(
    source_data: ThreatSourceCreate,
    db: Session = Depends(get_db)
):
    """Create a new threat source"""
    service = ThreatIntelligenceService(db)
    return service.create_source(source_data)


@router.put("/{source_id}", response_model=ThreatSource)
async def update_source(
    source_id: int,
    update_data: ThreatSourceUpdate,
    db: Session = Depends(get_db)
):
    """Update a threat source"""
    service = ThreatIntelligenceService(db)
    source = service.update_source(source_id, update_data)
    
    if not source:
        raise HTTPException(status_code=404, detail="Threat source not found")
    
    return source


@router.delete("/{source_id}")
async def delete_source(
    source_id: int,
    db: Session = Depends(get_db)
):
    """Delete a threat source"""
    source = db.query(ThreatSource).filter(ThreatSource.id == source_id).first()
    
    if not source:
        raise HTTPException(status_code=404, detail="Threat source not found")
    
    db.delete(source)
    db.commit()
    
    return {"message": "Threat source deleted successfully"}
