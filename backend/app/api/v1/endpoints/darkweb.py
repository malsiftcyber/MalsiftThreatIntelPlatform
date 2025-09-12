from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from typing import List
from app.core.database import get_db
from app.schemas.threat_intelligence import (
    DarkWebSource, DarkWebSourceCreate, DarkWebSourceUpdate
)
from app.models.threat_intelligence import DarkWebSource as DarkWebSourceModel
from app.services.feed_fetchers import DarkWebFeedFetcher
from app.services.threat_intelligence import ThreatIntelligenceService
from loguru import logger

router = APIRouter()


@router.get("/", response_model=List[DarkWebSource])
async def get_darkweb_sources(
    active_only: bool = True,
    db: Session = Depends(get_db)
):
    """Get all dark web sources"""
    query = db.query(DarkWebSourceModel)
    if active_only:
        query = query.filter(DarkWebSourceModel.is_active == True)
    return query.all()


@router.get("/{source_id}", response_model=DarkWebSource)
async def get_darkweb_source(
    source_id: int,
    db: Session = Depends(get_db)
):
    """Get a specific dark web source"""
    source = db.query(DarkWebSourceModel).filter(DarkWebSourceModel.id == source_id).first()
    
    if not source:
        raise HTTPException(status_code=404, detail="Dark web source not found")
    
    return source


@router.post("/", response_model=DarkWebSource)
async def create_darkweb_source(
    source_data: DarkWebSourceCreate,
    db: Session = Depends(get_db)
):
    """Create a new dark web source"""
    source = DarkWebSourceModel(**source_data.dict())
    db.add(source)
    db.commit()
    db.refresh(source)
    return source


@router.put("/{source_id}", response_model=DarkWebSource)
async def update_darkweb_source(
    source_id: int,
    update_data: DarkWebSourceUpdate,
    db: Session = Depends(get_db)
):
    """Update a dark web source"""
    source = db.query(DarkWebSourceModel).filter(DarkWebSourceModel.id == source_id).first()
    
    if not source:
        raise HTTPException(status_code=404, detail="Dark web source not found")
    
    for field, value in update_data.dict(exclude_unset=True).items():
        setattr(source, field, value)
    
    db.commit()
    db.refresh(source)
    return source


@router.delete("/{source_id}")
async def delete_darkweb_source(
    source_id: int,
    db: Session = Depends(get_db)
):
    """Delete a dark web source"""
    source = db.query(DarkWebSourceModel).filter(DarkWebSourceModel.id == source_id).first()
    
    if not source:
        raise HTTPException(status_code=404, detail="Dark web source not found")
    
    db.delete(source)
    db.commit()
    
    return {"message": "Dark web source deleted successfully"}


@router.post("/{source_id}/scrape")
async def scrape_darkweb_source(
    source_id: int,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """Scrape a specific dark web source"""
    source = db.query(DarkWebSourceModel).filter(DarkWebSourceModel.id == source_id).first()
    
    if not source:
        raise HTTPException(status_code=404, detail="Dark web source not found")
    
    if not source.is_active:
        raise HTTPException(status_code=400, detail="Dark web source is disabled")
    
    # Start background scraping task
    background_tasks.add_task(scrape_darkweb_task, source_id, db)
    
    return {
        "message": f"Started scraping dark web source: {source.name}",
        "source_id": source_id
    }


@router.post("/scrape-all")
async def scrape_all_darkweb_sources(
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """Scrape all active dark web sources"""
    active_sources = db.query(DarkWebSourceModel).filter(
        DarkWebSourceModel.is_active == True
    ).all()
    
    if not active_sources:
        raise HTTPException(status_code=400, detail="No active dark web sources found")
    
    # Start background tasks for all sources
    for source in active_sources:
        background_tasks.add_task(scrape_darkweb_task, source.id, db)
    
    return {
        "message": f"Started scraping {len(active_sources)} dark web sources",
        "sources": [{"id": source.id, "name": source.name} for source in active_sources]
    }


async def scrape_darkweb_task(source_id: int, db: Session):
    """Background task to scrape dark web source"""
    try:
        source = db.query(DarkWebSourceModel).filter(DarkWebSourceModel.id == source_id).first()
        
        if not source:
            logger.error(f"Dark web source {source_id} not found")
            return
        
        # Create a dummy threat source for the dark web fetcher
        from app.models.threat_intelligence import ThreatSource
        threat_source = ThreatSource(
            id=0,  # Dummy ID
            name=source.name,
            description=source.description,
            source_type="darkweb"
        )
        
        # Create fetcher and scrape
        fetcher = DarkWebFeedFetcher(threat_source)
        async with fetcher:
            indicators = await fetcher.fetch_indicators()
        
        # Process indicators (this would need a proper source ID)
        # For now, we'll just log the results
        logger.info(f"Dark web scraping completed for {source.name}: {len(indicators)} indicators found")
        
        # Update last scrape time
        source.last_scrape = source.last_scrape or source.created_at
        db.commit()
        
    except Exception as e:
        logger.error(f"Dark web scraping error for source {source_id}: {e}")


@router.get("/status")
async def get_darkweb_status(
    db: Session = Depends(get_db)
):
    """Get dark web scraping status"""
    total_sources = db.query(DarkWebSourceModel).count()
    active_sources = db.query(DarkWebSourceModel).filter(
        DarkWebSourceModel.is_active == True
    ).count()
    
    # Get recent scraping activity
    recent_sources = db.query(DarkWebSourceModel).filter(
        DarkWebSourceModel.last_scrape.isnot(None)
    ).order_by(DarkWebSourceModel.last_scrape.desc()).limit(5).all()
    
    return {
        "total_sources": total_sources,
        "active_sources": active_sources,
        "recent_scrapes": [
            {
                "name": source.name,
                "last_scrape": source.last_scrape,
                "scrape_interval_hours": source.scrape_interval_hours
            }
            for source in recent_sources
        ]
    }
