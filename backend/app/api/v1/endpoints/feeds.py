from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from typing import List
from app.core.database import get_db
from app.services.threat_intelligence import ThreatIntelligenceService
from app.services.feed_fetchers import create_feed_fetcher
from app.schemas.threat_intelligence import (
    FeedConfiguration, FeedConfigurationCreate, FeedConfigurationUpdate,
    ThreatSource, ThreatSourceCreate, ThreatSourceUpdate,
    FetchJob, FetchJobCreate, PaginatedResponse
)
from app.models.threat_intelligence import ThreatSource, FetchJob
from loguru import logger
import asyncio

router = APIRouter()


@router.get("/", response_model=List[FeedConfiguration])
async def get_feed_configurations(
    db: Session = Depends(get_db)
):
    """Get all feed configurations"""
    configurations = db.query(FeedConfiguration).all()
    return configurations


@router.get("/{config_id}", response_model=FeedConfiguration)
async def get_feed_configuration(
    config_id: int,
    db: Session = Depends(get_db)
):
    """Get a specific feed configuration"""
    config = db.query(FeedConfiguration).filter(
        FeedConfiguration.id == config_id
    ).first()
    
    if not config:
        raise HTTPException(status_code=404, detail="Feed configuration not found")
    
    return config


@router.post("/", response_model=FeedConfiguration)
async def create_feed_configuration(
    config_data: FeedConfigurationCreate,
    db: Session = Depends(get_db)
):
    """Create a new feed configuration"""
    # Check if source already exists
    existing = db.query(FeedConfiguration).filter(
        FeedConfiguration.source_name == config_data.source_name
    ).first()
    
    if existing:
        raise HTTPException(
            status_code=400, 
            detail=f"Feed configuration for {config_data.source_name} already exists"
        )
    
    config = FeedConfiguration(**config_data.dict())
    db.add(config)
    db.commit()
    db.refresh(config)
    
    return config


@router.put("/{config_id}", response_model=FeedConfiguration)
async def update_feed_configuration(
    config_id: int,
    update_data: FeedConfigurationUpdate,
    db: Session = Depends(get_db)
):
    """Update a feed configuration"""
    config = db.query(FeedConfiguration).filter(
        FeedConfiguration.id == config_id
    ).first()
    
    if not config:
        raise HTTPException(status_code=404, detail="Feed configuration not found")
    
    for field, value in update_data.dict(exclude_unset=True).items():
        setattr(config, field, value)
    
    db.commit()
    db.refresh(config)
    
    return config


@router.delete("/{config_id}")
async def delete_feed_configuration(
    config_id: int,
    db: Session = Depends(get_db)
):
    """Delete a feed configuration"""
    config = db.query(FeedConfiguration).filter(
        FeedConfiguration.id == config_id
    ).first()
    
    if not config:
        raise HTTPException(status_code=404, detail="Feed configuration not found")
    
    db.delete(config)
    db.commit()
    
    return {"message": "Feed configuration deleted successfully"}


@router.post("/{config_id}/fetch", response_model=FetchJob)
async def fetch_feed_data(
    config_id: int,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """Fetch data from a specific feed"""
    config = db.query(FeedConfiguration).filter(
        FeedConfiguration.id == config_id
    ).first()
    
    if not config:
        raise HTTPException(status_code=404, detail="Feed configuration not found")
    
    if not config.is_enabled:
        raise HTTPException(status_code=400, detail="Feed is disabled")
    
    # Get or create source
    source = db.query(ThreatSource).filter(
        ThreatSource.name == config.source_name
    ).first()
    
    if not source:
        # Create source if it doesn't exist
        source_data = ThreatSourceCreate(
            name=config.source_name,
            description=f"Auto-created source for {config.source_name}",
            source_type="commercial"  # Default type
        )
        source = ThreatIntelligenceService(db).create_source(source_data)
    
    # Create fetch job
    job = FetchJob(
        source_name=config.source_name,
        status="pending"
    )
    db.add(job)
    db.commit()
    db.refresh(job)
    
    # Start background task
    background_tasks.add_task(
        fetch_feed_data_task,
        job.id,
        source.id,
        config_id,
        db
    )
    
    return job


@router.get("/jobs/", response_model=List[FetchJob])
async def get_fetch_jobs(
    limit: int = 50,
    db: Session = Depends(get_db)
):
    """Get recent fetch jobs"""
    jobs = db.query(FetchJob).order_by(
        FetchJob.created_at.desc()
    ).limit(limit).all()
    
    return jobs


@router.get("/jobs/{job_id}", response_model=FetchJob)
async def get_fetch_job(
    job_id: int,
    db: Session = Depends(get_db)
):
    """Get a specific fetch job"""
    job = db.query(FetchJob).filter(FetchJob.id == job_id).first()
    
    if not job:
        raise HTTPException(status_code=404, detail="Fetch job not found")
    
    return job


@router.post("/fetch-all")
async def fetch_all_feeds(
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """Fetch data from all enabled feeds"""
    enabled_configs = db.query(FeedConfiguration).filter(
        FeedConfiguration.is_enabled == True
    ).all()
    
    jobs = []
    for config in enabled_configs:
        # Get or create source
        source = db.query(ThreatSource).filter(
            ThreatSource.name == config.source_name
        ).first()
        
        if not source:
            source_data = ThreatSourceCreate(
                name=config.source_name,
                description=f"Auto-created source for {config.source_name}",
                source_type="commercial"
            )
            source = ThreatIntelligenceService(db).create_source(source_data)
        
        # Create fetch job
        job = FetchJob(
            source_name=config.source_name,
            status="pending"
        )
        db.add(job)
        jobs.append(job)
    
    db.commit()
    
    # Start background tasks for all jobs
    for i, config in enumerate(enabled_configs):
        source = db.query(ThreatSource).filter(
            ThreatSource.name == config.source_name
        ).first()
        
        background_tasks.add_task(
            fetch_feed_data_task,
            jobs[i].id,
            source.id,
            config.id,
            db
        )
    
    return {
        "message": f"Started {len(jobs)} fetch jobs",
        "jobs": [{"id": job.id, "source_name": job.source_name} for job in jobs]
    }


async def fetch_feed_data_task(
    job_id: int,
    source_id: int,
    config_id: int,
    db: Session
):
    """Background task to fetch feed data"""
    try:
        # Update job status
        job = db.query(FetchJob).filter(FetchJob.id == job_id).first()
        if job:
            job.status = "running"
            job.started_at = job.started_at or job.created_at
            db.commit()
        
        # Get source and config
        source = db.query(ThreatSource).filter(ThreatSource.id == source_id).first()
        config = db.query(FeedConfiguration).filter(FeedConfiguration.id == config_id).first()
        
        if not source or not config:
            if job:
                job.status = "failed"
                job.error_message = "Source or configuration not found"
                db.commit()
            return
        
        # Create fetcher and fetch data
        fetcher = create_feed_fetcher(source)
        async with fetcher:
            indicators = await fetcher.fetch_indicators()
        
        # Process indicators
        service = ThreatIntelligenceService(db)
        new_indicators = 0
        
        for indicator_data in indicators:
            try:
                indicator_data.source_id = source_id
                service.create_indicator(indicator_data)
                new_indicators += 1
            except Exception as e:
                logger.error(f"Error creating indicator: {e}")
        
        # Update job status
        if job:
            job.status = "completed"
            job.completed_at = job.completed_at or job.created_at
            job.indicators_found = len(indicators)
            job.indicators_new = new_indicators
            db.commit()
        
        # Update source last fetch time
        source.last_fetch = source.last_fetch or source.created_at
        db.commit()
        
        logger.info(f"Feed fetch completed for {source.name}: {new_indicators} new indicators")
        
    except Exception as e:
        logger.error(f"Feed fetch error for job {job_id}: {e}")
        
        # Update job status
        job = db.query(FetchJob).filter(FetchJob.id == job_id).first()
        if job:
            job.status = "failed"
            job.error_message = str(e)
            db.commit()


@router.get("/sources/", response_model=List[ThreatSource])
async def get_threat_sources(
    active_only: bool = True,
    db: Session = Depends(get_db)
):
    """Get threat sources"""
    service = ThreatIntelligenceService(db)
    return service.get_sources(active_only=active_only)


@router.post("/sources/", response_model=ThreatSource)
async def create_threat_source(
    source_data: ThreatSourceCreate,
    db: Session = Depends(get_db)
):
    """Create a new threat source"""
    service = ThreatIntelligenceService(db)
    return service.create_source(source_data)


@router.put("/sources/{source_id}", response_model=ThreatSource)
async def update_threat_source(
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
