from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from app.core.database import get_db
from app.services.threat_intelligence import ThreatIntelligenceService
from app.schemas.threat_intelligence import (
    ThreatIndicator, ThreatIndicatorCreate, ThreatIndicatorUpdate,
    PaginatedResponse, ThreatIntelligenceSummary, DeduplicationResult,
    IndicatorType, ThreatLevel
)

router = APIRouter()


@router.get("/", response_model=PaginatedResponse)
async def get_indicators(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    indicator_type: Optional[IndicatorType] = Query(None),
    threat_level: Optional[ThreatLevel] = Query(None),
    source_id: Optional[int] = Query(None),
    tags: Optional[List[str]] = Query(None),
    search: Optional[str] = Query(None),
    include_excluded: bool = Query(False, description="Include indicators that would be excluded by exclusion rules"),
    db: Session = Depends(get_db)
):
    """Get threat indicators with filtering and pagination"""
    service = ThreatIntelligenceService(db)
    indicators = service.get_indicators(
        skip=skip,
        limit=limit,
        indicator_type=indicator_type,
        threat_level=threat_level,
        source_id=source_id,
        tags=tags,
        search=search,
        include_excluded=include_excluded
    )
    
    # Get total count for pagination
    total = len(indicators)  # This should be optimized with a separate count query
    
    return PaginatedResponse(
        items=indicators,
        total=total,
        page=skip // limit + 1,
        size=limit,
        pages=(total + limit - 1) // limit
    )


@router.get("/{indicator_id}", response_model=ThreatIndicator)
async def get_indicator(
    indicator_id: int,
    db: Session = Depends(get_db)
):
    """Get a specific threat indicator by ID"""
    service = ThreatIntelligenceService(db)
    indicator = service.get_indicator_by_id(indicator_id)
    
    if not indicator:
        raise HTTPException(status_code=404, detail="Indicator not found")
    
    return indicator


@router.post("/", response_model=ThreatIndicator)
async def create_indicator(
    indicator_data: ThreatIndicatorCreate,
    db: Session = Depends(get_db)
):
    """Create a new threat indicator"""
    service = ThreatIntelligenceService(db)
    indicator = service.create_indicator(indicator_data)
    return indicator


@router.put("/{indicator_id}", response_model=ThreatIndicator)
async def update_indicator(
    indicator_id: int,
    update_data: ThreatIndicatorUpdate,
    db: Session = Depends(get_db)
):
    """Update a threat indicator"""
    service = ThreatIntelligenceService(db)
    indicator = service.update_indicator(indicator_id, update_data)
    
    if not indicator:
        raise HTTPException(status_code=404, detail="Indicator not found")
    
    return indicator


@router.delete("/{indicator_id}")
async def delete_indicator(
    indicator_id: int,
    db: Session = Depends(get_db)
):
    """Delete a threat indicator"""
    service = ThreatIntelligenceService(db)
    success = service.delete_indicator(indicator_id)
    
    if not success:
        raise HTTPException(status_code=404, detail="Indicator not found")
    
    return {"message": "Indicator deleted successfully"}


@router.get("/summary/stats", response_model=ThreatIntelligenceSummary)
async def get_indicators_summary(
    db: Session = Depends(get_db)
):
    """Get summary statistics of threat indicators"""
    service = ThreatIntelligenceService(db)
    return service.get_indicators_summary()


@router.post("/deduplicate", response_model=DeduplicationResult)
async def deduplicate_indicators(
    db: Session = Depends(get_db)
):
    """Perform deduplication of all indicators"""
    service = ThreatIntelligenceService(db)
    result = service.deduplicate_indicators()
    return result


@router.get("/search/{query}")
async def search_indicators(
    query: str,
    limit: int = Query(50, ge=1, le=100),
    include_excluded: bool = Query(False, description="Include indicators that would be excluded by exclusion rules"),
    db: Session = Depends(get_db)
):
    """Search indicators by value or description"""
    service = ThreatIntelligenceService(db)
    indicators = service.get_indicators(
        skip=0,
        limit=limit,
        search=query,
        include_excluded=include_excluded
    )
    
    return {
        "query": query,
        "results": indicators,
        "total": len(indicators)
    }


@router.get("/by-type/{indicator_type}")
async def get_indicators_by_type(
    indicator_type: IndicatorType,
    limit: int = Query(100, ge=1, le=1000),
    include_excluded: bool = Query(False, description="Include indicators that would be excluded by exclusion rules"),
    db: Session = Depends(get_db)
):
    """Get indicators by type"""
    service = ThreatIntelligenceService(db)
    indicators = service.get_indicators(
        skip=0,
        limit=limit,
        indicator_type=indicator_type,
        include_excluded=include_excluded
    )
    
    return {
        "indicator_type": indicator_type,
        "indicators": indicators,
        "total": len(indicators)
    }


@router.get("/by-level/{threat_level}")
async def get_indicators_by_level(
    threat_level: ThreatLevel,
    limit: int = Query(100, ge=1, le=1000),
    include_excluded: bool = Query(False, description="Include indicators that would be excluded by exclusion rules"),
    db: Session = Depends(get_db)
):
    """Get indicators by threat level"""
    service = ThreatIntelligenceService(db)
    indicators = service.get_indicators(
        skip=0,
        limit=limit,
        threat_level=threat_level,
        include_excluded=include_excluded
    )
    
    return {
        "threat_level": threat_level,
        "indicators": indicators,
        "total": len(indicators)
    }


@router.get("/by-source/{source_id}")
async def get_indicators_by_source(
    source_id: int,
    limit: int = Query(100, ge=1, le=1000),
    include_excluded: bool = Query(False, description="Include indicators that would be excluded by exclusion rules"),
    db: Session = Depends(get_db)
):
    """Get indicators by source"""
    service = ThreatIntelligenceService(db)
    indicators = service.get_indicators(
        skip=0,
        limit=limit,
        source_id=source_id,
        include_excluded=include_excluded
    )
    
    return {
        "source_id": source_id,
        "indicators": indicators,
        "total": len(indicators)
    }
