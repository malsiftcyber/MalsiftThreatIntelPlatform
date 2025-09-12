from fastapi import APIRouter, Depends, HTTPException, Query, UploadFile, File
from sqlalchemy.orm import Session
from typing import List, Optional
from app.core.database import get_db
from app.services.exclusion_service import ExclusionService
from app.schemas.threat_intelligence import (
    IndicatorExclusion, IndicatorExclusionCreate, IndicatorExclusionUpdate,
    PaginatedResponse, ExclusionTestResult, PatternType, IndicatorType
)

router = APIRouter()


@router.get("/", response_model=PaginatedResponse)
async def get_exclusions(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    indicator_type: Optional[IndicatorType] = Query(None),
    pattern_type: Optional[PatternType] = Query(None),
    is_active: Optional[bool] = Query(None),
    db: Session = Depends(get_db)
):
    """Get indicator exclusions with filtering and pagination"""
    service = ExclusionService(db)
    exclusions = service.get_exclusions(
        skip=skip,
        limit=limit,
        indicator_type=indicator_type,
        pattern_type=pattern_type,
        is_active=is_active
    )
    
    # Get total count for pagination
    total = len(exclusions)  # This should be optimized with a separate count query
    
    return PaginatedResponse(
        items=exclusions,
        total=total,
        page=skip // limit + 1,
        size=limit,
        pages=(total + limit - 1) // limit
    )


@router.get("/{exclusion_id}", response_model=IndicatorExclusion)
async def get_exclusion(
    exclusion_id: int,
    db: Session = Depends(get_db)
):
    """Get a specific indicator exclusion by ID"""
    service = ExclusionService(db)
    exclusion = service.get_exclusion_by_id(exclusion_id)
    
    if not exclusion:
        raise HTTPException(status_code=404, detail="Exclusion not found")
    
    return exclusion


@router.post("/", response_model=IndicatorExclusion)
async def create_exclusion(
    exclusion_data: IndicatorExclusionCreate,
    db: Session = Depends(get_db)
):
    """Create a new indicator exclusion"""
    service = ExclusionService(db)
    exclusion = service.create_exclusion(exclusion_data)
    return exclusion


@router.put("/{exclusion_id}", response_model=IndicatorExclusion)
async def update_exclusion(
    exclusion_id: int,
    update_data: IndicatorExclusionUpdate,
    db: Session = Depends(get_db)
):
    """Update an indicator exclusion"""
    service = ExclusionService(db)
    exclusion = service.update_exclusion(exclusion_id, update_data)
    
    if not exclusion:
        raise HTTPException(status_code=404, detail="Exclusion not found")
    
    return exclusion


@router.delete("/{exclusion_id}")
async def delete_exclusion(
    exclusion_id: int,
    db: Session = Depends(get_db)
):
    """Delete an indicator exclusion"""
    service = ExclusionService(db)
    success = service.delete_exclusion(exclusion_id)
    
    if not success:
        raise HTTPException(status_code=404, detail="Exclusion not found")
    
    return {"message": "Exclusion deleted successfully"}


@router.post("/test", response_model=ExclusionTestResult)
async def test_exclusion_pattern(
    pattern: str = Query(..., description="Pattern to test"),
    pattern_type: PatternType = Query(..., description="Type of pattern"),
    indicator_type: Optional[IndicatorType] = Query(None, description="Indicator type to test against"),
    db: Session = Depends(get_db)
):
    """Test an exclusion pattern against existing indicators"""
    service = ExclusionService(db)
    result = service.test_exclusion_pattern(pattern, pattern_type, indicator_type)
    return result


@router.get("/stats/summary")
async def get_exclusion_stats(
    db: Session = Depends(get_db)
):
    """Get exclusion statistics"""
    service = ExclusionService(db)
    return service.get_exclusion_stats()


@router.post("/bulk")
async def bulk_create_exclusions(
    exclusions_data: List[IndicatorExclusionCreate],
    db: Session = Depends(get_db)
):
    """Create multiple exclusions at once"""
    service = ExclusionService(db)
    exclusions = service.bulk_create_exclusions(exclusions_data)
    return {
        "message": f"Created {len(exclusions)} exclusions",
        "exclusions": exclusions
    }


@router.post("/import")
async def import_exclusions(
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    """Import exclusions from a file (CSV or JSON)"""
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file provided")
    
    # Read file content
    content = await file.read()
    file_content = content.decode('utf-8')
    
    service = ExclusionService(db)
    exclusions = service.import_exclusions_from_file(file_content)
    
    return {
        "message": f"Imported {len(exclusions)} exclusions from {file.filename}",
        "exclusions": exclusions
    }


@router.post("/{exclusion_id}/toggle")
async def toggle_exclusion(
    exclusion_id: int,
    db: Session = Depends(get_db)
):
    """Toggle the active status of an exclusion"""
    service = ExclusionService(db)
    exclusion = service.get_exclusion_by_id(exclusion_id)
    
    if not exclusion:
        raise HTTPException(status_code=404, detail="Exclusion not found")
    
    update_data = IndicatorExclusionUpdate(is_active=not exclusion.is_active)
    updated_exclusion = service.update_exclusion(exclusion_id, update_data)
    
    return {
        "message": f"Exclusion {'activated' if updated_exclusion.is_active else 'deactivated'}",
        "exclusion": updated_exclusion
    }


@router.get("/check/{indicator_type}/{value}")
async def check_indicator_exclusion(
    indicator_type: str,
    value: str,
    db: Session = Depends(get_db)
):
    """Check if a specific indicator would be excluded"""
    service = ExclusionService(db)
    is_excluded = service.is_indicator_excluded(indicator_type, value)
    
    return {
        "indicator_type": indicator_type,
        "value": value,
        "is_excluded": is_excluded
    }
