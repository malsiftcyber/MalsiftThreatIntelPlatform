from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.orm import Session
from typing import Optional
from datetime import datetime

from app.core.database import get_db
from app.services.feed_comparison.comparison_service import FeedComparisonService
from app.services.auth_service import AuthService
from app.schemas.auth import User
from app.api.v1.endpoints.auth import get_current_user

router = APIRouter()

def get_comparison_service(db: Session = Depends(get_db)) -> FeedComparisonService:
    return FeedComparisonService(db)

@router.get("/overview")
async def get_feed_comparison_overview(
    days: int = Query(30, ge=1, le=365, description="Number of days to analyze"),
    comparison_service: FeedComparisonService = Depends(get_comparison_service),
    current_user: User = Depends(get_current_user)
):
    """Get overview comparison between open source and premium feeds"""
    try:
        return comparison_service.calculate_overlap_percentage(days)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to calculate comparison: {str(e)}")

@router.get("/by-type")
async def get_comparison_by_type(
    days: int = Query(30, ge=1, le=365, description="Number of days to analyze"),
    comparison_service: FeedComparisonService = Depends(get_comparison_service),
    current_user: User = Depends(get_current_user)
):
    """Get comparison by indicator type (IP, domain, URL, hash)"""
    try:
        return comparison_service.get_comparison_by_type(days)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to calculate type comparison: {str(e)}")

@router.get("/by-source")
async def get_comparison_by_source(
    days: int = Query(30, ge=1, le=365, description="Number of days to analyze"),
    comparison_service: FeedComparisonService = Depends(get_comparison_service),
    current_user: User = Depends(get_current_user)
):
    """Get detailed comparison by individual sources"""
    try:
        return comparison_service.get_source_comparison(days)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to calculate source comparison: {str(e)}")

@router.get("/trends")
async def get_comparison_trends(
    days: int = Query(30, ge=1, le=365, description="Number of days to analyze"),
    comparison_service: FeedComparisonService = Depends(get_comparison_service),
    current_user: User = Depends(get_current_user)
):
    """Get trend data for feed comparison over time"""
    try:
        return comparison_service.get_trend_data(days)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to calculate trends: {str(e)}")

@router.get("/comprehensive")
async def get_comprehensive_comparison(
    days: int = Query(30, ge=1, le=365, description="Number of days to analyze"),
    comparison_service: FeedComparisonService = Depends(get_comparison_service),
    current_user: User = Depends(get_current_user)
):
    """Get comprehensive comparison data for dashboard"""
    try:
        return comparison_service.get_comprehensive_comparison(days)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to calculate comprehensive comparison: {str(e)}")

@router.get("/health")
async def feed_comparison_health():
    """Health check for feed comparison service"""
    return {
        "status": "healthy",
        "service": "feed-comparison",
        "timestamp": datetime.utcnow().isoformat()
    }
