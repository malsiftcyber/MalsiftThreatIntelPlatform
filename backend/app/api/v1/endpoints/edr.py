from fastapi import APIRouter, Depends, HTTPException, Query, BackgroundTasks
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime

from app.core.database import get_db
from app.services.edr.edr_service import EDRService
from app.services.edr.llm_service import LLMService
from app.schemas.edr.edr_schemas import (
    EDRConnectionCreate, EDRConnectionUpdate, EDRConnection,
    EDRExtractionCreate, EDRExtraction, EDRIndicator,
    LLMConfigurationCreate, LLMConfigurationUpdate, LLMConfiguration,
    IndicatorAnalysisRequest, BulkAnalysisRequest,
    EDRConnectionStatus, EDRDashboardStats, IndicatorAnalysisResult
)
from app.services.auth_service import AuthService
from app.schemas.auth import User
from app.api.v1.endpoints.auth import get_current_user

router = APIRouter()

def get_edr_service(db: Session = Depends(get_db)) -> EDRService:
    return EDRService(db)

def get_llm_service(db: Session = Depends(get_db)) -> LLMService:
    return LLMService(db)

# EDR Connection Management
@router.post("/connections", response_model=EDRConnection)
async def create_edr_connection(
    connection_data: EDRConnectionCreate,
    edr_service: EDRService = Depends(get_edr_service),
    current_user: User = Depends(get_current_user)
):
    """Create a new EDR connection"""
    if not current_user.is_superuser:
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    
    try:
        return edr_service.create_connection(connection_data)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create connection: {str(e)}")

@router.get("/connections", response_model=List[EDRConnection])
async def get_edr_connections(
    edr_service: EDRService = Depends(get_edr_service),
    current_user: User = Depends(get_current_user)
):
    """Get all EDR connections"""
    return edr_service.get_connections()

@router.get("/connections/{connection_id}", response_model=EDRConnection)
async def get_edr_connection(
    connection_id: int,
    edr_service: EDRService = Depends(get_edr_service),
    current_user: User = Depends(get_current_user)
):
    """Get EDR connection by ID"""
    connection = edr_service.get_connection(connection_id)
    if not connection:
        raise HTTPException(status_code=404, detail="Connection not found")
    return connection

@router.put("/connections/{connection_id}", response_model=EDRConnection)
async def update_edr_connection(
    connection_id: int,
    connection_data: EDRConnectionUpdate,
    edr_service: EDRService = Depends(get_edr_service),
    current_user: User = Depends(get_current_user)
):
    """Update EDR connection"""
    if not current_user.is_superuser:
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    
    connection = edr_service.update_connection(connection_id, connection_data)
    if not connection:
        raise HTTPException(status_code=404, detail="Connection not found")
    return connection

@router.delete("/connections/{connection_id}")
async def delete_edr_connection(
    connection_id: int,
    edr_service: EDRService = Depends(get_edr_service),
    current_user: User = Depends(get_current_user)
):
    """Delete EDR connection"""
    if not current_user.is_superuser:
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    
    success = edr_service.delete_connection(connection_id)
    if not success:
        raise HTTPException(status_code=404, detail="Connection not found")
    
    return {"message": "Connection deleted successfully"}

@router.post("/connections/{connection_id}/test")
async def test_edr_connection(
    connection_id: int,
    edr_service: EDRService = Depends(get_edr_service),
    current_user: User = Depends(get_current_user)
):
    """Test EDR connection"""
    result = edr_service.test_connection(connection_id)
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "Connection test failed"))
    return result

# EDR Data Extraction
@router.post("/extractions", response_model=EDRExtraction)
async def start_edr_extraction(
    extraction_data: EDRExtractionCreate,
    background_tasks: BackgroundTasks,
    edr_service: EDRService = Depends(get_edr_service),
    current_user: User = Depends(get_current_user)
):
    """Start EDR data extraction"""
    if not current_user.is_superuser:
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    
    try:
        return await edr_service.start_extraction(extraction_data)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to start extraction: {str(e)}")

@router.get("/extractions", response_model=List[EDRExtraction])
async def get_edr_extractions(
    connection_id: Optional[int] = Query(None),
    status: Optional[str] = Query(None),
    edr_service: EDRService = Depends(get_edr_service),
    current_user: User = Depends(get_current_user)
):
    """Get EDR extractions"""
    # This would need to be implemented in the service
    return []

# Indicator Analysis
@router.post("/analyze-indicator", response_model=IndicatorAnalysisResult)
async def analyze_indicator(
    analysis_request: IndicatorAnalysisRequest,
    edr_service: EDRService = Depends(get_edr_service),
    current_user: User = Depends(get_current_user)
):
    """Analyze a single indicator"""
    try:
        result = await edr_service.analyze_indicator(analysis_request)
        return IndicatorAnalysisResult(**result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

@router.post("/bulk-analyze-indicators")
async def bulk_analyze_indicators(
    bulk_request: BulkAnalysisRequest,
    edr_service: EDRService = Depends(get_edr_service),
    current_user: User = Depends(get_current_user)
):
    """Analyze multiple indicators"""
    try:
        results = await edr_service.bulk_analyze_indicators(bulk_request)
        return {"results": results}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Bulk analysis failed: {str(e)}")

# LLM Configuration Management
@router.post("/llm-configurations", response_model=LLMConfiguration)
async def create_llm_configuration(
    config_data: LLMConfigurationCreate,
    llm_service: LLMService = Depends(get_llm_service),
    current_user: User = Depends(get_current_user)
):
    """Create LLM configuration"""
    if not current_user.is_superuser:
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    
    # This would need to be implemented in the service
    raise HTTPException(status_code=501, detail="Not implemented yet")

@router.get("/llm-configurations", response_model=List[LLMConfiguration])
async def get_llm_configurations(
    current_user: User = Depends(get_current_user)
):
    """Get LLM configurations"""
    # This would need to be implemented in the service
    return []

@router.put("/llm-configurations/{config_id}", response_model=LLMConfiguration)
async def update_llm_configuration(
    config_id: int,
    config_data: LLMConfigurationUpdate,
    current_user: User = Depends(get_current_user)
):
    """Update LLM configuration"""
    if not current_user.is_superuser:
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    
    # This would need to be implemented in the service
    raise HTTPException(status_code=501, detail="Not implemented yet")

@router.post("/llm-configurations/{config_id}/test")
async def test_llm_configuration(
    config_id: int,
    llm_service: LLMService = Depends(get_llm_service),
    current_user: User = Depends(get_current_user)
):
    """Test LLM configuration"""
    if not current_user.is_superuser:
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    
    # This would need to be implemented in the service
    raise HTTPException(status_code=501, detail="Not implemented yet")

# Dashboard and Statistics
@router.get("/dashboard/stats", response_model=EDRDashboardStats)
async def get_edr_dashboard_stats(
    edr_service: EDRService = Depends(get_edr_service),
    current_user: User = Depends(get_current_user)
):
    """Get EDR dashboard statistics"""
    stats = edr_service.get_dashboard_stats()
    return EDRDashboardStats(**stats)

@router.get("/connections/{connection_id}/status", response_model=EDRConnectionStatus)
async def get_connection_status(
    connection_id: int,
    edr_service: EDRService = Depends(get_edr_service),
    current_user: User = Depends(get_current_user)
):
    """Get connection status and statistics"""
    status = edr_service.get_connection_status(connection_id)
    if "error" in status:
        raise HTTPException(status_code=404, detail=status["error"])
    return EDRConnectionStatus(**status)

# Health Check
@router.get("/health")
async def edr_health():
    """EDR service health check"""
    return {
        "status": "healthy",
        "service": "edr-integration",
        "timestamp": datetime.utcnow().isoformat()
    }
