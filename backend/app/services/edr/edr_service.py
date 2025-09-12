from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_
import httpx
import asyncio
from loguru import logger

from app.models.edr.edr_models import (
    EDRConnection, EDRExtraction, EDRIndicator, EDRAnalysis,
    LLMConfiguration, ThreatIntelligenceMatch
)
from app.models.threat_intelligence import ThreatIndicator
from app.schemas.edr.edr_schemas import (
    EDRConnectionCreate, EDRConnectionUpdate, EDRExtractionCreate,
    IndicatorAnalysisRequest, BulkAnalysisRequest
)
from app.services.edr.crowdstrike_client import CrowdstrikeClient
from app.services.edr.sentinelone_client import SentinelOneClient
from app.services.edr.defender_client import DefenderClient
from app.services.edr.llm_service import LLMService
from app.services.edr.indicator_comparison import IndicatorComparisonService


class EDRService:
    """Main EDR integration service"""
    
    def __init__(self, db: Session):
        self.db = db
        self.llm_service = LLMService(db)
        self.comparison_service = IndicatorComparisonService(db)
    
    # EDR Connection Management
    def create_connection(self, connection_data: EDRConnectionCreate) -> EDRConnection:
        """Create a new EDR connection"""
        connection = EDRConnection(**connection_data.dict())
        self.db.add(connection)
        self.db.commit()
        self.db.refresh(connection)
        return connection
    
    def get_connection(self, connection_id: int) -> Optional[EDRConnection]:
        """Get EDR connection by ID"""
        return self.db.query(EDRConnection).filter(EDRConnection.id == connection_id).first()
    
    def get_connections(self) -> List[EDRConnection]:
        """Get all EDR connections"""
        return self.db.query(EDRConnection).all()
    
    def update_connection(self, connection_id: int, connection_data: EDRConnectionUpdate) -> Optional[EDRConnection]:
        """Update EDR connection"""
        connection = self.get_connection(connection_id)
        if not connection:
            return None
        
        update_data = connection_data.dict(exclude_unset=True)
        for field, value in update_data.items():
            setattr(connection, field, value)
        
        self.db.commit()
        self.db.refresh(connection)
        return connection
    
    def delete_connection(self, connection_id: int) -> bool:
        """Delete EDR connection"""
        connection = self.get_connection(connection_id)
        if not connection:
            return False
        
        self.db.delete(connection)
        self.db.commit()
        return True
    
    def test_connection(self, connection_id: int) -> Dict[str, Any]:
        """Test EDR connection"""
        connection = self.get_connection(connection_id)
        if not connection:
            return {"success": False, "error": "Connection not found"}
        
        try:
            if connection.platform == "crowdstrike":
                client = CrowdstrikeClient(connection)
            elif connection.platform == "sentinelone":
                client = SentinelOneClient(connection)
            elif connection.platform == "defender":
                client = DefenderClient(connection)
            else:
                return {"success": False, "error": "Unsupported platform"}
            
            # Test API connectivity
            result = client.test_connection()
            return result
            
        except Exception as e:
            logger.error(f"Connection test failed: {e}")
            return {"success": False, "error": str(e)}
    
    # EDR Data Extraction
    async def start_extraction(self, extraction_data: EDRExtractionCreate) -> EDRExtraction:
        """Start EDR data extraction"""
        extraction = EDRExtraction(**extraction_data.dict())
        self.db.add(extraction)
        self.db.commit()
        self.db.refresh(extraction)
        
        # Start background extraction task
        asyncio.create_task(self._run_extraction(extraction.id))
        
        return extraction
    
    async def _run_extraction(self, extraction_id: int):
        """Run EDR data extraction in background"""
        extraction = self.db.query(EDRExtraction).filter(EDRExtraction.id == extraction_id).first()
        if not extraction:
            return
        
        connection = self.get_connection(extraction.connection_id)
        if not connection:
            extraction.status = "failed"
            extraction.error_message = "Connection not found"
            self.db.commit()
            return
        
        try:
            extraction.status = "running"
            extraction.start_time = datetime.utcnow()
            self.db.commit()
            
            # Get appropriate client
            if connection.platform == "crowdstrike":
                client = CrowdstrikeClient(connection)
            elif connection.platform == "sentinelone":
                client = SentinelOneClient(connection)
            elif connection.platform == "defender":
                client = DefenderClient(connection)
            else:
                raise ValueError(f"Unsupported platform: {connection.platform}")
            
            # Extract indicators
            indicators = await client.extract_indicators(extraction.extraction_type, extraction.filters)
            
            # Save indicators to database
            for indicator_data in indicators:
                indicator = EDRIndicator(
                    extraction_id=extraction.id,
                    **indicator_data
                )
                self.db.add(indicator)
            
            extraction.status = "completed"
            extraction.end_time = datetime.utcnow()
            extraction.total_records = len(indicators)
            extraction.processed_records = len(indicators)
            
            # Update connection last sync
            connection.last_sync = datetime.utcnow()
            
            self.db.commit()
            
            # Start indicator analysis for unknown indicators
            await self._analyze_unknown_indicators(extraction.id)
            
        except Exception as e:
            logger.error(f"Extraction failed: {e}")
            extraction.status = "failed"
            extraction.error_message = str(e)
            extraction.end_time = datetime.utcnow()
            self.db.commit()
    
    async def _analyze_unknown_indicators(self, extraction_id: int):
        """Analyze indicators that are not in known threat intelligence"""
        # Get indicators from this extraction
        indicators = self.db.query(EDRIndicator).filter(
            EDRIndicator.extraction_id == extraction_id
        ).all()
        
        for indicator in indicators:
            # Check if indicator is in known threat intelligence
            is_known = await self.comparison_service.check_threat_intelligence(indicator.indicator_value)
            
            if not is_known:
                # Analyze with LLM
                await self._analyze_indicator_with_llm(indicator.id)
    
    async def _analyze_indicator_with_llm(self, indicator_id: int):
        """Analyze indicator with LLM"""
        indicator = self.db.query(EDRIndicator).filter(EDRIndicator.id == indicator_id).first()
        if not indicator:
            return
        
        try:
            # Get LLM configuration
            llm_config = self.db.query(LLMConfiguration).filter(
                LLMConfiguration.is_active == True
            ).first()
            
            if not llm_config:
                logger.warning("No active LLM configuration found")
                return
            
            # Analyze indicator
            analysis_result = await self.llm_service.analyze_indicator(
                indicator=indicator,
                llm_config=llm_config
            )
            
            # Save analysis
            analysis = EDRAnalysis(
                connection_id=indicator.extraction.connection_id,
                indicator_id=indicator.id,
                **analysis_result
            )
            self.db.add(analysis)
            
            # Update indicator with analysis
            indicator.llm_analysis = analysis_result
            self.db.commit()
            
        except Exception as e:
            logger.error(f"LLM analysis failed for indicator {indicator_id}: {e}")
    
    # Indicator Analysis
    async def analyze_indicator(self, analysis_request: IndicatorAnalysisRequest) -> Dict[str, Any]:
        """Analyze a single indicator"""
        # Check if indicator exists in EDR data
        indicator = self.db.query(EDRIndicator).filter(
            EDRIndicator.indicator_value == analysis_request.indicator_value
        ).first()
        
        if not indicator:
            # Create temporary indicator for analysis
            indicator = EDRIndicator(
                extraction_id=0,  # Temporary
                indicator_type=analysis_request.indicator_type,
                indicator_value=analysis_request.indicator_value,
                context_data=analysis_request.context_data
            )
        
        # Check threat intelligence
        threat_matches = await self.comparison_service.find_threat_intelligence_matches(
            indicator.indicator_value
        )
        
        result = {
            "indicator_id": indicator.id if indicator.id else None,
            "indicator_value": indicator.indicator_value,
            "indicator_type": indicator.indicator_type,
            "is_known_threat": len(threat_matches) > 0,
            "threat_intel_matches": threat_matches,
            "llm_analysis": None,
            "malicious_probability": None,
            "analysis_confidence": None,
            "recommended_actions": None,
            "processing_time": None,
            "cost": None
        }
        
        # If not in threat intelligence, analyze with LLM
        if len(threat_matches) == 0:
            llm_config = self.db.query(LLMConfiguration).filter(
                LLMConfiguration.is_active == True
            ).first()
            
            if llm_config:
                analysis_result = await self.llm_service.analyze_indicator(
                    indicator=indicator,
                    llm_config=llm_config
                )
                
                result.update({
                    "llm_analysis": analysis_result,
                    "malicious_probability": analysis_result.get("malicious_probability"),
                    "analysis_confidence": analysis_result.get("analysis_confidence"),
                    "recommended_actions": analysis_result.get("recommended_actions"),
                    "processing_time": analysis_result.get("processing_time"),
                    "cost": analysis_result.get("cost")
                })
        
        return result
    
    async def bulk_analyze_indicators(self, bulk_request: BulkAnalysisRequest) -> List[Dict[str, Any]]:
        """Analyze multiple indicators"""
        results = []
        
        for indicator_id in bulk_request.indicator_ids:
            indicator = self.db.query(EDRIndicator).filter(EDRIndicator.id == indicator_id).first()
            if indicator:
                analysis_request = IndicatorAnalysisRequest(
                    indicator_type=indicator.indicator_type,
                    indicator_value=indicator.indicator_value,
                    context_data=indicator.context_data
                )
                result = await self.analyze_indicator(analysis_request)
                results.append(result)
        
        return results
    
    # Dashboard and Statistics
    def get_dashboard_stats(self) -> Dict[str, Any]:
        """Get EDR dashboard statistics"""
        total_connections = self.db.query(EDRConnection).count()
        active_connections = self.db.query(EDRConnection).filter(EDRConnection.is_active == True).count()
        
        total_extractions = self.db.query(EDRExtraction).count()
        total_indicators = self.db.query(EDRIndicator).count()
        
        unknown_indicators = self.db.query(EDRIndicator).filter(
            EDRIndicator.is_known_threat == False
        ).count()
        
        analyzed_indicators = self.db.query(EDRAnalysis).count()
        
        malicious_indicators = self.db.query(EDRAnalysis).filter(
            EDRAnalysis.malicious_probability >= 0.7
        ).count()
        
        total_llm_cost = self.db.query(EDRAnalysis).with_entities(
            EDRAnalysis.cost
        ).all()
        total_cost = sum([cost[0] for cost in total_llm_cost if cost[0]])
        
        # Last 24 hours
        last_24h = datetime.utcnow() - timedelta(hours=24)
        last_24h_indicators = self.db.query(EDRIndicator).filter(
            EDRIndicator.created_at >= last_24h
        ).count()
        
        last_24h_analyses = self.db.query(EDRAnalysis).filter(
            EDRAnalysis.created_at >= last_24h
        ).count()
        
        return {
            "total_connections": total_connections,
            "active_connections": active_connections,
            "total_extractions": total_extractions,
            "total_indicators": total_indicators,
            "unknown_indicators": unknown_indicators,
            "analyzed_indicators": analyzed_indicators,
            "malicious_indicators": malicious_indicators,
            "total_llm_cost": total_cost,
            "last_24h_indicators": last_24h_indicators,
            "last_24h_analyses": last_24h_analyses
        }
    
    def get_connection_status(self, connection_id: int) -> Dict[str, Any]:
        """Get connection status and statistics"""
        connection = self.get_connection(connection_id)
        if not connection:
            return {"error": "Connection not found"}
        
        total_extractions = self.db.query(EDRExtraction).filter(
            EDRExtraction.connection_id == connection_id
        ).count()
        
        total_indicators = self.db.query(EDRIndicator).join(EDRExtraction).filter(
            EDRExtraction.connection_id == connection_id
        ).count()
        
        unknown_indicators = self.db.query(EDRIndicator).join(EDRExtraction).filter(
            and_(
                EDRExtraction.connection_id == connection_id,
                EDRIndicator.is_known_threat == False
            )
        ).count()
        
        analyzed_indicators = self.db.query(EDRAnalysis).filter(
            EDRAnalysis.connection_id == connection_id
        ).count()
        
        return {
            "id": connection.id,
            "name": connection.name,
            "platform": connection.platform,
            "is_active": connection.is_active,
            "last_sync": connection.last_sync,
            "status": "active" if connection.is_active else "inactive",
            "total_extractions": total_extractions,
            "total_indicators": total_indicators,
            "unknown_indicators": unknown_indicators,
            "analyzed_indicators": analyzed_indicators
        }
