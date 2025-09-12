from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, func
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
import hashlib
import re
from loguru import logger

from app.models.threat_intelligence import (
    ThreatIndicator, ThreatSource, ThreatCampaign, 
    IndicatorDuplicate, FeedConfiguration, FetchJob
)
from app.schemas.threat_intelligence import (
    ThreatIndicatorCreate, ThreatIndicatorUpdate,
    ThreatSourceCreate, ThreatSourceUpdate,
    IndicatorType, ThreatLevel, SourceType
)
from app.services.exclusion_service import ExclusionService


class ThreatIntelligenceService:
    """Service for managing threat intelligence data"""
    
    def __init__(self, db: Session):
        self.db = db
        self.exclusion_service = ExclusionService(db)
    
    def normalize_indicator(self, indicator_type: str, value: str) -> str:
        """Normalize indicator value for deduplication"""
        if indicator_type == IndicatorType.IP:
            # Normalize IP addresses
            return self._normalize_ip(value)
        elif indicator_type == IndicatorType.DOMAIN:
            # Normalize domains
            return self._normalize_domain(value)
        elif indicator_type == IndicatorType.URL:
            # Normalize URLs
            return self._normalize_url(value)
        elif indicator_type == IndicatorType.HASH:
            # Normalize hashes (lowercase)
            return value.lower()
        elif indicator_type == IndicatorType.EMAIL:
            # Normalize emails (lowercase)
            return value.lower()
        else:
            return value.lower()
    
    def _normalize_ip(self, ip: str) -> str:
        """Normalize IP address"""
        # Remove any whitespace and convert to lowercase
        ip = ip.strip().lower()
        
        # Handle IPv4
        if re.match(r'^\d+\.\d+\.\d+\.\d+$', ip):
            parts = ip.split('.')
            return '.'.join(str(int(part)) for part in parts)
        
        # Handle IPv6 (basic normalization)
        if ':' in ip:
            return ip.lower()
        
        return ip
    
    def _normalize_domain(self, domain: str) -> str:
        """Normalize domain name"""
        domain = domain.strip().lower()
        
        # Remove protocol if present
        if domain.startswith(('http://', 'https://')):
            domain = domain.split('://', 1)[1]
        
        # Remove path and query parameters
        domain = domain.split('/')[0]
        
        # Remove port if present
        if ':' in domain:
            domain = domain.split(':')[0]
        
        return domain
    
    def _normalize_url(self, url: str) -> str:
        """Normalize URL"""
        url = url.strip().lower()
        
        # Remove protocol
        if url.startswith(('http://', 'https://')):
            url = url.split('://', 1)[1]
        
        # Remove query parameters and fragments
        url = url.split('?')[0].split('#')[0]
        
        return url
    
    def create_indicator(self, indicator_data: ThreatIndicatorCreate) -> ThreatIndicator:
        """Create a new threat indicator"""
        # Normalize the value
        normalized_value = self.normalize_indicator(
            indicator_data.indicator_type, 
            indicator_data.value
        )
        
        # Check for existing indicator
        existing = self.db.query(ThreatIndicator).filter(
            and_(
                ThreatIndicator.indicator_type == indicator_data.indicator_type,
                ThreatIndicator.normalized_value == normalized_value
            )
        ).first()
        
        if existing:
            # Update existing indicator
            existing.last_seen = datetime.utcnow()
            existing.confidence_score = max(
                existing.confidence_score, 
                indicator_data.confidence_score
            )
            if indicator_data.threat_level != ThreatLevel.LOW:
                existing.threat_level = indicator_data.threat_level
            
            # Merge tags
            if indicator_data.tags:
                existing_tags = existing.tags or []
                existing.tags = list(set(existing_tags + indicator_data.tags))
            
            # Merge metadata
            if indicator_data.metadata:
                existing_metadata = existing.metadata or {}
                existing_metadata.update(indicator_data.metadata)
                existing.metadata = existing_metadata
            
            self.db.commit()
            return existing
        
        # Create new indicator
        indicator = ThreatIndicator(
            indicator_type=indicator_data.indicator_type,
            value=indicator_data.value,
            normalized_value=normalized_value,
            confidence_score=indicator_data.confidence_score,
            threat_level=indicator_data.threat_level,
            tags=indicator_data.tags,
            description=indicator_data.description,
            source_id=indicator_data.source_id,
            external_id=indicator_data.external_id,
            metadata=indicator_data.metadata
        )
        
        self.db.add(indicator)
        self.db.commit()
        self.db.refresh(indicator)
        
        return indicator
    
    def get_indicators(
        self,
        skip: int = 0,
        limit: int = 100,
        indicator_type: Optional[IndicatorType] = None,
        threat_level: Optional[ThreatLevel] = None,
        source_id: Optional[int] = None,
        tags: Optional[List[str]] = None,
        search: Optional[str] = None,
        include_excluded: bool = False
    ) -> List[ThreatIndicator]:
        """Get threat indicators with filtering and exclusion checking"""
        query = self.db.query(ThreatIndicator)
        
        if indicator_type:
            query = query.filter(ThreatIndicator.indicator_type == indicator_type)
        
        if threat_level:
            query = query.filter(ThreatIndicator.threat_level == threat_level)
        
        if source_id:
            query = query.filter(ThreatIndicator.source_id == source_id)
        
        if tags:
            for tag in tags:
                query = query.filter(ThreatIndicator.tags.contains([tag]))
        
        if search:
            search_filter = or_(
                ThreatIndicator.value.ilike(f"%{search}%"),
                ThreatIndicator.description.ilike(f"%{search}%")
            )
            query = query.filter(search_filter)
        
        # Get all indicators first
        all_indicators = query.offset(skip).limit(limit).all()
        
        # Apply exclusions if not including excluded indicators
        if not include_excluded:
            filtered_indicators = []
            for indicator in all_indicators:
                if not self.exclusion_service.is_indicator_excluded(
                    indicator.indicator_type, 
                    indicator.value
                ):
                    filtered_indicators.append(indicator)
            return filtered_indicators
        
        return all_indicators
    
    def get_indicator_by_id(self, indicator_id: int) -> Optional[ThreatIndicator]:
        """Get indicator by ID"""
        return self.db.query(ThreatIndicator).filter(
            ThreatIndicator.id == indicator_id
        ).first()
    
    def update_indicator(
        self, 
        indicator_id: int, 
        update_data: ThreatIndicatorUpdate
    ) -> Optional[ThreatIndicator]:
        """Update threat indicator"""
        indicator = self.get_indicator_by_id(indicator_id)
        if not indicator:
            return None
        
        for field, value in update_data.dict(exclude_unset=True).items():
            setattr(indicator, field, value)
        
        indicator.updated_at = datetime.utcnow()
        self.db.commit()
        self.db.refresh(indicator)
        
        return indicator
    
    def delete_indicator(self, indicator_id: int) -> bool:
        """Delete threat indicator"""
        indicator = self.get_indicator_by_id(indicator_id)
        if not indicator:
            return False
        
        self.db.delete(indicator)
        self.db.commit()
        return True
    
    def get_indicators_summary(self) -> Dict[str, Any]:
        """Get summary statistics of indicators"""
        total = self.db.query(ThreatIndicator).count()
        
        # Count by type
        by_type = self.db.query(
            ThreatIndicator.indicator_type,
            func.count(ThreatIndicator.id)
        ).group_by(ThreatIndicator.indicator_type).all()
        
        # Count by threat level
        by_level = self.db.query(
            ThreatIndicator.threat_level,
            func.count(ThreatIndicator.id)
        ).group_by(ThreatIndicator.threat_level).all()
        
        # Active sources
        active_sources = self.db.query(ThreatSource).filter(
            ThreatSource.is_active == True
        ).count()
        
        return {
            "total_indicators": total,
            "indicators_by_type": dict(by_type),
            "indicators_by_level": dict(by_level),
            "active_sources": active_sources,
            "last_update": datetime.utcnow()
        }
    
    def deduplicate_indicators(self) -> Dict[str, Any]:
        """Perform deduplication of indicators"""
        start_time = datetime.utcnow()
        
        # Get all indicators
        indicators = self.db.query(ThreatIndicator).all()
        original_count = len(indicators)
        
        # Group by normalized value and type
        groups = {}
        for indicator in indicators:
            key = (indicator.indicator_type, indicator.normalized_value)
            if key not in groups:
                groups[key] = []
            groups[key].append(indicator)
        
        duplicates_found = 0
        deduplicated_count = 0
        
        for key, group in groups.items():
            if len(group) > 1:
                # Keep the one with highest confidence score
                primary = max(group, key=lambda x: x.confidence_score)
                
                for indicator in group:
                    if indicator.id != primary.id:
                        # Mark as duplicate
                        duplicate = IndicatorDuplicate(
                            indicator_id=primary.id,
                            duplicate_indicator_id=indicator.id,
                            similarity_score=1.0  # Exact match
                        )
                        self.db.add(duplicate)
                        
                        # Deactivate duplicate
                        indicator.is_active = False
                        duplicates_found += 1
                
                deduplicated_count += len(group) - 1
        
        self.db.commit()
        
        processing_time = (datetime.utcnow() - start_time).total_seconds()
        
        return {
            "original_count": original_count,
            "deduplicated_count": original_count - duplicates_found,
            "duplicates_found": duplicates_found,
            "processing_time": processing_time
        }
    
    def create_source(self, source_data: ThreatSourceCreate) -> ThreatSource:
        """Create a new threat source"""
        source = ThreatSource(**source_data.dict())
        self.db.add(source)
        self.db.commit()
        self.db.refresh(source)
        return source
    
    def get_sources(self, active_only: bool = True) -> List[ThreatSource]:
        """Get threat sources"""
        query = self.db.query(ThreatSource)
        if active_only:
            query = query.filter(ThreatSource.is_active == True)
        return query.all()
    
    def update_source(
        self, 
        source_id: int, 
        update_data: ThreatSourceUpdate
    ) -> Optional[ThreatSource]:
        """Update threat source"""
        source = self.db.query(ThreatSource).filter(
            ThreatSource.id == source_id
        ).first()
        
        if not source:
            return None
        
        for field, value in update_data.dict(exclude_unset=True).items():
            setattr(source, field, value)
        
        source.updated_at = datetime.utcnow()
        self.db.commit()
        self.db.refresh(source)
        
        return source
