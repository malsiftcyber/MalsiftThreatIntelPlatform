import re
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_
from typing import List, Dict, Any, Optional
from datetime import datetime
from loguru import logger

from app.models.threat_intelligence import IndicatorExclusion, ThreatIndicator
from app.schemas.threat_intelligence import (
    IndicatorExclusionCreate, IndicatorExclusionUpdate,
    PatternType, IndicatorType, ExclusionTestResult
)


class ExclusionService:
    """Service for managing indicator exclusions"""
    
    def __init__(self, db: Session):
        self.db = db
    
    def create_exclusion(self, exclusion_data: IndicatorExclusionCreate) -> IndicatorExclusion:
        """Create a new indicator exclusion"""
        exclusion = IndicatorExclusion(**exclusion_data.dict())
        self.db.add(exclusion)
        self.db.commit()
        self.db.refresh(exclusion)
        return exclusion
    
    def get_exclusions(
        self,
        skip: int = 0,
        limit: int = 100,
        indicator_type: Optional[IndicatorType] = None,
        pattern_type: Optional[PatternType] = None,
        is_active: Optional[bool] = None
    ) -> List[IndicatorExclusion]:
        """Get exclusions with filtering"""
        query = self.db.query(IndicatorExclusion)
        
        if indicator_type:
            query = query.filter(IndicatorExclusion.indicator_type == indicator_type)
        
        if pattern_type:
            query = query.filter(IndicatorExclusion.pattern_type == pattern_type)
        
        if is_active is not None:
            query = query.filter(IndicatorExclusion.is_active == is_active)
        
        return query.offset(skip).limit(limit).all()
    
    def get_exclusion_by_id(self, exclusion_id: int) -> Optional[IndicatorExclusion]:
        """Get exclusion by ID"""
        return self.db.query(IndicatorExclusion).filter(
            IndicatorExclusion.id == exclusion_id
        ).first()
    
    def update_exclusion(
        self, 
        exclusion_id: int, 
        update_data: IndicatorExclusionUpdate
    ) -> Optional[IndicatorExclusion]:
        """Update an exclusion"""
        exclusion = self.get_exclusion_by_id(exclusion_id)
        if not exclusion:
            return None
        
        for field, value in update_data.dict(exclude_unset=True).items():
            setattr(exclusion, field, value)
        
        exclusion.updated_at = datetime.utcnow()
        self.db.commit()
        self.db.refresh(exclusion)
        return exclusion
    
    def delete_exclusion(self, exclusion_id: int) -> bool:
        """Delete an exclusion"""
        exclusion = self.get_exclusion_by_id(exclusion_id)
        if not exclusion:
            return False
        
        self.db.delete(exclusion)
        self.db.commit()
        return True
    
    def is_indicator_excluded(self, indicator_type: str, value: str) -> bool:
        """Check if an indicator should be excluded from API responses"""
        # Get all active exclusions for this indicator type
        exclusions = self.db.query(IndicatorExclusion).filter(
            and_(
                IndicatorExclusion.is_active == True,
                or_(
                    IndicatorExclusion.indicator_type == indicator_type,
                    IndicatorExclusion.indicator_type == "all"
                )
            )
        ).all()
        
        for exclusion in exclusions:
            if self._matches_pattern(value, exclusion.value, exclusion.pattern_type):
                logger.info(f"Indicator {value} excluded by rule {exclusion.id}: {exclusion.reason}")
                return True
        
        return False
    
    def _matches_pattern(self, value: str, pattern: str, pattern_type: PatternType) -> bool:
        """Check if a value matches a pattern"""
        if pattern_type == PatternType.EXACT:
            return value.lower() == pattern.lower()
        
        elif pattern_type == PatternType.REGEX:
            try:
                return bool(re.search(pattern, value, re.IGNORECASE))
            except re.error:
                logger.error(f"Invalid regex pattern: {pattern}")
                return False
        
        elif pattern_type == PatternType.WILDCARD:
            # Convert wildcard pattern to regex
            regex_pattern = pattern.replace("*", ".*").replace("?", ".")
            try:
                return bool(re.search(regex_pattern, value, re.IGNORECASE))
            except re.error:
                logger.error(f"Invalid wildcard pattern: {pattern}")
                return False
        
        return False
    
    def test_exclusion_pattern(
        self, 
        pattern: str, 
        pattern_type: PatternType, 
        indicator_type: Optional[IndicatorType] = None
    ) -> ExclusionTestResult:
        """Test an exclusion pattern against existing indicators"""
        # Get indicators to test against
        query = self.db.query(ThreatIndicator)
        if indicator_type:
            query = query.filter(ThreatIndicator.indicator_type == indicator_type)
        
        indicators = query.limit(1000).all()  # Limit for performance
        
        matches = []
        for indicator in indicators:
            if self._matches_pattern(indicator.value, pattern, pattern_type):
                matches.append({
                    "id": indicator.id,
                    "value": indicator.value,
                    "indicator_type": indicator.indicator_type,
                    "threat_level": indicator.threat_level,
                    "source_id": indicator.source_id
                })
        
        return ExclusionTestResult(
            matches=matches,
            total_matches=len(matches),
            test_value=pattern,
            test_type=pattern_type
        )
    
    def get_exclusion_stats(self) -> Dict[str, Any]:
        """Get statistics about exclusions"""
        total_exclusions = self.db.query(IndicatorExclusion).count()
        active_exclusions = self.db.query(IndicatorExclusion).filter(
            IndicatorExclusion.is_active == True
        ).count()
        
        # Count by type
        by_type = self.db.query(
            IndicatorExclusion.indicator_type,
            self.db.func.count(IndicatorExclusion.id)
        ).group_by(IndicatorExclusion.indicator_type).all()
        
        # Count by pattern type
        by_pattern = self.db.query(
            IndicatorExclusion.pattern_type,
            self.db.func.count(IndicatorExclusion.id)
        ).group_by(IndicatorExclusion.pattern_type).all()
        
        return {
            "total_exclusions": total_exclusions,
            "active_exclusions": active_exclusions,
            "exclusions_by_type": dict(by_type),
            "exclusions_by_pattern": dict(by_pattern)
        }
    
    def bulk_create_exclusions(self, exclusions_data: List[IndicatorExclusionCreate]) -> List[IndicatorExclusion]:
        """Create multiple exclusions at once"""
        exclusions = []
        for exclusion_data in exclusions_data:
            exclusion = IndicatorExclusion(**exclusion_data.dict())
            exclusions.append(exclusion)
        
        self.db.add_all(exclusions)
        self.db.commit()
        
        for exclusion in exclusions:
            self.db.refresh(exclusion)
        
        return exclusions
    
    def import_exclusions_from_file(self, file_content: str) -> List[IndicatorExclusion]:
        """Import exclusions from a CSV or JSON file"""
        # This is a basic implementation - could be enhanced for different file formats
        exclusions = []
        
        try:
            import json
            data = json.loads(file_content)
            
            for item in data:
                exclusion_data = IndicatorExclusionCreate(
                    indicator_type=item.get("indicator_type", "all"),
                    value=item["value"],
                    pattern_type=item.get("pattern_type", "exact"),
                    reason=item.get("reason", "Imported from file"),
                    excluded_by=item.get("excluded_by", "system")
                )
                exclusions.append(self.create_exclusion(exclusion_data))
                
        except json.JSONDecodeError:
            # Try CSV format
            lines = file_content.strip().split('\n')
            headers = lines[0].split(',')
            
            for line in lines[1:]:
                values = line.split(',')
                if len(values) >= 2:
                    exclusion_data = IndicatorExclusionCreate(
                        indicator_type=values[0] if len(values) > 0 else "all",
                        value=values[1] if len(values) > 1 else "",
                        pattern_type=values[2] if len(values) > 2 else "exact",
                        reason=values[3] if len(values) > 3 else "Imported from file",
                        excluded_by=values[4] if len(values) > 4 else "system"
                    )
                    exclusions.append(self.create_exclusion(exclusion_data))
        
        return exclusions
