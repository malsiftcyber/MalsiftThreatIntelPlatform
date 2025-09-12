from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, func
import re
from urllib.parse import urlparse
import ipaddress
from loguru import logger

from app.models.edr.edr_models import EDRIndicator, ThreatIntelligenceMatch
from app.models.threat_intelligence import ThreatIndicator


class IndicatorComparisonService:
    """Service for comparing EDR indicators with threat intelligence"""
    
    def __init__(self, db: Session):
        self.db = db
    
    async def check_threat_intelligence(self, indicator_value: str) -> bool:
        """Check if indicator exists in threat intelligence"""
        matches = await self.find_threat_intelligence_matches(indicator_value)
        return len(matches) > 0
    
    async def find_threat_intelligence_matches(self, indicator_value: str) -> List[Dict[str, Any]]:
        """Find threat intelligence matches for an indicator"""
        matches = []
        
        # Try different matching strategies
        exact_matches = self._find_exact_matches(indicator_value)
        fuzzy_matches = self._find_fuzzy_matches(indicator_value)
        domain_matches = self._find_domain_matches(indicator_value)
        
        matches.extend(exact_matches)
        matches.extend(fuzzy_matches)
        matches.extend(domain_matches)
        
        # Remove duplicates and sort by confidence
        unique_matches = self._deduplicate_matches(matches)
        return sorted(unique_matches, key=lambda x: x["match_confidence"], reverse=True)
    
    def _find_exact_matches(self, indicator_value: str) -> List[Dict[str, Any]]:
        """Find exact matches in threat intelligence"""
        matches = []
        
        # Exact match
        threat_indicators = self.db.query(ThreatIndicator).filter(
            ThreatIndicator.value == indicator_value
        ).all()
        
        for ti in threat_indicators:
            matches.append({
                "threat_indicator_id": ti.id,
                "match_type": "exact",
                "match_confidence": 1.0,
                "match_details": {
                    "source": ti.source.name,
                    "confidence": ti.confidence,
                    "threat_level": ti.threat_level,
                    "tags": ti.tags,
                    "description": ti.description
                }
            })
        
        return matches
    
    def _find_fuzzy_matches(self, indicator_value: str) -> List[Dict[str, Any]]:
        """Find fuzzy matches in threat intelligence"""
        matches = []
        
        # Normalize indicator for fuzzy matching
        normalized_value = self._normalize_indicator(indicator_value)
        
        if not normalized_value:
            return matches
        
        # Fuzzy match on normalized value
        threat_indicators = self.db.query(ThreatIndicator).filter(
            ThreatIndicator.value.like(f"%{normalized_value}%")
        ).all()
        
        for ti in threat_indicators:
            similarity = self._calculate_similarity(normalized_value, ti.value)
            if similarity >= 0.8:  # Threshold for fuzzy match
                matches.append({
                    "threat_indicator_id": ti.id,
                    "match_type": "fuzzy",
                    "match_confidence": similarity,
                    "match_details": {
                        "source": ti.source.name,
                        "confidence": ti.confidence,
                        "threat_level": ti.threat_level,
                        "tags": ti.tags,
                        "description": ti.description,
                        "similarity_score": similarity
                    }
                })
        
        return matches
    
    def _find_domain_matches(self, indicator_value: str) -> List[Dict[str, Any]]:
        """Find domain-based matches"""
        matches = []
        
        # Extract domain from URL or email
        domain = self._extract_domain(indicator_value)
        if not domain:
            return matches
        
        # Find matches for the domain
        threat_indicators = self.db.query(ThreatIndicator).filter(
            or_(
                ThreatIndicator.value == domain,
                ThreatIndicator.value.like(f"%{domain}%")
            )
        ).all()
        
        for ti in threat_indicators:
            if ti.value == domain:
                confidence = 1.0
                match_type = "exact_domain"
            else:
                confidence = 0.8
                match_type = "domain_based"
            
            matches.append({
                "threat_indicator_id": ti.id,
                "match_type": match_type,
                "match_confidence": confidence,
                "match_details": {
                    "source": ti.source.name,
                    "confidence": ti.confidence,
                    "threat_level": ti.threat_level,
                    "tags": ti.tags,
                    "description": ti.description,
                    "extracted_domain": domain
                }
            })
        
        return matches
    
    def _normalize_indicator(self, indicator_value: str) -> Optional[str]:
        """Normalize indicator for comparison"""
        if not indicator_value:
            return None
        
        # Remove common prefixes/suffixes
        normalized = indicator_value.lower().strip()
        
        # Remove protocol from URLs
        if normalized.startswith(('http://', 'https://')):
            normalized = normalized.split('://', 1)[1]
        
        # Remove www prefix
        if normalized.startswith('www.'):
            normalized = normalized[4:]
        
        # Remove trailing slash
        normalized = normalized.rstrip('/')
        
        return normalized
    
    def _extract_domain(self, indicator_value: str) -> Optional[str]:
        """Extract domain from indicator"""
        try:
            # If it's a URL
            if '://' in indicator_value or indicator_value.startswith('www.'):
                parsed = urlparse(indicator_value if '://' in indicator_value else f'http://{indicator_value}')
                domain = parsed.netloc or parsed.path.split('/')[0]
                return domain.lower()
            
            # If it's an email
            if '@' in indicator_value:
                return indicator_value.split('@')[1].lower()
            
            # If it's already a domain (contains dots but no protocol)
            if '.' in indicator_value and not indicator_value.startswith(('http://', 'https://')):
                return indicator_value.lower()
            
            return None
            
        except Exception:
            return None
    
    def _calculate_similarity(self, str1: str, str2: str) -> float:
        """Calculate similarity between two strings"""
        if not str1 or not str2:
            return 0.0
        
        # Simple Jaccard similarity
        set1 = set(str1.lower())
        set2 = set(str2.lower())
        
        intersection = len(set1.intersection(set2))
        union = len(set1.union(set2))
        
        if union == 0:
            return 0.0
        
        return intersection / union
    
    def _deduplicate_matches(self, matches: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Remove duplicate matches"""
        seen = set()
        unique_matches = []
        
        for match in matches:
            key = match["threat_indicator_id"]
            if key not in seen:
                seen.add(key)
                unique_matches.append(match)
        
        return unique_matches
    
    def create_threat_intelligence_match(self, edr_indicator_id: int, threat_indicator_id: int, 
                                       match_type: str, match_confidence: float, 
                                       match_details: Dict[str, Any]) -> ThreatIntelligenceMatch:
        """Create a threat intelligence match record"""
        match = ThreatIntelligenceMatch(
            edr_indicator_id=edr_indicator_id,
            threat_indicator_id=threat_indicator_id,
            match_type=match_type,
            match_confidence=match_confidence,
            match_details=match_details
        )
        
        self.db.add(match)
        self.db.commit()
        self.db.refresh(match)
        
        return match
    
    def get_indicator_analysis_summary(self, indicator_value: str) -> Dict[str, Any]:
        """Get comprehensive analysis summary for an indicator"""
        matches = self.find_threat_intelligence_matches(indicator_value)
        
        if not matches:
            return {
                "is_known_threat": False,
                "threat_intel_matches": [],
                "highest_confidence": 0.0,
                "threat_sources": [],
                "recommended_action": "analyze_with_llm"
            }
        
        # Analyze matches
        highest_confidence = max(match["match_confidence"] for match in matches)
        threat_sources = list(set(match["match_details"]["source"] for match in matches))
        
        # Determine recommended action
        if highest_confidence >= 0.9:
            recommended_action = "block_immediately"
        elif highest_confidence >= 0.7:
            recommended_action = "investigate_further"
        else:
            recommended_action = "monitor"
        
        return {
            "is_known_threat": True,
            "threat_intel_matches": matches,
            "highest_confidence": highest_confidence,
            "threat_sources": threat_sources,
            "recommended_action": recommended_action
        }
