from typing import Dict, List, Tuple, Optional
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from sqlalchemy import func, and_, or_
import pandas as pd
from loguru import logger

from app.models.threat_intelligence import ThreatIndicator, ThreatSource
from app.core.config import settings


class FeedComparisonService:
    """Service for comparing open source and premium threat intelligence feeds"""
    
    def __init__(self, db: Session):
        self.db = db
    
    def get_feed_categories(self) -> Dict[str, List[str]]:
        """Define feed categories"""
        return {
            "open_source": [
                "CISA", "AlienVault OTX", "PhishTank", "URLhaus", 
                "Binary Defense", "Botvrij.eu", "BruteForceBlocker",
                "Emerging Threats", "OpenPhish", "MalwareBazaar", 
                "Feodo Tracker", "AbuseIPDB"
            ],
            "premium": [
                "Crowdstrike Falcon", "Mandiant Threat Intelligence", 
                "Recorded Future", "Nordstellar", "Anomali Threatstream",
                "FBI InfraGuard", "VirusTotal", "ThreatFox"
            ]
        }
    
    def get_indicators_by_category(self, days: int = 30) -> Dict[str, List[Dict]]:
        """Get indicators grouped by feed category"""
        since_date = datetime.utcnow() - timedelta(days=days)
        
        categories = self.get_feed_categories()
        results = {"open_source": [], "premium": []}
        
        for category, sources in categories.items():
            indicators = self.db.query(ThreatIndicator).join(ThreatSource).filter(
                and_(
                    ThreatIndicator.created_at >= since_date,
                    ThreatSource.name.in_(sources)
                )
            ).all()
            
            results[category] = [
                {
                    "id": ind.id,
                    "value": ind.value,
                    "type": ind.type,
                    "confidence": ind.confidence,
                    "source": ind.source.name,
                    "created_at": ind.created_at.isoformat()
                }
                for ind in indicators
            ]
        
        return results
    
    def calculate_overlap_percentage(self, days: int = 30) -> Dict[str, float]:
        """Calculate percentage overlap between open source and premium feeds"""
        indicators = self.get_indicators_by_category(days)
        
        # Convert to sets for comparison
        open_source_values = set(ind["value"] for ind in indicators["open_source"])
        premium_values = set(ind["value"] for ind in indicators["premium"])
        
        # Calculate overlaps
        total_open_source = len(open_source_values)
        total_premium = len(premium_values)
        
        if total_open_source == 0 or total_premium == 0:
            return {
                "open_source_coverage": 0.0,
                "premium_coverage": 0.0,
                "overlap_percentage": 0.0,
                "unique_open_source": 0,
                "unique_premium": 0,
                "shared_indicators": 0
            }
        
        # Find overlapping indicators
        overlap = open_source_values.intersection(premium_values)
        overlap_count = len(overlap)
        
        # Calculate percentages
        open_source_coverage = (overlap_count / total_premium) * 100 if total_premium > 0 else 0
        premium_coverage = (overlap_count / total_open_source) * 100 if total_open_source > 0 else 0
        overlap_percentage = (overlap_count / (total_open_source + total_premium - overlap_count)) * 100
        
        return {
            "open_source_coverage": round(open_source_coverage, 2),
            "premium_coverage": round(premium_coverage, 2),
            "overlap_percentage": round(overlap_percentage, 2),
            "unique_open_source": total_open_source - overlap_count,
            "unique_premium": total_premium - overlap_count,
            "shared_indicators": overlap_count,
            "total_open_source": total_open_source,
            "total_premium": total_premium
        }
    
    def get_comparison_by_type(self, days: int = 30) -> Dict[str, Dict]:
        """Compare feeds by indicator type (IP, domain, URL, hash)"""
        since_date = datetime.utcnow() - timedelta(days=days)
        categories = self.get_feed_categories()
        
        results = {}
        
        for indicator_type in ["ip", "domain", "url", "hash"]:
            open_source_indicators = self.db.query(ThreatIndicator).join(ThreatSource).filter(
                and_(
                    ThreatIndicator.created_at >= since_date,
                    ThreatIndicator.type == indicator_type,
                    ThreatSource.name.in_(categories["open_source"])
                )
            ).all()
            
            premium_indicators = self.db.query(ThreatIndicator).join(ThreatSource).filter(
                and_(
                    ThreatIndicator.created_at >= since_date,
                    ThreatIndicator.type == indicator_type,
                    ThreatSource.name.in_(categories["premium"])
                )
            ).all()
            
            open_source_values = set(ind.value for ind in open_source_indicators)
            premium_values = set(ind.value for ind in premium_indicators)
            
            overlap = open_source_values.intersection(premium_values)
            overlap_count = len(overlap)
            
            total_open_source = len(open_source_values)
            total_premium = len(premium_values)
            
            if total_open_source == 0 or total_premium == 0:
                results[indicator_type] = {
                    "open_source_count": 0,
                    "premium_count": 0,
                    "overlap_count": 0,
                    "open_source_coverage": 0.0,
                    "premium_coverage": 0.0
                }
            else:
                open_source_coverage = (overlap_count / total_premium) * 100
                premium_coverage = (overlap_count / total_open_source) * 100
                
                results[indicator_type] = {
                    "open_source_count": total_open_source,
                    "premium_count": total_premium,
                    "overlap_count": overlap_count,
                    "open_source_coverage": round(open_source_coverage, 2),
                    "premium_coverage": round(premium_coverage, 2)
                }
        
        return results
    
    def get_source_comparison(self, days: int = 30) -> Dict[str, Dict]:
        """Compare individual sources within categories"""
        since_date = datetime.utcnow() - timedelta(days=days)
        categories = self.get_feed_categories()
        
        results = {}
        
        for category, sources in categories.items():
            category_results = {}
            
            for source in sources:
                indicators = self.db.query(ThreatIndicator).join(ThreatSource).filter(
                    and_(
                        ThreatIndicator.created_at >= since_date,
                        ThreatSource.name == source
                    )
                ).all()
                
                if indicators:
                    category_results[source] = {
                        "total_indicators": len(indicators),
                        "unique_indicators": len(set(ind.value for ind in indicators)),
                        "types": list(set(ind.type for ind in indicators)),
                        "avg_confidence": round(
                            sum(ind.confidence for ind in indicators) / len(indicators), 2
                        ) if indicators else 0,
                        "latest_update": max(ind.created_at for ind in indicators).isoformat()
                    }
                else:
                    category_results[source] = {
                        "total_indicators": 0,
                        "unique_indicators": 0,
                        "types": [],
                        "avg_confidence": 0,
                        "latest_update": None
                    }
            
            results[category] = category_results
        
        return results
    
    def get_trend_data(self, days: int = 30) -> Dict[str, List]:
        """Get trend data for feed comparison over time"""
        since_date = datetime.utcnow() - timedelta(days=days)
        categories = self.get_feed_categories()
        
        # Get daily data
        daily_data = []
        for i in range(days):
            date = since_date + timedelta(days=i)
            next_date = date + timedelta(days=1)
            
            open_source_count = self.db.query(ThreatIndicator).join(ThreatSource).filter(
                and_(
                    ThreatIndicator.created_at >= date,
                    ThreatIndicator.created_at < next_date,
                    ThreatSource.name.in_(categories["open_source"])
                )
            ).count()
            
            premium_count = self.db.query(ThreatIndicator).join(ThreatSource).filter(
                and_(
                    ThreatIndicator.created_at >= date,
                    ThreatIndicator.created_at < next_date,
                    ThreatSource.name.in_(categories["premium"])
                )
            ).count()
            
            daily_data.append({
                "date": date.strftime("%Y-%m-%d"),
                "open_source": open_source_count,
                "premium": premium_count
            })
        
        return {"daily_data": daily_data}
    
    def get_comprehensive_comparison(self, days: int = 30) -> Dict:
        """Get comprehensive comparison data for dashboard"""
        try:
            return {
                "overview": self.calculate_overlap_percentage(days),
                "by_type": self.get_comparison_by_type(days),
                "by_source": self.get_source_comparison(days),
                "trends": self.get_trend_data(days),
                "last_updated": datetime.utcnow().isoformat(),
                "period_days": days
            }
        except Exception as e:
            logger.error(f"Error calculating feed comparison: {e}")
            return {
                "error": "Failed to calculate feed comparison",
                "last_updated": datetime.utcnow().isoformat()
            }
