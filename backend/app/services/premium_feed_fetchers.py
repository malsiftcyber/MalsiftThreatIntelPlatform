import aiohttp
import asyncio
import requests
import json
import time
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from loguru import logger
import base64
from urllib.parse import urljoin

from app.core.config import settings
from app.models.threat_intelligence import ThreatIndicator, ThreatSource
from app.schemas.threat_intelligence import (
    ThreatIndicatorCreate, IndicatorType, ThreatLevel, SourceType
)
from .feed_fetchers import BaseFeedFetcher


class CrowdStrikeFeedFetcher(BaseFeedFetcher):
    """CrowdStrike Falcon Intelligence feed fetcher"""
    
    def __init__(self, source: ThreatSource):
        super().__init__(source)
        self.access_token = None
        self.token_expires = None
    
    async def _get_access_token(self) -> str:
        """Get OAuth2 access token for CrowdStrike API"""
        if self.access_token and self.token_expires and datetime.now() < self.token_expires:
            return self.access_token
        
        auth_url = f"{settings.CROWDSTRIKE_BASE_URL}/oauth2/token"
        auth_data = {
            "client_id": settings.CROWDSTRIKE_CLIENT_ID,
            "client_secret": settings.CROWDSTRIKE_CLIENT_SECRET
        }
        
        async with self.session.post(auth_url, data=auth_data) as response:
            if response.status == 200:
                token_data = await response.json()
                self.access_token = token_data.get("access_token")
                expires_in = token_data.get("expires_in", 3600)
                self.token_expires = datetime.now() + timedelta(seconds=expires_in - 300)
                return self.access_token
            else:
                raise Exception(f"Failed to get CrowdStrike access token: {response.status}")
    
    async def fetch_indicators(self) -> List[ThreatIndicatorCreate]:
        """Fetch indicators from CrowdStrike Falcon Intelligence"""
        try:
            access_token = await self._get_access_token()
            headers = {
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            }
            
            # Fetch threat intelligence reports
            intel_url = f"{settings.CROWDSTRIKE_BASE_URL}/intel/queries/reports/v1"
            params = {
                "limit": 100,
                "sort": "published_date|desc"
            }
            
            indicators = []
            async with self.session.get(intel_url, headers=headers, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    resources = data.get("resources", [])
                    
                    for report in resources:
                        # Extract indicators from report
                        for indicator in report.get("indicators", []):
                            indicator_type = self._map_indicator_type(indicator.get("type"))
                            if indicator_type:
                                indicators.append(ThreatIndicatorCreate(
                                    value=indicator.get("value"),
                                    indicator_type=indicator_type,
                                    threat_level=ThreatLevel.HIGH,
                                    description=f"CrowdStrike Intel: {report.get('title', 'Unknown')}",
                                    source_id=self.source.id,
                                    first_seen=datetime.fromisoformat(indicator.get("published_date", datetime.now().isoformat())),
                                    last_seen=datetime.now(),
                                    tags=indicator.get("tags", []),
                                    metadata={
                                        "crowdstrike_report_id": report.get("id"),
                                        "malware_family": report.get("malware_family"),
                                        "threat_actors": report.get("threat_actors", [])
                                    }
                                ))
                
                self._rate_limit(60 / settings.CROWDSTRIKE_FREE_LIMIT)  # Rate limiting
                
            return indicators
            
        except Exception as e:
            logger.error(f"Error fetching CrowdStrike indicators: {e}")
            return []
    
    def _map_indicator_type(self, crowdstrike_type: str) -> Optional[IndicatorType]:
        """Map CrowdStrike indicator types to our types"""
        mapping = {
            "domain": IndicatorType.DOMAIN,
            "ipv4": IndicatorType.IP_ADDRESS,
            "ipv6": IndicatorType.IP_ADDRESS,
            "url": IndicatorType.URL,
            "md5": IndicatorType.HASH,
            "sha256": IndicatorType.HASH,
            "sha1": IndicatorType.HASH,
            "email": IndicatorType.EMAIL
        }
        return mapping.get(crowdstrike_type.lower())


class MandiantFeedFetcher(BaseFeedFetcher):
    """Mandiant Threat Intelligence feed fetcher"""
    
    async def fetch_indicators(self) -> List[ThreatIndicatorCreate]:
        """Fetch indicators from Mandiant Threat Intelligence"""
        try:
            headers = {
                "Authorization": f"Bearer {settings.MANDIANT_API_KEY}",
                "Content-Type": "application/json"
            }
            
            # Fetch threat intelligence reports
            reports_url = f"{settings.MANDIANT_BASE_URL}/reports"
            params = {
                "limit": 50,
                "sort": "published_date desc"
            }
            
            indicators = []
            async with self.session.get(reports_url, headers=headers, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    reports = data.get("reports", [])
                    
                    for report in reports:
                        # Extract indicators from report content
                        content = report.get("content", {})
                        for section in content.get("sections", []):
                            for indicator in section.get("indicators", []):
                                indicator_type = self._map_indicator_type(indicator.get("type"))
                                if indicator_type:
                                    indicators.append(ThreatIndicatorCreate(
                                        value=indicator.get("value"),
                                        indicator_type=indicator_type,
                                        threat_level=ThreatLevel.HIGH,
                                        description=f"Mandiant Intel: {report.get('title', 'Unknown')}",
                                        source_id=self.source.id,
                                        first_seen=datetime.fromisoformat(report.get("published_date", datetime.now().isoformat())),
                                        last_seen=datetime.now(),
                                        tags=report.get("tags", []),
                                        metadata={
                                            "mandiant_report_id": report.get("id"),
                                            "threat_actors": report.get("threat_actors", []),
                                            "malware_families": report.get("malware_families", [])
                                        }
                                    ))
                
                self._rate_limit(60 / settings.MANDIANT_FREE_LIMIT)  # Rate limiting
                
            return indicators
            
        except Exception as e:
            logger.error(f"Error fetching Mandiant indicators: {e}")
            return []
    
    def _map_indicator_type(self, mandiant_type: str) -> Optional[IndicatorType]:
        """Map Mandiant indicator types to our types"""
        mapping = {
            "domain": IndicatorType.DOMAIN,
            "ip": IndicatorType.IP_ADDRESS,
            "url": IndicatorType.URL,
            "hash": IndicatorType.HASH,
            "email": IndicatorType.EMAIL,
            "registry": IndicatorType.REGISTRY_KEY
        }
        return mapping.get(mandiant_type.lower())


class RecordedFutureFeedFetcher(BaseFeedFetcher):
    """Recorded Future Threat Intelligence feed fetcher"""
    
    async def fetch_indicators(self) -> List[ThreatIndicatorCreate]:
        """Fetch indicators from Recorded Future"""
        try:
            headers = {
                "X-RFToken": settings.RECORDEDFUTURE_API_KEY,
                "Content-Type": "application/json"
            }
            
            # Fetch threat intelligence
            intel_url = f"{settings.RECORDEDFUTURE_BASE_URL}/intelligence"
            params = {
                "limit": 100,
                "sort": "timestamp desc"
            }
            
            indicators = []
            async with self.session.get(intel_url, headers=headers, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    results = data.get("results", [])
                    
                    for result in results:
                        for entity in result.get("entities", []):
                            indicator_type = self._map_indicator_type(entity.get("type"))
                            if indicator_type:
                                indicators.append(ThreatIndicatorCreate(
                                    value=entity.get("name"),
                                    indicator_type=indicator_type,
                                    threat_level=ThreatLevel.HIGH,
                                    description=f"Recorded Future Intel: {result.get('title', 'Unknown')}",
                                    source_id=self.source.id,
                                    first_seen=datetime.fromtimestamp(result.get("timestamp", time.time())),
                                    last_seen=datetime.now(),
                                    tags=result.get("tags", []),
                                    metadata={
                                        "recordedfuture_id": result.get("id"),
                                        "risk_score": entity.get("risk_score"),
                                        "threat_lists": entity.get("threat_lists", [])
                                    }
                                ))
                
                self._rate_limit(60 / settings.RECORDEDFUTURE_FREE_LIMIT)  # Rate limiting
                
            return indicators
            
        except Exception as e:
            logger.error(f"Error fetching Recorded Future indicators: {e}")
            return []
    
    def _map_indicator_type(self, rf_type: str) -> Optional[IndicatorType]:
        """Map Recorded Future indicator types to our types"""
        mapping = {
            "domain": IndicatorType.DOMAIN,
            "ipaddress": IndicatorType.IP_ADDRESS,
            "url": IndicatorType.URL,
            "hash": IndicatorType.HASH,
            "email": IndicatorType.EMAIL,
            "malware": IndicatorType.MALWARE
        }
        return mapping.get(rf_type.lower())


class NordstellarFeedFetcher(BaseFeedFetcher):
    """Nordstellar Threat Intelligence feed fetcher"""
    
    async def fetch_indicators(self) -> List[ThreatIndicatorCreate]:
        """Fetch indicators from Nordstellar"""
        try:
            headers = {
                "Authorization": f"Bearer {settings.NORDSTELLAR_API_KEY}",
                "Content-Type": "application/json"
            }
            
            # Fetch threat intelligence feeds
            feeds_url = f"{settings.NORDSTELLAR_BASE_URL}/feeds"
            
            indicators = []
            async with self.session.get(feeds_url, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    feeds = data.get("feeds", [])
                    
                    for feed in feeds:
                        feed_id = feed.get("id")
                        feed_url = f"{settings.NORDSTELLAR_BASE_URL}/feeds/{feed_id}/indicators"
                        
                        async with self.session.get(feed_url, headers=headers) as feed_response:
                            if feed_response.status == 200:
                                feed_data = await feed_response.json()
                                feed_indicators = feed_data.get("indicators", [])
                                
                                for indicator in feed_indicators:
                                    indicator_type = self._map_indicator_type(indicator.get("type"))
                                    if indicator_type:
                                        indicators.append(ThreatIndicatorCreate(
                                            value=indicator.get("value"),
                                            indicator_type=indicator_type,
                                            threat_level=ThreatLevel.MEDIUM,
                                            description=f"Nordstellar: {feed.get('name', 'Unknown')}",
                                            source_id=self.source.id,
                                            first_seen=datetime.fromisoformat(indicator.get("first_seen", datetime.now().isoformat())),
                                            last_seen=datetime.now(),
                                            tags=indicator.get("tags", []),
                                            metadata={
                                                "nordstellar_feed_id": feed_id,
                                                "confidence": indicator.get("confidence"),
                                                "threat_level": indicator.get("threat_level")
                                            }
                                        ))
                        
                        self._rate_limit(60 / settings.NORDSTELLAR_FREE_LIMIT)  # Rate limiting
                
            return indicators
            
        except Exception as e:
            logger.error(f"Error fetching Nordstellar indicators: {e}")
            return []
    
    def _map_indicator_type(self, nordstellar_type: str) -> Optional[IndicatorType]:
        """Map Nordstellar indicator types to our types"""
        mapping = {
            "domain": IndicatorType.DOMAIN,
            "ip": IndicatorType.IP_ADDRESS,
            "url": IndicatorType.URL,
            "hash": IndicatorType.HASH,
            "email": IndicatorType.EMAIL
        }
        return mapping.get(nordstellar_type.lower())


class AnomaliFeedFetcher(BaseFeedFetcher):
    """Anomali ThreatStream feed fetcher"""
    
    async def fetch_indicators(self) -> List[ThreatIndicatorCreate]:
        """Fetch indicators from Anomali ThreatStream"""
        try:
            headers = {
                "Authorization": f"Bearer {settings.ANOMALI_API_KEY}",
                "Content-Type": "application/json"
            }
            
            # Fetch threat intelligence
            intel_url = f"{settings.ANOMALI_BASE_URL}/intelligence"
            params = {
                "limit": 100,
                "sort": "created_ts desc"
            }
            
            indicators = []
            async with self.session.get(intel_url, headers=headers, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    results = data.get("results", [])
                    
                    for result in results:
                        indicator_type = self._map_indicator_type(result.get("itype"))
                        if indicator_type:
                            indicators.append(ThreatIndicatorCreate(
                                value=result.get("value"),
                                indicator_type=indicator_type,
                                threat_level=ThreatLevel.HIGH,
                                description=f"Anomali Intel: {result.get('title', 'Unknown')}",
                                source_id=self.source.id,
                                first_seen=datetime.fromtimestamp(result.get("created_ts", time.time())),
                                last_seen=datetime.now(),
                                tags=result.get("tags", []),
                                metadata={
                                    "anomali_id": result.get("id"),
                                    "confidence": result.get("confidence"),
                                    "threat_score": result.get("threat_score")
                                }
                            ))
                
                self._rate_limit(60 / settings.ANOMALI_FREE_LIMIT)  # Rate limiting
                
            return indicators
            
        except Exception as e:
            logger.error(f"Error fetching Anomali indicators: {e}")
            return []
    
    def _map_indicator_type(self, anomali_type: str) -> Optional[IndicatorType]:
        """Map Anomali indicator types to our types"""
        mapping = {
            "domain": IndicatorType.DOMAIN,
            "ip": IndicatorType.IP_ADDRESS,
            "url": IndicatorType.URL,
            "md5": IndicatorType.HASH,
            "sha256": IndicatorType.HASH,
            "email": IndicatorType.EMAIL
        }
        return mapping.get(anomali_type.lower())


class FBIInfraGuardFeedFetcher(BaseFeedFetcher):
    """FBI InfraGuard feed fetcher"""
    
    async def fetch_indicators(self) -> List[ThreatIndicatorCreate]:
        """Fetch indicators from FBI InfraGuard"""
        try:
            headers = {
                "Authorization": f"Bearer {settings.FBI_INFRAGUARD_API_KEY}",
                "Content-Type": "application/json"
            }
            
            # Fetch threat intelligence reports
            reports_url = f"{settings.FBI_INFRAGUARD_BASE_URL}/reports"
            params = {
                "limit": 50,
                "sort": "published_date desc"
            }
            
            indicators = []
            async with self.session.get(reports_url, headers=headers, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    reports = data.get("reports", [])
                    
                    for report in reports:
                        # Extract indicators from report content
                        content = report.get("content", {})
                        for indicator in content.get("indicators", []):
                            indicator_type = self._map_indicator_type(indicator.get("type"))
                            if indicator_type:
                                indicators.append(ThreatIndicatorCreate(
                                    value=indicator.get("value"),
                                    indicator_type=indicator_type,
                                    threat_level=ThreatLevel.HIGH,
                                    description=f"FBI InfraGuard: {report.get('title', 'Unknown')}",
                                    source_id=self.source.id,
                                    first_seen=datetime.fromisoformat(report.get("published_date", datetime.now().isoformat())),
                                    last_seen=datetime.now(),
                                    tags=report.get("tags", []),
                                    metadata={
                                        "fbi_report_id": report.get("id"),
                                        "classification": report.get("classification"),
                                        "threat_actors": report.get("threat_actors", [])
                                    }
                                ))
                
                self._rate_limit(60 / 5)  # Conservative rate limiting for government API
                
            return indicators
            
        except Exception as e:
            logger.error(f"Error fetching FBI InfraGuard indicators: {e}")
            return []
    
    def _map_indicator_type(self, fbi_type: str) -> Optional[IndicatorType]:
        """Map FBI InfraGuard indicator types to our types"""
        mapping = {
            "domain": IndicatorType.DOMAIN,
            "ip": IndicatorType.IP_ADDRESS,
            "url": IndicatorType.URL,
            "hash": IndicatorType.HASH,
            "email": IndicatorType.EMAIL
        }
        return mapping.get(fbi_type.lower())
