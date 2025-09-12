import aiohttp
import asyncio
import requests
import json
import time
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from loguru import logger
import feedparser
from bs4 import BeautifulSoup
import re

from app.core.config import settings
from app.models.threat_intelligence import ThreatIndicator, ThreatSource
from app.schemas.threat_intelligence import (
from .premium_feed_fetchers import (
    CrowdStrikeFeedFetcher,
    MandiantFeedFetcher,
    RecordedFutureFeedFetcher,
    NordstellarFeedFetcher,
    AnomaliFeedFetcher,
    FBIInfraGuardFeedFetcher
)
from .opensource_feed_fetchers import (
from .custom_feed_parsers import CustomFeedFetcher
from .ml_threat_scoring import MLThreatScoring
    AbuseIPDBFeedFetcher,
    BinaryDefenseFeedFetcher,
    BotvrijFeedFetcher,
    BruteForceBlockerFeedFetcher,
    EmergingThreatsFeedFetcher,
    OpenPhishFeedFetcher,
    URLhausFeedFetcher,
    MalwareBazaarFeedFetcher,
    FeodoTrackerFeedFetcher
)    ThreatIndicatorCreate, IndicatorType, ThreatLevel, SourceType
)


class BaseFeedFetcher:
    """Base class for feed fetchers"""
    
    def __init__(self, source: ThreatSource):
        self.source = source
        self.session = None
    
    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def fetch_indicators(self) -> List[ThreatIndicatorCreate]:
        """Fetch indicators from the source"""
        raise NotImplementedError
    
    def _rate_limit(self, delay_seconds: float = 1.0):
        """Rate limiting"""
        time.sleep(delay_seconds)


class CISAFeedFetcher(BaseFeedFetcher):
    """CISA Known Exploited Vulnerabilities feed fetcher"""
    
    async def fetch_indicators(self) -> List[ThreatIndicatorCreate]:
        """Fetch CISA known exploited vulnerabilities"""
        try:
            async with self.session.get(settings.CISA_BASE_URL) as response:
                if response.status == 200:
                    data = await response.json()
                    indicators = []
                    
                    for vuln in data.get('vulnerabilities', []):
                        cve_id = vuln.get('cveID')
                        if cve_id:
                            indicator = ThreatIndicatorCreate(
                                indicator_type=IndicatorType.CVE,
                                value=cve_id,
                                confidence_score=0.9,
                                threat_level=ThreatLevel.HIGH,
                                tags=['cisa', 'known-exploited', 'vulnerability'],
                                description=vuln.get('shortDescription', ''),
                                source_id=self.source.id,
                                external_id=cve_id,
                                metadata={
                                    'vendor': vuln.get('vendor'),
                                    'product': vuln.get('product'),
                                    'dateAdded': vuln.get('dateAdded'),
                                    'dueDate': vuln.get('dueDate'),
                                    'requiredAction': vuln.get('requiredAction')
                                }
                            )
                            indicators.append(indicator)
                    
                    logger.info(f"CISA: Fetched {len(indicators)} indicators")
                    return indicators
                else:
                    logger.error(f"CISA: HTTP {response.status}")
                    return []
                    
        except Exception as e:
            logger.error(f"CISA fetch error: {e}")
            return []


class AlienVaultOTXFeedFetcher(BaseFeedFetcher):
    """AlienVault OTX feed fetcher"""
    
    async def fetch_indicators(self) -> List[ThreatIndicatorCreate]:
        """Fetch indicators from AlienVault OTX"""
        if not settings.OTX_API_KEY:
            logger.warning("OTX API key not configured")
            return []
        
        headers = {'X-OTX-API-KEY': settings.OTX_API_KEY}
        indicators = []
        
        # Fetch recent pulses
        try:
            url = f"{settings.OTX_BASE_URL}/pulses/subscribed"
            async with self.session.get(url, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    for pulse in data.get('results', []):
                        # Process indicators from pulse
                        for indicator_data in pulse.get('indicators', []):
                            indicator_type = self._map_otx_type(indicator_data.get('type'))
                            if indicator_type:
                                indicator = ThreatIndicatorCreate(
                                    indicator_type=indicator_type,
                                    value=indicator_data.get('indicator', ''),
                                    confidence_score=0.7,
                                    threat_level=self._map_otx_threat_level(pulse.get('tlp', 'white')),
                                    tags=pulse.get('tags', []) + ['otx'],
                                    description=pulse.get('description', ''),
                                    source_id=self.source.id,
                                    external_id=indicator_data.get('id'),
                                    metadata={
                                        'pulse_id': pulse.get('id'),
                                        'author': pulse.get('author_name'),
                                        'created': pulse.get('created'),
                                        'modified': pulse.get('modified')
                                    }
                                )
                                indicators.append(indicator)
                        
                        # Rate limiting
                        self._rate_limit(0.1)  # 10 requests per second limit
                    
                    logger.info(f"OTX: Fetched {len(indicators)} indicators")
                    return indicators
                else:
                    logger.error(f"OTX: HTTP {response.status}")
                    return []
                    
        except Exception as e:
            logger.error(f"OTX fetch error: {e}")
            return []
    
    def _map_otx_type(self, otx_type: str) -> Optional[IndicatorType]:
        """Map OTX indicator type to our enum"""
        mapping = {
            'IPv4': IndicatorType.IP,
            'domain': IndicatorType.DOMAIN,
            'URL': IndicatorType.URL,
            'FileHash-MD5': IndicatorType.HASH,
            'FileHash-SHA1': IndicatorType.HASH,
            'FileHash-SHA256': IndicatorType.HASH,
            'email': IndicatorType.EMAIL
        }
        return mapping.get(otx_type)
    
    def _map_otx_threat_level(self, tlp: str) -> ThreatLevel:
        """Map OTX TLP to threat level"""
        mapping = {
            'white': ThreatLevel.LOW,
            'green': ThreatLevel.LOW,
            'amber': ThreatLevel.MEDIUM,
            'red': ThreatLevel.HIGH
        }
        return mapping.get(tlp, ThreatLevel.LOW)


class VirusTotalFeedFetcher(BaseFeedFetcher):
    """VirusTotal feed fetcher"""
    
    async def fetch_indicators(self) -> List[ThreatIndicatorCreate]:
        """Fetch indicators from VirusTotal"""
        if not settings.VIRUSTOTAL_API_KEY:
            logger.warning("VirusTotal API key not configured")
            return []
        
        indicators = []
        
        # Fetch recent malicious URLs
        try:
            url = f"{settings.VIRUSTOTAL_BASE_URL}/url/report"
            params = {
                'apikey': settings.VIRUSTOTAL_API_KEY,
                'resource': 'example.com'  # This would need to be dynamic
            }
            
            async with self.session.get(url, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    if data.get('positives', 0) > 0:
                        indicator = ThreatIndicatorCreate(
                            indicator_type=IndicatorType.URL,
                            value=data.get('url', ''),
                            confidence_score=data.get('positives', 0) / data.get('total', 1),
                            threat_level=ThreatLevel.HIGH if data.get('positives', 0) > 5 else ThreatLevel.MEDIUM,
                            tags=['virustotal', 'malicious'],
                            description=f"Detected by {data.get('positives')} out of {data.get('total')} scanners",
                            source_id=self.source.id,
                            external_id=data.get('scan_id'),
                            metadata={
                                'positives': data.get('positives'),
                                'total': data.get('total'),
                                'scan_date': data.get('scan_date')
                            }
                        )
                        indicators.append(indicator)
                
                # Rate limiting for free tier
                self._rate_limit(15)  # 4 requests per minute limit
                
                logger.info(f"VirusTotal: Fetched {len(indicators)} indicators")
                return indicators
                
        except Exception as e:
            logger.error(f"VirusTotal fetch error: {e}")
            return []


class ThreatFoxFeedFetcher(BaseFeedFetcher):
    """ThreatFox feed fetcher"""
    
    async def fetch_indicators(self) -> List[ThreatIndicatorCreate]:
        """Fetch indicators from ThreatFox"""
        indicators = []
        
        try:
            # Fetch recent malware samples
            url = f"{settings.THREATFOX_BASE_URL}/query/"
            payload = {
                'query': 'get_recent',
                'days': 1
            }
            
            async with self.session.post(url, json=payload) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    if data.get('query_status') == 'ok':
                        for sample in data.get('data', []):
                            if sample.get('md5_hash'):
                                indicator = ThreatIndicatorCreate(
                                    indicator_type=IndicatorType.HASH,
                                    value=sample.get('md5_hash'),
                                    confidence_score=0.8,
                                    threat_level=ThreatLevel.HIGH,
                                    tags=['threatfox', 'malware', sample.get('malware_type', 'unknown')],
                                    description=f"Malware: {sample.get('malware_type')}",
                                    source_id=self.source.id,
                                    external_id=sample.get('id'),
                                    metadata={
                                        'malware_type': sample.get('malware_type'),
                                        'platform': sample.get('platform'),
                                        'first_seen': sample.get('first_seen'),
                                        'last_seen': sample.get('last_seen')
                                    }
                                )
                                indicators.append(indicator)
                    
                    logger.info(f"ThreatFox: Fetched {len(indicators)} indicators")
                    return indicators
                else:
                    logger.error(f"ThreatFox: {data.get('query_status')}")
                    return []
                    
        except Exception as e:
            logger.error(f"ThreatFox fetch error: {e}")
            return []


class PhishTankFeedFetcher(BaseFeedFetcher):
    """PhishTank feed fetcher"""
    
    async def fetch_indicators(self) -> List[ThreatIndicatorCreate]:
        """Fetch indicators from PhishTank"""
        indicators = []
        
        try:
            # Fetch recent phishing URLs
            url = f"{settings.PHISHTANK_BASE_URL}/online-valid.json"
            
            async with self.session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    for phish in data:
                        if phish.get('url'):
                            indicator = ThreatIndicatorCreate(
                                indicator_type=IndicatorType.URL,
                                value=phish.get('url'),
                                confidence_score=0.9,
                                threat_level=ThreatLevel.HIGH,
                                tags=['phishtank', 'phishing'],
                                description=f"Phishing site targeting {phish.get('target', 'unknown')}",
                                source_id=self.source.id,
                                external_id=str(phish.get('phish_id')),
                                metadata={
                                    'target': phish.get('target'),
                                    'verification_time': phish.get('verification_time'),
                                    'online': phish.get('online')
                                }
                            )
                            indicators.append(indicator)
                    
                    logger.info(f"PhishTank: Fetched {len(indicators)} indicators")
                    return indicators
                else:
                    logger.error(f"PhishTank: HTTP {response.status}")
                    return []
                    
        except Exception as e:
            logger.error(f"PhishTank fetch error: {e}")
            return []


class URLhausFeedFetcher(BaseFeedFetcher):
    """URLhaus feed fetcher"""
    
    async def fetch_indicators(self) -> List[ThreatIndicatorCreate]:
        """Fetch indicators from URLhaus"""
        indicators = []
        
        try:
            # Fetch recent malicious URLs
            url = f"{settings.URLHAUS_BASE_URL}/payloads/recent/"
            
            async with self.session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    if data.get('query_status') == 'ok':
                        for payload in data.get('data', []):
                            if payload.get('url'):
                                indicator = ThreatIndicatorCreate(
                                    indicator_type=IndicatorType.URL,
                                    value=payload.get('url'),
                                    confidence_score=0.8,
                                    threat_level=ThreatLevel.HIGH,
                                    tags=['urlhaus', 'malware', payload.get('tags', [])],
                                    description=f"Malware payload: {payload.get('tags', [])}",
                                    source_id=self.source.id,
                                    external_id=payload.get('id'),
                                    metadata={
                                        'tags': payload.get('tags'),
                                        'date_added': payload.get('date_added'),
                                        'status': payload.get('status')
                                    }
                                )
                                indicators.append(indicator)
                    
                    logger.info(f"URLhaus: Fetched {len(indicators)} indicators")
                    return indicators
                else:
                    logger.error(f"URLhaus: HTTP {response.status}")
                    return []
                    
        except Exception as e:
            logger.error(f"URLhaus fetch error: {e}")
            return []


class DarkWebFeedFetcher(BaseFeedFetcher):
    """Dark web feed fetcher using Tor"""
    
    async def fetch_indicators(self) -> List[ThreatIndicatorCreate]:
        """Fetch indicators from dark web sources"""
        if not settings.TOR_PROXY_URL:
            logger.warning("Tor proxy not configured")
            return []
        
        indicators = []
        
        # Configure Tor proxy
        proxy = f"socks5://{settings.TOR_PROXY_URL}:{settings.TOR_PROXY_PORT}"
        
        try:
            connector = aiohttp.TCPConnector()
            timeout = aiohttp.ClientTimeout(total=30)
            
            async with aiohttp.ClientSession(
                connector=connector,
                timeout=timeout
            ) as session:
                # Example dark web sources (these would need to be configured)
                dark_sources = [
                    "http://example.onion",  # Replace with actual .onion sites
                ]
                
                for source_url in dark_sources:
                    try:
                        async with session.get(source_url) as response:
                            if response.status == 200:
                                content = await response.text()
                                
                                # Extract indicators from content
                                extracted = self._extract_indicators(content)
                                for indicator_data in extracted:
                                    indicator = ThreatIndicatorCreate(
                                        indicator_type=indicator_data['type'],
                                        value=indicator_data['value'],
                                        confidence_score=0.6,  # Lower confidence for dark web
                                        threat_level=ThreatLevel.MEDIUM,
                                        tags=['darkweb', 'scraped'],
                                        description=f"Scraped from dark web source",
                                        source_id=self.source.id,
                                        metadata={
                                            'source_url': source_url,
                                            'scraped_at': datetime.utcnow().isoformat()
                                        }
                                    )
                                    indicators.append(indicator)
                    
                    except Exception as e:
                        logger.error(f"Dark web source {source_url} error: {e}")
                        continue
                
                logger.info(f"Dark Web: Fetched {len(indicators)} indicators")
                return indicators
                
        except Exception as e:
            logger.error(f"Dark web fetch error: {e}")
            return []
    
    def _extract_indicators(self, content: str) -> List[Dict[str, Any]]:
        """Extract indicators from dark web content"""
        indicators = []
        
        # Extract IP addresses
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        for ip in re.findall(ip_pattern, content):
            indicators.append({
                'type': IndicatorType.IP,
                'value': ip
            })
        
        # Extract domains
        domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
        for domain in re.findall(domain_pattern, content):
            if not domain.startswith('http'):
                indicators.append({
                    'type': IndicatorType.DOMAIN,
                    'value': domain
                })
        
        # Extract URLs
        url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
        for url in re.findall(url_pattern, content):
            indicators.append({
                'type': IndicatorType.URL,
                'value': url
            })
        
        return indicators


# Factory function to create appropriate fetcher
def create_feed_fetcher(source: ThreatSource) -> BaseFeedFetcher:
    """Create appropriate feed fetcher based on source type"""
    fetchers = {
        # Premium Threat Intelligence
        "crowdstrike": CrowdStrikeFeedFetcher,
        "mandiant": MandiantFeedFetcher,
        "recordedfuture": RecordedFutureFeedFetcher,
        "nordstellar": NordstellarFeedFetcher,
        "anomali": AnomaliFeedFetcher,
        "fbi_infraguard": FBIInfraGuardFeedFetcher,
        
        # Open Source Threat Intelligence
        "abuseipdb": AbuseIPDBFeedFetcher,
        "binarydefense": BinaryDefenseFeedFetcher,
        "botvrij": BotvrijFeedFetcher,
        "bruteforceblocker": BruteForceBlockerFeedFetcher,
        "emergingthreats": EmergingThreatsFeedFetcher,
        "openphish": OpenPhishFeedFetcher,
        "malwarebazaar": MalwareBazaarFeedFetcher,
        "feodotracker": FeodoTrackerFeedFetcher,
        
        # Custom Feed Parsers
        "custom": CustomFeedFetcher,
        
        # Original Sources
        "cisa": CISAFeedFetcher,
        "otx": AlienVaultOTXFeedFetcher,
        "virustotal": VirusTotalFeedFetcher,
        "threatfox": ThreatFoxFeedFetcher,
        "phishtank": PhishTankFeedFetcher,
        "urlhaus": URLhausFeedFetcher,
        "darkweb": DarkWebFeedFetcher
        'cisa': CISAFeedFetcher,
        'otx': AlienVaultOTXFeedFetcher,
        'virustotal': VirusTotalFeedFetcher,
        'threatfox': ThreatFoxFeedFetcher,
        'phishtank': PhishTankFeedFetcher,
        'urlhaus': URLhausFeedFetcher,
        'darkweb': DarkWebFeedFetcher
    }
    
    fetcher_class = fetchers.get(source.name.lower())
    if fetcher_class:
        return fetcher_class(source)
    else:
        logger.warning(f"No fetcher found for source: {source.name}")
        return BaseFeedFetcher(source)
