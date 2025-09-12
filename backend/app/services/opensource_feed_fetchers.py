import aiohttp
import asyncio
import requests
import json
import time
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from loguru import logger
import csv
import io

from app.core.config import settings
from app.models.threat_intelligence import ThreatIndicator, ThreatSource
from app.schemas.threat_intelligence import (
    ThreatIndicatorCreate, IndicatorType, ThreatLevel, SourceType
)
from .feed_fetchers import BaseFeedFetcher


class AbuseIPDBFeedFetcher(BaseFeedFetcher):
    """AbuseIPDB feed fetcher"""
    
    async def fetch_indicators(self) -> List[ThreatIndicatorCreate]:
        """Fetch indicators from AbuseIPDB"""
        try:
            headers = {
                "Key": settings.ABUSEIPDB_API_KEY,
                "Accept": "application/json"
            }
            
            # Fetch recent abuse reports
            reports_url = f"{settings.ABUSEIPDB_BASE_URL}/blacklist"
            params = {
                "confidenceMinimum": 90,
                "limit": 100
            }
            
            indicators = []
            async with self.session.get(reports_url, headers=headers, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    blacklist = data.get("data", [])
                    
                    for entry in blacklist:
                        indicators.append(ThreatIndicatorCreate(
                            value=entry.get("ipAddress"),
                            indicator_type=IndicatorType.IP_ADDRESS,
                            threat_level=ThreatLevel.MEDIUM,
                            description=f"AbuseIPDB: {entry.get('abuseConfidenceScore', 0)}% confidence",
                            source_id=self.source.id,
                            first_seen=datetime.now(),
                            last_seen=datetime.now(),
                            tags=["abuseipdb", "blacklist"],
                            metadata={
                                "abuse_confidence_score": entry.get("abuseConfidenceScore"),
                                "country_code": entry.get("countryCode"),
                                "usage_type": entry.get("usageType"),
                                "isp": entry.get("isp")
                            }
                        ))
                
                self._rate_limit(60 / settings.ABUSEIPDB_FREE_LIMIT)  # Rate limiting
                
            return indicators
            
        except Exception as e:
            logger.error(f"Error fetching AbuseIPDB indicators: {e}")
            return []


class BinaryDefenseFeedFetcher(BaseFeedFetcher):
    """Binary Defense Artillery Threat Intelligence Feed fetcher"""
    
    async def fetch_indicators(self) -> List[ThreatIndicatorCreate]:
        """Fetch indicators from Binary Defense banlist"""
        try:
            indicators = []
            async with self.session.get(settings.BINARYDEFENSE_BANLIST_URL) as response:
                if response.status == 200:
                    content = await response.text()
                    lines = content.strip().split('\n')
                    
                    for line in lines:
                        if line and not line.startswith('#'):
                            # Parse IP address from line
                            parts = line.split()
                            if parts:
                                ip_address = parts[0]
                                indicators.append(ThreatIndicatorCreate(
                                    value=ip_address,
                                    indicator_type=IndicatorType.IP_ADDRESS,
                                    threat_level=ThreatLevel.MEDIUM,
                                    description="Binary Defense Artillery Threat Intelligence",
                                    source_id=self.source.id,
                                    first_seen=datetime.now(),
                                    last_seen=datetime.now(),
                                    tags=["binarydefense", "artillery", "banlist"],
                                    metadata={
                                        "source": "binarydefense_banlist",
                                        "raw_line": line
                                    }
                                ))
                
            return indicators
            
        except Exception as e:
            logger.error(f"Error fetching Binary Defense indicators: {e}")
            return []


class BotvrijFeedFetcher(BaseFeedFetcher):
    """Botvrij.eu feed fetcher"""
    
    async def fetch_indicators(self) -> List[ThreatIndicatorCreate]:
        """Fetch indicators from Botvrij.eu"""
        try:
            indicators = []
            
            # Botvrij provides multiple feed types
            feed_types = [
                "ip-list.txt",
                "domain-list.txt",
                "url-list.txt"
            ]
            
            for feed_type in feed_types:
                feed_url = f"{settings.BOTVRIJ_BASE_URL}/{feed_type}"
                
                async with self.session.get(feed_url) as response:
                    if response.status == 200:
                        content = await response.text()
                        lines = content.strip().split('\n')
                        
                        for line in lines:
                            if line and not line.startswith('#'):
                                # Determine indicator type based on feed
                                if feed_type == "ip-list.txt":
                                    indicator_type = IndicatorType.IP_ADDRESS
                                elif feed_type == "domain-list.txt":
                                    indicator_type = IndicatorType.DOMAIN
                                elif feed_type == "url-list.txt":
                                    indicator_type = IndicatorType.URL
                                else:
                                    continue
                                
                                indicators.append(ThreatIndicatorCreate(
                                    value=line.strip(),
                                    indicator_type=indicator_type,
                                    threat_level=ThreatLevel.LOW,
                                    description=f"Botvrij.eu: {feed_type}",
                                    source_id=self.source.id,
                                    first_seen=datetime.now(),
                                    last_seen=datetime.now(),
                                    tags=["botvrij", "opensource"],
                                    metadata={
                                        "feed_type": feed_type,
                                        "source": "botvrij"
                                    }
                                ))
                
            return indicators
            
        except Exception as e:
            logger.error(f"Error fetching Botvrij indicators: {e}")
            return []


class BruteForceBlockerFeedFetcher(BaseFeedFetcher):
    """BruteForceBlocker feed fetcher"""
    
    async def fetch_indicators(self) -> List[ThreatIndicatorCreate]:
        """Fetch indicators from BruteForceBlocker"""
        try:
            indicators = []
            async with self.session.get(settings.BRUTEFORCEBLOCKER_URL) as response:
                if response.status == 200:
                    content = await response.text()
                    lines = content.strip().split('\n')
                    
                    for line in lines:
                        if line and not line.startswith('#'):
                            # Parse IP address from line
                            parts = line.split()
                            if parts:
                                ip_address = parts[0]
                                indicators.append(ThreatIndicatorCreate(
                                    value=ip_address,
                                    indicator_type=IndicatorType.IP_ADDRESS,
                                    threat_level=ThreatLevel.MEDIUM,
                                    description="BruteForceBlocker: SSH brute force attempts",
                                    source_id=self.source.id,
                                    first_seen=datetime.now(),
                                    last_seen=datetime.now(),
                                    tags=["bruteforceblocker", "ssh", "bruteforce"],
                                    metadata={
                                        "source": "bruteforceblocker",
                                        "attack_type": "ssh_bruteforce"
                                    }
                                ))
                
            return indicators
            
        except Exception as e:
            logger.error(f"Error fetching BruteForceBlocker indicators: {e}")
            return []


class EmergingThreatsFeedFetcher(BaseFeedFetcher):
    """Emerging Threats feed fetcher"""
    
    async def fetch_indicators(self) -> List[ThreatIndicatorCreate]:
        """Fetch indicators from Emerging Threats"""
        try:
            indicators = []
            
            # Emerging Threats provides multiple feeds
            feeds = [
                "https://rules.emergingthreats.net/open/suricata/rules/compromised-ips.txt",
                "https://rules.emergingthreats.net/open/suricata/rules/compromised-domains.txt"
            ]
            
            for feed_url in feeds:
                async with self.session.get(feed_url) as response:
                    if response.status == 200:
                        content = await response.text()
                        lines = content.strip().split('\n')
                        
                        for line in lines:
                            if line and not line.startswith('#'):
                                # Determine indicator type based on feed URL
                                if "compromised-ips" in feed_url:
                                    indicator_type = IndicatorType.IP_ADDRESS
                                elif "compromised-domains" in feed_url:
                                    indicator_type = IndicatorType.DOMAIN
                                else:
                                    continue
                                
                                indicators.append(ThreatIndicatorCreate(
                                    value=line.strip(),
                                    indicator_type=indicator_type,
                                    threat_level=ThreatLevel.HIGH,
                                    description="Emerging Threats: Compromised indicators",
                                    source_id=self.source.id,
                                    first_seen=datetime.now(),
                                    last_seen=datetime.now(),
                                    tags=["emergingthreats", "compromised"],
                                    metadata={
                                        "feed_url": feed_url,
                                        "source": "emergingthreats"
                                    }
                                ))
                
            return indicators
            
        except Exception as e:
            logger.error(f"Error fetching Emerging Threats indicators: {e}")
            return []


class OpenPhishFeedFetcher(BaseFeedFetcher):
    """OpenPhish feed fetcher"""
    
    async def fetch_indicators(self) -> List[ThreatIndicatorCreate]:
        """Fetch indicators from OpenPhish"""
        try:
            indicators = []
            
            # OpenPhish provides a CSV feed
            feed_url = "https://openphish.com/feed.txt"
            
            async with self.session.get(feed_url) as response:
                if response.status == 200:
                    content = await response.text()
                    lines = content.strip().split('\n')
                    
                    for line in lines:
                        if line and not line.startswith('#'):
                            # Parse CSV format: URL,Timestamp
                            parts = line.split(',')
                            if len(parts) >= 1:
                                url = parts[0].strip()
                                timestamp = parts[1].strip() if len(parts) > 1 else None
                                
                                indicators.append(ThreatIndicatorCreate(
                                    value=url,
                                    indicator_type=IndicatorType.URL,
                                    threat_level=ThreatLevel.HIGH,
                                    description="OpenPhish: Phishing URL",
                                    source_id=self.source.id,
                                    first_seen=datetime.fromisoformat(timestamp) if timestamp else datetime.now(),
                                    last_seen=datetime.now(),
                                    tags=["openphish", "phishing", "url"],
                                    metadata={
                                        "source": "openphish",
                                        "timestamp": timestamp
                                    }
                                ))
                
            return indicators
            
        except Exception as e:
            logger.error(f"Error fetching OpenPhish indicators: {e}")
            return []


class URLhausFeedFetcher(BaseFeedFetcher):
    """URLhaus feed fetcher (enhanced version)"""
    
    async def fetch_indicators(self) -> List[ThreatIndicatorCreate]:
        """Fetch indicators from URLhaus"""
        try:
            indicators = []
            
            # URLhaus provides multiple endpoints
            endpoints = [
                "/payloads/recent/",
                "/payloads/recent/online/",
                "/payloads/recent/offline/"
            ]
            
            for endpoint in endpoints:
                url = f"{settings.URLHAUS_BASE_URL}{endpoint}"
                
                async with self.session.get(url) as response:
                    if response.status == 200:
                        data = await response.json()
                        entries = data.get("query_status") == "ok" and data.get("data", [])
                        
                        for entry in entries:
                            # Extract URL
                            url_value = entry.get("url")
                            if url_value:
                                indicators.append(ThreatIndicatorCreate(
                                    value=url_value,
                                    indicator_type=IndicatorType.URL,
                                    threat_level=ThreatLevel.HIGH,
                                    description=f"URLhaus: {entry.get('tags', ['malware'])[0]}",
                                    source_id=self.source.id,
                                    first_seen=datetime.fromtimestamp(entry.get("date_added", time.time())),
                                    last_seen=datetime.now(),
                                    tags=["urlhaus", "malware"] + entry.get("tags", []),
                                    metadata={
                                        "urlhaus_id": entry.get("id"),
                                        "status": entry.get("url_status"),
                                        "tags": entry.get("tags", []),
                                        "threat": entry.get("threat"),
                                        "tags": entry.get("tags", [])
                                    }
                                ))
                
                self._rate_limit(1)  # Rate limiting between requests
                
            return indicators
            
        except Exception as e:
            logger.error(f"Error fetching URLhaus indicators: {e}")
            return []


class MalwareBazaarFeedFetcher(BaseFeedFetcher):
    """MalwareBazaar feed fetcher"""
    
    async def fetch_indicators(self) -> List[ThreatIndicatorCreate]:
        """Fetch indicators from MalwareBazaar"""
        try:
            indicators = []
            
            # MalwareBazaar API endpoint
            api_url = "https://bazaar.abuse.ch/api/v1"
            
            # Fetch recent samples
            data = {
                "query": "get_recent",
                "selector": "100"  # Get last 100 samples
            }
            
            async with self.session.post(api_url, data=data) as response:
                if response.status == 200:
                    result = await response.json()
                    
                    if result.get("query_status") == "ok":
                        samples = result.get("data", [])
                        
                        for sample in samples:
                            # Extract hashes
                            hashes = []
                            if sample.get("md5_hash"):
                                hashes.append(("md5", sample["md5_hash"]))
                            if sample.get("sha256_hash"):
                                hashes.append(("sha256", sample["sha256_hash"]))
                            if sample.get("sha1_hash"):
                                hashes.append(("sha1", sample["sha1_hash"]))
                            
                            for hash_type, hash_value in hashes:
                                indicators.append(ThreatIndicatorCreate(
                                    value=hash_value,
                                    indicator_type=IndicatorType.HASH,
                                    threat_level=ThreatLevel.HIGH,
                                    description=f"MalwareBazaar: {sample.get('signature', 'Unknown malware')}",
                                    source_id=self.source.id,
                                    first_seen=datetime.fromtimestamp(sample.get("first_seen", time.time())),
                                    last_seen=datetime.now(),
                                    tags=["malwarebazaar", "malware", hash_type],
                                    metadata={
                                        "malwarebazaar_id": sample.get("id"),
                                        "file_type": sample.get("file_type"),
                                        "file_type_mime": sample.get("file_type_mime"),
                                        "signature": sample.get("signature"),
                                        "tags": sample.get("tags", []),
                                        "hash_type": hash_type
                                    }
                                ))
                
            return indicators
            
        except Exception as e:
            logger.error(f"Error fetching MalwareBazaar indicators: {e}")
            return []


class FeodoTrackerFeedFetcher(BaseFeedFetcher):
    """Feodo Tracker feed fetcher"""
    
    async def fetch_indicators(self) -> List[ThreatIndicatorCreate]:
        """Fetch indicators from Feodo Tracker"""
        try:
            indicators = []
            
            # Feodo Tracker provides multiple feeds
            feeds = [
                "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
                "https://feodotracker.abuse.ch/downloads/ipblocklist_aggressive.json"
            ]
            
            for feed_url in feeds:
                async with self.session.get(feed_url) as response:
                    if response.status == 200:
                        data = await response.json()
                        entries = data.get("data", [])
                        
                        for entry in entries:
                            ip_address = entry.get("ip_address")
                            if ip_address:
                                indicators.append(ThreatIndicatorCreate(
                                    value=ip_address,
                                    indicator_type=IndicatorType.IP_ADDRESS,
                                    threat_level=ThreatLevel.HIGH,
                                    description=f"Feodo Tracker: {entry.get('malware', 'Unknown')}",
                                    source_id=self.source.id,
                                    first_seen=datetime.fromisoformat(entry.get("first_seen", datetime.now().isoformat())),
                                    last_seen=datetime.now(),
                                    tags=["feodotracker", "botnet", "malware"],
                                    metadata={
                                        "malware": entry.get("malware"),
                                        "port": entry.get("port"),
                                        "status": entry.get("status"),
                                        "hostname": entry.get("hostname")
                                    }
                                ))
                
            return indicators
            
        except Exception as e:
            logger.error(f"Error fetching Feodo Tracker indicators: {e}")
            return []
