"""
Example Custom Feed Parser Template

This is an example of how to create a custom feed parser for organization-specific
threat intelligence sources. Copy this file and modify it for your specific needs.

Usage:
1. Copy this file to custom_parsers/your_parser_name.py
2. Modify the class name and implementation
3. Update the configuration in the web interface
4. Set parser_type to 'custom' and parser_class to your class name
"""

from typing import List, Dict, Any
from datetime import datetime
import re
import json

from app.services.custom_feed_parsers import CustomFeedParser
from app.schemas.threat_intelligence import (
    ThreatIndicatorCreate, IndicatorType, ThreatLevel
)


class ExampleCustomParser(CustomFeedParser):
    """
    Example custom parser for demonstration purposes.
    
    This parser shows how to:
    - Handle custom authentication
    - Parse complex data structures
    - Apply custom business logic
    - Handle different data formats
    """
    
    async def fetch_data(self) -> Dict[str, Any]:
        """Fetch data from your custom source"""
        
        # Example: Custom authentication
        api_key = self.config.get('api_key')
        if not api_key:
            raise ValueError("API key required for this parser")
        
        # Example: Custom headers
        headers = {
            'Authorization': f'Bearer {api_key}',
            'User-Agent': 'Malsift-Custom-Parser/1.0',
            'Accept': 'application/json'
        }
        
        # Fetch data from your source
        url = self.config.get('url')
        async with self.session.get(url, headers=headers) as response:
            if response.status == 200:
                return await response.json()
            else:
                raise Exception(f"HTTP {response.status}: {response.reason}")
    
    def parse_indicators(self, data: Dict[str, Any]) -> List[ThreatIndicatorCreate]:
        """Parse your custom data format into indicators"""
        
        indicators = []
        
        # Example: Navigate to your data structure
        # Modify this based on your actual data format
        threat_data = data.get('threats', [])
        
        for threat in threat_data:
            try:
                # Extract basic information
                value = threat.get('indicator')
                if not value:
                    continue
                
                # Apply custom business logic
                threat_level = self._calculate_custom_threat_level(threat)
                indicator_type = self._determine_indicator_type(value)
                
                # Extract additional metadata
                description = threat.get('description', 'Custom threat indicator')
                tags = threat.get('tags', [])
                
                # Apply custom filtering
                if self._should_include_indicator(threat):
                    indicator = ThreatIndicatorCreate(
                        value=value,
                        indicator_type=indicator_type,
                        threat_level=threat_level,
                        description=description,
                        source_id=self.source.id,
                        first_seen=datetime.now(),
                        last_seen=datetime.now(),
                        tags=tags,
                        metadata={
                            'custom_feed': True,
                            'parser': 'example_custom',
                            'original_data': threat,
                            'custom_field': threat.get('custom_field'),
                            'confidence_score': threat.get('confidence', 0.5)
                        }
                    )
                    
                    indicators.append(indicator)
            
            except Exception as e:
                # Log error but continue processing other indicators
                print(f"Error parsing indicator: {e}")
                continue
        
        return indicators
    
    def _calculate_custom_threat_level(self, threat: Dict[str, Any]) -> ThreatLevel:
        """Apply your custom threat level calculation logic"""
        
        # Example: Custom scoring algorithm
        score = 0.0
        
        # Factor 1: Confidence score
        confidence = threat.get('confidence', 0.5)
        score += confidence * 0.4
        
        # Factor 2: Severity rating
        severity = threat.get('severity', 'medium')
        severity_scores = {'low': 0.2, 'medium': 0.5, 'high': 0.8, 'critical': 1.0}
        score += severity_scores.get(severity.lower(), 0.5) * 0.3
        
        # Factor 3: Age factor (newer = higher score)
        age_days = threat.get('age_days', 30)
        age_factor = max(0, 30 - age_days) / 30
        score += age_factor * 0.3
        
        # Map score to threat level
        if score >= 0.8:
            return ThreatLevel.CRITICAL
        elif score >= 0.6:
            return ThreatLevel.HIGH
        elif score >= 0.4:
            return ThreatLevel.MEDIUM
        else:
            return ThreatLevel.LOW
    
    def _determine_indicator_type(self, value: str) -> IndicatorType:
        """Determine indicator type based on value patterns"""
        
        # IP address pattern
        if re.match(r'^(?:\d{1,3}\.){3}\d{1,3}$', value):
            return IndicatorType.IP_ADDRESS
        
        # Domain pattern
        if re.match(r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$', value):
            return IndicatorType.DOMAIN
        
        # URL pattern
        if re.match(r'^https?://', value):
            return IndicatorType.URL
        
        # Hash patterns
        if re.match(r'^[a-fA-F0-9]{32}$', value):  # MD5
            return IndicatorType.HASH
        if re.match(r'^[a-fA-F0-9]{40}$', value):  # SHA1
            return IndicatorType.HASH
        if re.match(r'^[a-fA-F0-9]{64}$', value):  # SHA256
            return IndicatorType.HASH
        
        # Email pattern
        if re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', value):
            return IndicatorType.EMAIL
        
        # Default to IP address if unknown
        return IndicatorType.IP_ADDRESS
    
    def _should_include_indicator(self, threat: Dict[str, Any]) -> bool:
        """Apply custom filtering logic"""
        
        # Example: Filter out low-confidence indicators
        confidence = threat.get('confidence', 0.5)
        if confidence < 0.3:
            return False
        
        # Example: Filter out old indicators
        age_days = threat.get('age_days', 30)
        if age_days > 90:
            return False
        
        # Example: Filter by threat category
        category = threat.get('category', '')
        excluded_categories = ['false_positive', 'test', 'benign']
        if category.lower() in excluded_categories:
            return False
        
        return True


class AdvancedCustomParser(CustomFeedParser):
    """
    Advanced custom parser example with more sophisticated features.
    
    This parser demonstrates:
    - Rate limiting
    - Caching
    - Complex data transformation
    - Error handling and retries
    """
    
    def __init__(self, source, config):
        super().__init__(source, config)
        self.cache = {}
        self.last_request_time = 0
    
    async def fetch_data(self) -> Dict[str, Any]:
        """Fetch data with rate limiting and caching"""
        
        # Check cache first
        cache_key = f"{self.config.get('url')}_{datetime.now().strftime('%Y%m%d')}"
        if cache_key in self.cache:
            return self.cache[cache_key]
        
        # Rate limiting
        await self._rate_limit()
        
        # Fetch data
        data = await self._fetch_with_retry()
        
        # Cache the result
        self.cache[cache_key] = data
        
        return data
    
    async def _rate_limit(self):
        """Implement custom rate limiting"""
        import asyncio
        import time
        
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        
        # Minimum 1 second between requests
        if time_since_last < 1:
            await asyncio.sleep(1 - time_since_last)
        
        self.last_request_time = time.time()
    
    async def _fetch_with_retry(self, max_retries: int = 3) -> Dict[str, Any]:
        """Fetch data with retry logic"""
        
        for attempt in range(max_retries):
            try:
                headers = {
                    'Authorization': f'Bearer {self.config.get("api_key")}',
                    'Content-Type': 'application/json'
                }
                
                async with self.session.get(
                    self.config.get('url'), 
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as response:
                    if response.status == 200:
                        return await response.json()
                    elif response.status == 429:  # Rate limited
                        await asyncio.sleep(2 ** attempt)  # Exponential backoff
                        continue
                    else:
                        raise Exception(f"HTTP {response.status}: {response.reason}")
            
            except Exception as e:
                if attempt == max_retries - 1:
                    raise e
                await asyncio.sleep(2 ** attempt)
        
        raise Exception("Max retries exceeded")
    
    def parse_indicators(self, data: Dict[str, Any]) -> List[ThreatIndicatorCreate]:
        """Parse data with advanced processing"""
        
        indicators = []
        
        # Example: Process multiple data types
        for data_type, items in data.items():
            if data_type == 'threats':
                indicators.extend(self._parse_threats(items))
            elif data_type == 'malware':
                indicators.extend(self._parse_malware(items))
            elif data_type == 'network':
                indicators.extend(self._parse_network(items))
        
        return indicators
    
    def _parse_threats(self, threats: List[Dict[str, Any]]) -> List[ThreatIndicatorCreate]:
        """Parse threat data"""
        indicators = []
        
        for threat in threats:
            try:
                indicator = ThreatIndicatorCreate(
                    value=threat.get('indicator'),
                    indicator_type=self._map_type(threat.get('type')),
                    threat_level=self._map_level(threat.get('level')),
                    description=threat.get('description', 'Threat indicator'),
                    source_id=self.source.id,
                    first_seen=datetime.now(),
                    last_seen=datetime.now(),
                    tags=threat.get('tags', []),
                    metadata={'data_type': 'threat', 'original': threat}
                )
                indicators.append(indicator)
            except Exception as e:
                print(f"Error parsing threat: {e}")
        
        return indicators
    
    def _parse_malware(self, malware: List[Dict[str, Any]]) -> List[ThreatIndicatorCreate]:
        """Parse malware data"""
        indicators = []
        
        for item in malware:
            try:
                # Extract multiple indicators from malware data
                if 'hashes' in item:
                    for hash_type, hash_value in item['hashes'].items():
                        indicator = ThreatIndicatorCreate(
                            value=hash_value,
                            indicator_type=IndicatorType.HASH,
                            threat_level=ThreatLevel.HIGH,
                            description=f"Malware hash: {item.get('name', 'Unknown')}",
                            source_id=self.source.id,
                            first_seen=datetime.now(),
                            last_seen=datetime.now(),
                            tags=['malware', hash_type] + item.get('tags', []),
                            metadata={'data_type': 'malware', 'original': item}
                        )
                        indicators.append(indicator)
            except Exception as e:
                print(f"Error parsing malware: {e}")
        
        return indicators
    
    def _parse_network(self, network: List[Dict[str, Any]]) -> List[ThreatIndicatorCreate]:
        """Parse network data"""
        indicators = []
        
        for item in network:
            try:
                indicator = ThreatIndicatorCreate(
                    value=item.get('ip'),
                    indicator_type=IndicatorType.IP_ADDRESS,
                    threat_level=self._calculate_network_threat_level(item),
                    description=f"Network indicator: {item.get('reason', 'Suspicious activity')}",
                    source_id=self.source.id,
                    first_seen=datetime.now(),
                    last_seen=datetime.now(),
                    tags=['network'] + item.get('tags', []),
                    metadata={'data_type': 'network', 'original': item}
                )
                indicators.append(indicator)
            except Exception as e:
                print(f"Error parsing network: {e}")
        
        return indicators
    
    def _map_type(self, raw_type: str) -> IndicatorType:
        """Map raw type to IndicatorType"""
        mapping = {
            'ip': IndicatorType.IP_ADDRESS,
            'domain': IndicatorType.DOMAIN,
            'url': IndicatorType.URL,
            'hash': IndicatorType.HASH,
            'email': IndicatorType.EMAIL
        }
        return mapping.get(raw_type.lower(), IndicatorType.IP_ADDRESS)
    
    def _map_level(self, raw_level: str) -> ThreatLevel:
        """Map raw level to ThreatLevel"""
        mapping = {
            'low': ThreatLevel.LOW,
            'medium': ThreatLevel.MEDIUM,
            'high': ThreatLevel.HIGH,
            'critical': ThreatLevel.CRITICAL
        }
        return mapping.get(raw_level.lower(), ThreatLevel.MEDIUM)
    
    def _calculate_network_threat_level(self, item: Dict[str, Any]) -> ThreatLevel:
        """Calculate threat level for network indicators"""
        
        # Example: Calculate based on multiple factors
        score = 0.0
        
        # Factor 1: Connection count
        connections = item.get('connections', 0)
        score += min(connections / 100.0, 0.3)
        
        # Factor 2: Geographic risk
        country = item.get('country', 'unknown')
        high_risk_countries = ['cn', 'ru', 'kp', 'ir']
        if country.lower() in high_risk_countries:
            score += 0.4
        
        # Factor 3: Port scanning
        if item.get('port_scanning', False):
            score += 0.3
        
        # Map to threat level
        if score >= 0.7:
            return ThreatLevel.HIGH
        elif score >= 0.4:
            return ThreatLevel.MEDIUM
        else:
            return ThreatLevel.LOW
