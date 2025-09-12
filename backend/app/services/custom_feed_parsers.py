import aiohttp
import asyncio
import json
import csv
import xml.etree.ElementTree as ET
from typing import List, Dict, Any, Optional, Callable, Union
from datetime import datetime, timedelta
from loguru import logger
import yaml
import re
from pathlib import Path
import importlib.util
import inspect
from abc import ABC, abstractmethod

from app.core.config import settings
from app.models.threat_intelligence import ThreatIndicator, ThreatSource
from app.schemas.threat_intelligence import (
    ThreatIndicatorCreate, IndicatorType, ThreatLevel, SourceType
)
from .feed_fetchers import BaseFeedFetcher


class CustomFeedParser(ABC):
    """Abstract base class for custom feed parsers"""
    
    def __init__(self, source: ThreatSource, config: Dict[str, Any]):
        self.source = source
        self.config = config
        self.session = None
    
    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    @abstractmethod
    async def fetch_data(self) -> Any:
        """Fetch raw data from the source"""
        pass
    
    @abstractmethod
    def parse_indicators(self, data: Any) -> List[ThreatIndicatorCreate]:
        """Parse raw data into threat indicators"""
        pass
    
    async def fetch_indicators(self) -> List[ThreatIndicatorCreate]:
        """Main method to fetch and parse indicators"""
        try:
            data = await self.fetch_data()
            indicators = self.parse_indicators(data)
            return indicators
        except Exception as e:
            logger.error(f"Error in custom feed parser {self.__class__.__name__}: {e}")
            return []


class JSONFeedParser(CustomFeedParser):
    """Parser for JSON-based threat feeds"""
    
    async def fetch_data(self) -> Dict[str, Any]:
        """Fetch JSON data from the source"""
        url = self.config.get('url')
        headers = self.config.get('headers', {})
        
        async with self.session.get(url, headers=headers) as response:
            if response.status == 200:
                return await response.json()
            else:
                raise Exception(f"HTTP {response.status}: {response.reason}")
    
    def parse_indicators(self, data: Dict[str, Any]) -> List[ThreatIndicatorCreate]:
        """Parse JSON data into indicators"""
        indicators = []
        
        # Get parsing configuration
        indicator_path = self.config.get('indicator_path', 'indicators')
        value_field = self.config.get('value_field', 'value')
        type_field = self.config.get('type_field', 'type')
        description_field = self.config.get('description_field', 'description')
        tags_field = self.config.get('tags_field', 'tags')
        threat_level_field = self.config.get('threat_level_field', 'threat_level')
        
        # Navigate to indicators array
        indicator_data = data
        for key in indicator_path.split('.'):
            indicator_data = indicator_data.get(key, [])
        
        if not isinstance(indicator_data, list):
            indicator_data = [indicator_data]
        
        for item in indicator_data:
            try:
                # Extract values
                value = item.get(value_field)
                if not value:
                    continue
                
                # Map indicator type
                raw_type = item.get(type_field, 'unknown')
                indicator_type = self._map_indicator_type(raw_type)
                
                # Get description
                description = item.get(description_field, f"Custom feed: {self.source.name}")
                
                # Get tags
                tags = item.get(tags_field, [])
                if isinstance(tags, str):
                    tags = [tags]
                
                # Get threat level
                raw_level = item.get(threat_level_field, 'medium')
                threat_level = self._map_threat_level(raw_level)
                
                # Create indicator
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
                        'parser': 'json',
                        'raw_data': item
                    }
                )
                
                indicators.append(indicator)
                
            except Exception as e:
                logger.error(f"Error parsing JSON indicator: {e}")
                continue
        
        return indicators
    
    def _map_indicator_type(self, raw_type: str) -> IndicatorType:
        """Map raw type to IndicatorType enum"""
        type_mapping = {
            'ip': IndicatorType.IP_ADDRESS,
            'domain': IndicatorType.DOMAIN,
            'url': IndicatorType.URL,
            'hash': IndicatorType.HASH,
            'md5': IndicatorType.HASH,
            'sha1': IndicatorType.HASH,
            'sha256': IndicatorType.HASH,
            'email': IndicatorType.EMAIL,
            'malware': IndicatorType.MALWARE,
            'registry': IndicatorType.REGISTRY_KEY
        }
        return type_mapping.get(raw_type.lower(), IndicatorType.IP_ADDRESS)
    
    def _map_threat_level(self, raw_level: str) -> ThreatLevel:
        """Map raw threat level to ThreatLevel enum"""
        level_mapping = {
            'low': ThreatLevel.LOW,
            'medium': ThreatLevel.MEDIUM,
            'high': ThreatLevel.HIGH,
            'critical': ThreatLevel.CRITICAL
        }
        return level_mapping.get(raw_level.lower(), ThreatLevel.MEDIUM)


class CSVFeedParser(CustomFeedParser):
    """Parser for CSV-based threat feeds"""
    
    async def fetch_data(self) -> str:
        """Fetch CSV data from the source"""
        url = self.config.get('url')
        headers = self.config.get('headers', {})
        
        async with self.session.get(url, headers=headers) as response:
            if response.status == 200:
                return await response.text()
            else:
                raise Exception(f"HTTP {response.status}: {response.reason}")
    
    def parse_indicators(self, data: str) -> List[ThreatIndicatorCreate]:
        """Parse CSV data into indicators"""
        indicators = []
        
        # Get parsing configuration
        delimiter = self.config.get('delimiter', ',')
        has_header = self.config.get('has_header', True)
        value_column = self.config.get('value_column', 0)
        type_column = self.config.get('type_column')
        description_column = self.config.get('description_column')
        tags_column = self.config.get('tags_column')
        threat_level_column = self.config.get('threat_level_column')
        
        # Parse CSV
        lines = data.strip().split('\n')
        if has_header:
            lines = lines[1:]
        
        for line in lines:
            try:
                row = line.split(delimiter)
                
                # Extract value
                value = row[value_column].strip()
                if not value:
                    continue
                
                # Extract type
                raw_type = 'unknown'
                if type_column is not None and type_column < len(row):
                    raw_type = row[type_column].strip()
                indicator_type = self._map_indicator_type(raw_type)
                
                # Extract description
                description = f"Custom feed: {self.source.name}"
                if description_column is not None and description_column < len(row):
                    description = row[description_column].strip()
                
                # Extract tags
                tags = []
                if tags_column is not None and tags_column < len(row):
                    tags_str = row[tags_column].strip()
                    if tags_str:
                        tags = [tag.strip() for tag in tags_str.split('|')]
                
                # Extract threat level
                raw_level = 'medium'
                if threat_level_column is not None and threat_level_column < len(row):
                    raw_level = row[threat_level_column].strip()
                threat_level = self._map_threat_level(raw_level)
                
                # Create indicator
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
                        'parser': 'csv',
                        'row_data': row
                    }
                )
                
                indicators.append(indicator)
                
            except Exception as e:
                logger.error(f"Error parsing CSV indicator: {e}")
                continue
        
        return indicators
    
    def _map_indicator_type(self, raw_type: str) -> IndicatorType:
        """Map raw type to IndicatorType enum"""
        type_mapping = {
            'ip': IndicatorType.IP_ADDRESS,
            'domain': IndicatorType.DOMAIN,
            'url': IndicatorType.URL,
            'hash': IndicatorType.HASH,
            'md5': IndicatorType.HASH,
            'sha1': IndicatorType.HASH,
            'sha256': IndicatorType.HASH,
            'email': IndicatorType.EMAIL,
            'malware': IndicatorType.MALWARE,
            'registry': IndicatorType.REGISTRY_KEY
        }
        return type_mapping.get(raw_type.lower(), IndicatorType.IP_ADDRESS)
    
    def _map_threat_level(self, raw_level: str) -> ThreatLevel:
        """Map raw threat level to ThreatLevel enum"""
        level_mapping = {
            'low': ThreatLevel.LOW,
            'medium': ThreatLevel.MEDIUM,
            'high': ThreatLevel.HIGH,
            'critical': ThreatLevel.CRITICAL
        }
        return level_mapping.get(raw_level.lower(), ThreatLevel.MEDIUM)


class XMLFeedParser(CustomFeedParser):
    """Parser for XML-based threat feeds"""
    
    async def fetch_data(self) -> str:
        """Fetch XML data from the source"""
        url = self.config.get('url')
        headers = self.config.get('headers', {})
        
        async with self.session.get(url, headers=headers) as response:
            if response.status == 200:
                return await response.text()
            else:
                raise Exception(f"HTTP {response.status}: {response.reason}")
    
    def parse_indicators(self, data: str) -> List[ThreatIndicatorCreate]:
        """Parse XML data into indicators"""
        indicators = []
        
        try:
            root = ET.fromstring(data)
            
            # Get parsing configuration
            indicator_xpath = self.config.get('indicator_xpath', './/indicator')
            value_xpath = self.config.get('value_xpath', './value')
            type_xpath = self.config.get('type_xpath', './type')
            description_xpath = self.config.get('description_xpath', './description')
            tags_xpath = self.config.get('tags_xpath', './tags')
            threat_level_xpath = self.config.get('threat_level_xpath', './threat_level')
            
            # Find all indicator elements
            indicator_elements = root.findall(indicator_xpath)
            
            for element in indicator_elements:
                try:
                    # Extract value
                    value_elem = element.find(value_xpath)
                    if value_elem is None or not value_elem.text:
                        continue
                    value = value_elem.text.strip()
                    
                    # Extract type
                    type_elem = element.find(type_xpath)
                    raw_type = type_elem.text.strip() if type_elem is not None else 'unknown'
                    indicator_type = self._map_indicator_type(raw_type)
                    
                    # Extract description
                    desc_elem = element.find(description_xpath)
                    description = desc_elem.text.strip() if desc_elem is not None else f"Custom feed: {self.source.name}"
                    
                    # Extract tags
                    tags = []
                    tags_elem = element.find(tags_xpath)
                    if tags_elem is not None and tags_elem.text:
                        tags = [tag.strip() for tag in tags_elem.text.split('|')]
                    
                    # Extract threat level
                    level_elem = element.find(threat_level_xpath)
                    raw_level = level_elem.text.strip() if level_elem is not None else 'medium'
                    threat_level = self._map_threat_level(raw_level)
                    
                    # Create indicator
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
                            'parser': 'xml',
                            'element_data': ET.tostring(element, encoding='unicode')
                        }
                    )
                    
                    indicators.append(indicator)
                    
                except Exception as e:
                    logger.error(f"Error parsing XML indicator: {e}")
                    continue
        
        except Exception as e:
            logger.error(f"Error parsing XML feed: {e}")
        
        return indicators
    
    def _map_indicator_type(self, raw_type: str) -> IndicatorType:
        """Map raw type to IndicatorType enum"""
        type_mapping = {
            'ip': IndicatorType.IP_ADDRESS,
            'domain': IndicatorType.DOMAIN,
            'url': IndicatorType.URL,
            'hash': IndicatorType.HASH,
            'md5': IndicatorType.HASH,
            'sha1': IndicatorType.HASH,
            'sha256': IndicatorType.HASH,
            'email': IndicatorType.EMAIL,
            'malware': IndicatorType.MALWARE,
            'registry': IndicatorType.REGISTRY_KEY
        }
        return type_mapping.get(raw_type.lower(), IndicatorType.IP_ADDRESS)
    
    def _map_threat_level(self, raw_level: str) -> ThreatLevel:
        """Map raw threat level to ThreatLevel enum"""
        level_mapping = {
            'low': ThreatLevel.LOW,
            'medium': ThreatLevel.MEDIUM,
            'high': ThreatLevel.HIGH,
            'critical': ThreatLevel.CRITICAL
        }
        return level_mapping.get(raw_level.lower(), ThreatLevel.MEDIUM)


class CustomFeedParserManager:
    """Manager for custom feed parsers"""
    
    def __init__(self):
        self.parsers_dir = Path("custom_parsers")
        self.parsers_dir.mkdir(exist_ok=True)
        self.loaded_parsers = {}
        self._load_custom_parsers()
    
    def _load_custom_parsers(self):
        """Load custom parser modules from the parsers directory"""
        for parser_file in self.parsers_dir.glob("*.py"):
            try:
                # Load the module
                spec = importlib.util.spec_from_file_location(
                    parser_file.stem, parser_file
                )
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                
                # Find parser classes
                for name, obj in inspect.getmembers(module):
                    if (inspect.isclass(obj) and 
                        issubclass(obj, CustomFeedParser) and 
                        obj != CustomFeedParser):
                        self.loaded_parsers[name] = obj
                        logger.info(f"Loaded custom parser: {name}")
                        
            except Exception as e:
                logger.error(f"Error loading custom parser {parser_file}: {e}")
    
    def create_parser(self, source: ThreatSource, config: Dict[str, Any]) -> CustomFeedParser:
        """Create a parser instance based on configuration"""
        parser_type = config.get('parser_type', 'json')
        
        if parser_type == 'json':
            return JSONFeedParser(source, config)
        elif parser_type == 'csv':
            return CSVFeedParser(source, config)
        elif parser_type == 'xml':
            return XMLFeedParser(source, config)
        elif parser_type == 'custom':
            # Use custom parser class
            parser_class_name = config.get('parser_class')
            if parser_class_name in self.loaded_parsers:
                parser_class = self.loaded_parsers[parser_class_name]
                return parser_class(source, config)
            else:
                raise ValueError(f"Custom parser class '{parser_class_name}' not found")
        else:
            raise ValueError(f"Unknown parser type: {parser_type}")
    
    def get_available_parsers(self) -> List[str]:
        """Get list of available parser types"""
        return ['json', 'csv', 'xml', 'custom'] + list(self.loaded_parsers.keys())
    
    def validate_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Validate parser configuration"""
        errors = []
        
        parser_type = config.get('parser_type')
        if not parser_type:
            errors.append("parser_type is required")
        
        url = config.get('url')
        if not url:
            errors.append("url is required")
        
        if parser_type == 'json':
            if not config.get('indicator_path'):
                errors.append("indicator_path is required for JSON parser")
        
        elif parser_type == 'csv':
            if config.get('value_column') is None:
                errors.append("value_column is required for CSV parser")
        
        elif parser_type == 'xml':
            if not config.get('indicator_xpath'):
                errors.append("indicator_xpath is required for XML parser")
        
        elif parser_type == 'custom':
            if not config.get('parser_class'):
                errors.append("parser_class is required for custom parser")
        
        if errors:
            raise ValueError(f"Configuration errors: {', '.join(errors)}")
        
        return config


class CustomFeedFetcher(BaseFeedFetcher):
    """Custom feed fetcher that uses the parser manager"""
    
    def __init__(self, source: ThreatSource):
        super().__init__(source)
        self.parser_manager = CustomFeedParserManager()
        
        # Parse configuration from source metadata
        config_str = source.metadata.get('custom_parser_config', '{}')
        try:
            self.config = json.loads(config_str)
        except json.JSONDecodeError:
            self.config = {}
    
    async def fetch_indicators(self) -> List[ThreatIndicatorCreate]:
        """Fetch indicators using custom parser"""
        try:
            # Validate configuration
            self.parser_manager.validate_config(self.config)
            
            # Create parser
            parser = self.parser_manager.create_parser(self.source, self.config)
            
            # Fetch indicators
            async with parser:
                indicators = await parser.fetch_indicators()
            
            return indicators
            
        except Exception as e:
            logger.error(f"Error in custom feed fetcher: {e}")
            return []
