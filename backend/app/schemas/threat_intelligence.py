from pydantic import BaseModel, Field, validator
from typing import List, Optional, Dict, Any
from datetime import datetime
from enum import Enum


class IndicatorType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH = "hash"
    EMAIL = "email"
    CVE = "cve"


class ThreatLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SourceType(str, Enum):
    GOVERNMENT = "government"
    OPENSOURCE = "opensource"
    COMMERCIAL = "commercial"
    DARKWEB = "darkweb"


class JobStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class PatternType(str, Enum):
    EXACT = "exact"
    REGEX = "regex"
    WILDCARD = "wildcard"


# Base schemas
class ThreatSourceBase(BaseModel):
    name: str = Field(..., description="Name of the threat source")
    description: Optional[str] = Field(None, description="Description of the source")
    url: Optional[str] = Field(None, description="URL of the source")
    source_type: SourceType = Field(..., description="Type of threat source")
    rate_limit_per_minute: int = Field(10, description="Rate limit per minute")
    rate_limit_per_hour: int = Field(1000, description="Rate limit per hour")


class ThreatSourceCreate(ThreatSourceBase):
    api_key: Optional[str] = Field(None, description="API key for the source")


class ThreatSourceUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    url: Optional[str] = None
    api_key: Optional[str] = None
    is_active: Optional[bool] = None
    source_type: Optional[SourceType] = None
    rate_limit_per_minute: Optional[int] = None
    rate_limit_per_hour: Optional[int] = None


class ThreatSource(ThreatSourceBase):
    id: int
    is_active: bool
    last_fetch: Optional[datetime]
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True


class ThreatIndicatorBase(BaseModel):
    indicator_type: IndicatorType = Field(..., description="Type of threat indicator")
    value: str = Field(..., description="The indicator value")
    confidence_score: float = Field(0.0, ge=0.0, le=1.0, description="Confidence score")
    threat_level: ThreatLevel = Field(ThreatLevel.LOW, description="Threat level")
    tags: Optional[List[str]] = Field(None, description="Tags for the indicator")
    description: Optional[str] = Field(None, description="Description of the indicator")


class ThreatIndicatorCreate(ThreatIndicatorBase):
    source_id: int = Field(..., description="ID of the source")
    external_id: Optional[str] = Field(None, description="External ID from source")
    metadata: Optional[Dict[str, Any]] = Field(None, description="Additional metadata")


class ThreatIndicatorUpdate(BaseModel):
    confidence_score: Optional[float] = Field(None, ge=0.0, le=1.0)
    threat_level: Optional[ThreatLevel] = None
    tags: Optional[List[str]] = None
    description: Optional[str] = None
    is_active: Optional[bool] = None
    metadata: Optional[Dict[str, Any]] = None


class ThreatIndicator(ThreatIndicatorBase):
    id: int
    normalized_value: str
    first_seen: datetime
    last_seen: datetime
    source_id: int
    external_id: Optional[str]
    metadata: Optional[Dict[str, Any]]
    is_active: bool
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True


class IndicatorExclusionBase(BaseModel):
    indicator_type: IndicatorType = Field(..., description="Type of indicator to exclude")
    value: str = Field(..., description="Value or pattern to exclude")
    pattern_type: PatternType = Field(PatternType.EXACT, description="Type of pattern matching")
    reason: Optional[str] = Field(None, description="Reason for exclusion")
    excluded_by: Optional[str] = Field(None, description="User or system that created exclusion")


class IndicatorExclusionCreate(IndicatorExclusionBase):
    pass


class IndicatorExclusionUpdate(BaseModel):
    value: Optional[str] = None
    pattern_type: Optional[PatternType] = None
    reason: Optional[str] = None
    is_active: Optional[bool] = None


class IndicatorExclusion(IndicatorExclusionBase):
    id: int
    is_active: bool
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True


class ThreatCampaignBase(BaseModel):
    name: str = Field(..., description="Name of the threat campaign")
    description: Optional[str] = Field(None, description="Description of the campaign")
    threat_actors: Optional[List[str]] = Field(None, description="List of threat actors")
    techniques: Optional[List[str]] = Field(None, description="MITRE ATT&CK techniques")


class ThreatCampaignCreate(ThreatCampaignBase):
    pass


class ThreatCampaignUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    threat_actors: Optional[List[str]] = None
    techniques: Optional[List[str]] = None
    is_active: Optional[bool] = None
    metadata: Optional[Dict[str, Any]] = None


class ThreatCampaign(ThreatCampaignBase):
    id: int
    first_seen: datetime
    last_seen: datetime
    is_active: bool
    metadata: Optional[Dict[str, Any]]
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True


class FeedConfigurationBase(BaseModel):
    source_name: str = Field(..., description="Name of the feed source")
    is_enabled: bool = Field(True, description="Whether the feed is enabled")
    base_url: Optional[str] = Field(None, description="Base URL for the API")
    endpoints: Optional[Dict[str, Any]] = Field(None, description="Endpoint configurations")
    rate_limits: Optional[Dict[str, Any]] = Field(None, description="Rate limiting configuration")
    headers: Optional[Dict[str, str]] = Field(None, description="Custom headers")
    parameters: Optional[Dict[str, Any]] = Field(None, description="Custom parameters")


class FeedConfigurationCreate(FeedConfigurationBase):
    api_key: Optional[str] = Field(None, description="API key for the feed")


class FeedConfigurationUpdate(BaseModel):
    is_enabled: Optional[bool] = None
    api_key: Optional[str] = None
    base_url: Optional[str] = None
    endpoints: Optional[Dict[str, Any]] = None
    rate_limits: Optional[Dict[str, Any]] = None
    headers: Optional[Dict[str, str]] = None
    parameters: Optional[Dict[str, Any]] = None


class FeedConfiguration(FeedConfigurationBase):
    id: int
    api_key: Optional[str]
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True


class FetchJobBase(BaseModel):
    source_name: str = Field(..., description="Name of the source to fetch from")
    metadata: Optional[Dict[str, Any]] = Field(None, description="Additional metadata")


class FetchJobCreate(FetchJobBase):
    pass


class FetchJob(FetchJobBase):
    id: int
    status: JobStatus
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    indicators_found: int
    indicators_new: int
    error_message: Optional[str]
    created_at: datetime
    
    class Config:
        from_attributes = True


class DarkWebSourceBase(BaseModel):
    name: str = Field(..., description="Name of the dark web source")
    url: Optional[str] = Field(None, description="URL of the source")
    description: Optional[str] = Field(None, description="Description of the source")
    requires_tor: bool = Field(True, description="Whether Tor is required")
    scrape_interval_hours: int = Field(24, description="Scrape interval in hours")


class DarkWebSourceCreate(DarkWebSourceBase):
    pass


class DarkWebSourceUpdate(BaseModel):
    name: Optional[str] = None
    url: Optional[str] = None
    description: Optional[str] = None
    is_active: Optional[bool] = None
    requires_tor: Optional[bool] = None
    scrape_interval_hours: Optional[int] = None


class DarkWebSource(DarkWebSourceBase):
    id: int
    is_active: bool
    last_scrape: Optional[datetime]
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True


# API Response schemas
class PaginatedResponse(BaseModel):
    items: List[Any]
    total: int
    page: int
    size: int
    pages: int


class ThreatIntelligenceSummary(BaseModel):
    total_indicators: int
    indicators_by_type: Dict[str, int]
    indicators_by_level: Dict[str, int]
    active_sources: int
    last_update: datetime


class DeduplicationResult(BaseModel):
    original_count: int
    deduplicated_count: int
    duplicates_found: int
    processing_time: float


class ExclusionTestResult(BaseModel):
    matches: List[Dict[str, Any]]
    total_matches: int
    test_value: str
    test_type: str
