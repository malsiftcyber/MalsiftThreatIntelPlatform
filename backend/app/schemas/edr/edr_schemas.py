from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum

class EDRPlatform(str, Enum):
    CROWDSTRIKE = "crowdstrike"
    SENTINELONE = "sentinelone"
    DEFENDER = "defender"

class ExtractionStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"

class IndicatorType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH = "hash"
    FILE_PATH = "file_path"
    EMAIL = "email"

class SeverityLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class LLMProvider(str, Enum):
    OPENAI = "openai"
    ANTHROPIC = "anthropic"

# EDR Connection Schemas
class EDRConnectionBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    platform: EDRPlatform
    api_endpoint: str = Field(..., min_length=1, max_length=500)
    api_key: str = Field(..., min_length=1, max_length=500)
    client_id: Optional[str] = Field(None, max_length=255)
    client_secret: Optional[str] = Field(None, max_length=500)
    tenant_id: Optional[str] = Field(None, max_length=255)
    is_active: bool = True
    sync_frequency: int = Field(3600, ge=300, le=86400)  # 5 minutes to 24 hours

class EDRConnectionCreate(EDRConnectionBase):
    pass

class EDRConnectionUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    api_endpoint: Optional[str] = Field(None, min_length=1, max_length=500)
    api_key: Optional[str] = Field(None, min_length=1, max_length=500)
    client_id: Optional[str] = Field(None, max_length=255)
    client_secret: Optional[str] = Field(None, max_length=500)
    tenant_id: Optional[str] = Field(None, max_length=255)
    is_active: Optional[bool] = None
    sync_frequency: Optional[int] = Field(None, ge=300, le=86400)

class EDRConnection(EDRConnectionBase):
    id: int
    last_sync: Optional[datetime] = None
    created_at: datetime
    updated_at: Optional[datetime] = None
    
    class Config:
        from_attributes = True

# EDR Extraction Schemas
class EDRExtractionBase(BaseModel):
    extraction_type: str = Field(..., min_length=1, max_length=50)
    filters: Optional[Dict[str, Any]] = None

class EDRExtractionCreate(EDRExtractionBase):
    connection_id: int

class EDRExtraction(EDRExtractionBase):
    id: int
    connection_id: int
    job_id: str
    status: ExtractionStatus
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    total_records: int = 0
    processed_records: int = 0
    error_message: Optional[str] = None
    created_at: datetime
    
    class Config:
        from_attributes = True

# EDR Indicator Schemas
class EDRIndicatorBase(BaseModel):
    indicator_type: IndicatorType
    indicator_value: str = Field(..., min_length=1, max_length=1000)
    source_event_id: Optional[str] = Field(None, max_length=255)
    source_device_id: Optional[str] = Field(None, max_length=255)
    detection_timestamp: Optional[datetime] = None
    confidence_score: Optional[float] = Field(None, ge=0.0, le=1.0)
    severity: Optional[SeverityLevel] = None
    context_data: Optional[Dict[str, Any]] = None

class EDRIndicatorCreate(EDRIndicatorBase):
    extraction_id: int

class EDRIndicator(EDRIndicatorBase):
    id: int
    extraction_id: int
    is_known_threat: bool = False
    threat_intel_match: Optional[Dict[str, Any]] = None
    llm_analysis: Optional[Dict[str, Any]] = None
    created_at: datetime
    
    class Config:
        from_attributes = True

# EDR Analysis Schemas
class EDRAnalysisBase(BaseModel):
    llm_provider: LLMProvider
    llm_model: str = Field(..., min_length=1, max_length=100)
    analysis_prompt: str = Field(..., min_length=1)
    analysis_response: str = Field(..., min_length=1)
    malicious_probability: Optional[float] = Field(None, ge=0.0, le=1.0)
    analysis_confidence: Optional[float] = Field(None, ge=0.0, le=1.0)
    reasoning: Optional[str] = None
    recommended_actions: Optional[List[str]] = None
    processing_time: Optional[float] = Field(None, ge=0.0)
    cost: Optional[float] = Field(None, ge=0.0)

class EDRAnalysisCreate(EDRAnalysisBase):
    connection_id: int
    indicator_id: int

class EDRAnalysis(EDRAnalysisBase):
    id: int
    connection_id: int
    indicator_id: int
    created_at: datetime
    
    class Config:
        from_attributes = True

# LLM Configuration Schemas
class LLMConfigurationBase(BaseModel):
    provider: LLMProvider
    api_key: str = Field(..., min_length=1, max_length=500)
    api_endpoint: Optional[str] = Field(None, max_length=500)
    default_model: str = Field(..., min_length=1, max_length=100)
    max_tokens: int = Field(4000, ge=100, le=32000)
    temperature: float = Field(0.1, ge=0.0, le=2.0)
    is_active: bool = True
    cost_per_token: Optional[float] = Field(None, ge=0.0)

class LLMConfigurationCreate(LLMConfigurationBase):
    pass

class LLMConfigurationUpdate(BaseModel):
    api_key: Optional[str] = Field(None, min_length=1, max_length=500)
    api_endpoint: Optional[str] = Field(None, max_length=500)
    default_model: Optional[str] = Field(None, min_length=1, max_length=100)
    max_tokens: Optional[int] = Field(None, ge=100, le=32000)
    temperature: Optional[float] = Field(None, ge=0.0, le=2.0)
    is_active: Optional[bool] = None
    cost_per_token: Optional[float] = Field(None, ge=0.0)

class LLMConfiguration(LLMConfigurationBase):
    id: int
    created_at: datetime
    updated_at: Optional[datetime] = None
    
    class Config:
        from_attributes = True

# Threat Intelligence Match Schemas
class ThreatIntelligenceMatchBase(BaseModel):
    edr_indicator_id: int
    threat_indicator_id: int
    match_type: str = Field(..., min_length=1, max_length=50)
    match_confidence: float = Field(..., ge=0.0, le=1.0)
    match_details: Optional[Dict[str, Any]] = None

class ThreatIntelligenceMatchCreate(ThreatIntelligenceMatchBase):
    pass

class ThreatIntelligenceMatch(ThreatIntelligenceMatchBase):
    id: int
    created_at: datetime
    
    class Config:
        from_attributes = True

# Analysis Request Schemas
class IndicatorAnalysisRequest(BaseModel):
    indicator_type: IndicatorType
    indicator_value: str = Field(..., min_length=1, max_length=1000)
    context_data: Optional[Dict[str, Any]] = None
    llm_provider: Optional[LLMProvider] = None
    llm_model: Optional[str] = None

class BulkAnalysisRequest(BaseModel):
    indicator_ids: List[int] = Field(..., min_items=1, max_items=100)
    llm_provider: Optional[LLMProvider] = None
    llm_model: Optional[str] = None

# Response Schemas
class EDRConnectionStatus(BaseModel):
    id: int
    name: str
    platform: EDRPlatform
    is_active: bool
    last_sync: Optional[datetime] = None
    status: str
    total_extractions: int
    total_indicators: int
    unknown_indicators: int
    analyzed_indicators: int

class EDRDashboardStats(BaseModel):
    total_connections: int
    active_connections: int
    total_extractions: int
    total_indicators: int
    unknown_indicators: int
    analyzed_indicators: int
    malicious_indicators: int
    total_llm_cost: float
    last_24h_indicators: int
    last_24h_analyses: int

class IndicatorAnalysisResult(BaseModel):
    indicator_id: int
    indicator_value: str
    indicator_type: IndicatorType
    is_known_threat: bool
    threat_intel_matches: List[Dict[str, Any]]
    llm_analysis: Optional[Dict[str, Any]] = None
    malicious_probability: Optional[float] = None
    analysis_confidence: Optional[float] = None
    recommended_actions: Optional[List[str]] = None
    processing_time: Optional[float] = None
    cost: Optional[float] = None
