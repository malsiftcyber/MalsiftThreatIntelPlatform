from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Text, JSON, Float
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.core.database import Base
import uuid

class EDRConnection(Base):
    """EDR platform connection configuration"""
    __tablename__ = "edr_connections"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), unique=True, index=True, nullable=False)
    platform = Column(String(50), nullable=False)  # crowdstrike, sentinelone, defender
    api_endpoint = Column(String(500), nullable=False)
    api_key = Column(String(500), nullable=False)
    client_id = Column(String(255), nullable=True)  # For OAuth2
    client_secret = Column(String(500), nullable=True)  # For OAuth2
    tenant_id = Column(String(255), nullable=True)  # For Microsoft Defender
    is_active = Column(Boolean, default=True)
    last_sync = Column(DateTime(timezone=True), nullable=True)
    sync_frequency = Column(Integer, default=3600)  # seconds
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    extractions = relationship("EDRExtraction", back_populates="connection", cascade="all, delete-orphan")
    analyses = relationship("EDRAnalysis", back_populates="connection", cascade="all, delete-orphan")

class EDRExtraction(Base):
    """EDR data extraction job"""
    __tablename__ = "edr_extractions"
    
    id = Column(Integer, primary_key=True, index=True)
    connection_id = Column(Integer, ForeignKey("edr_connections.id"), nullable=False)
    job_id = Column(String(255), unique=True, index=True, nullable=False, default=lambda: str(uuid.uuid4()))
    status = Column(String(50), default="pending")  # pending, running, completed, failed
    extraction_type = Column(String(50), nullable=False)  # indicators, alerts, events
    filters = Column(JSON, nullable=True)  # Extraction filters
    start_time = Column(DateTime(timezone=True), nullable=True)
    end_time = Column(DateTime(timezone=True), nullable=True)
    total_records = Column(Integer, default=0)
    processed_records = Column(Integer, default=0)
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    connection = relationship("EDRConnection", back_populates="extractions")
    indicators = relationship("EDRIndicator", back_populates="extraction", cascade="all, delete-orphan")

class EDRIndicator(Base):
    """Indicators extracted from EDR platforms"""
    __tablename__ = "edr_indicators"
    
    id = Column(Integer, primary_key=True, index=True)
    extraction_id = Column(Integer, ForeignKey("edr_extractions.id"), nullable=False)
    indicator_type = Column(String(50), nullable=False)  # ip, domain, url, hash, file_path
    indicator_value = Column(String(1000), nullable=False)
    source_event_id = Column(String(255), nullable=True)
    source_device_id = Column(String(255), nullable=True)
    detection_timestamp = Column(DateTime(timezone=True), nullable=True)
    confidence_score = Column(Float, nullable=True)
    severity = Column(String(50), nullable=True)  # low, medium, high, critical
    context_data = Column(JSON, nullable=True)  # Additional context from EDR
    is_known_threat = Column(Boolean, default=False)
    threat_intel_match = Column(JSON, nullable=True)  # Matched threat intelligence
    llm_analysis = Column(JSON, nullable=True)  # LLM analysis results
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    extraction = relationship("EDRExtraction", back_populates="indicators")
    analyses = relationship("EDRAnalysis", back_populates="indicator", cascade="all, delete-orphan")

class EDRAnalysis(Base):
    """LLM analysis of EDR indicators"""
    __tablename__ = "edr_analyses"
    
    id = Column(Integer, primary_key=True, index=True)
    connection_id = Column(Integer, ForeignKey("edr_connections.id"), nullable=False)
    indicator_id = Column(Integer, ForeignKey("edr_indicators.id"), nullable=False)
    llm_provider = Column(String(50), nullable=False)  # openai, anthropic
    llm_model = Column(String(100), nullable=False)  # gpt-4, claude-3
    analysis_prompt = Column(Text, nullable=False)
    analysis_response = Column(Text, nullable=False)
    malicious_probability = Column(Float, nullable=True)  # 0.0 to 1.0
    analysis_confidence = Column(Float, nullable=True)  # 0.0 to 1.0
    reasoning = Column(Text, nullable=True)
    recommended_actions = Column(JSON, nullable=True)
    processing_time = Column(Float, nullable=True)  # seconds
    cost = Column(Float, nullable=True)  # API cost
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    connection = relationship("EDRConnection", back_populates="analyses")
    indicator = relationship("EDRIndicator", back_populates="analyses")

class LLMConfiguration(Base):
    """LLM service configuration"""
    __tablename__ = "llm_configurations"
    
    id = Column(Integer, primary_key=True, index=True)
    provider = Column(String(50), unique=True, index=True, nullable=False)  # openai, anthropic
    api_key = Column(String(500), nullable=False)
    api_endpoint = Column(String(500), nullable=True)
    default_model = Column(String(100), nullable=False)
    max_tokens = Column(Integer, default=4000)
    temperature = Column(Float, default=0.1)
    is_active = Column(Boolean, default=True)
    cost_per_token = Column(Float, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

class ThreatIntelligenceMatch(Base):
    """Matches between EDR indicators and threat intelligence"""
    __tablename__ = "threat_intelligence_matches"
    
    id = Column(Integer, primary_key=True, index=True)
    edr_indicator_id = Column(Integer, ForeignKey("edr_indicators.id"), nullable=False)
    threat_indicator_id = Column(Integer, ForeignKey("threat_indicators.id"), nullable=False)
    match_type = Column(String(50), nullable=False)  # exact, fuzzy, domain_based
    match_confidence = Column(Float, nullable=False)
    match_details = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    edr_indicator = relationship("EDRIndicator")
    threat_indicator = relationship("ThreatIndicator")
