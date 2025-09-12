from sqlalchemy import Column, Integer, String, DateTime, Text, Boolean, Float, ForeignKey, JSON, Index
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from datetime import datetime
from app.core.database import Base


class ThreatSource(Base):
    """Model for threat intelligence sources"""
    __tablename__ = "threat_sources"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), unique=True, index=True, nullable=False)
    description = Column(Text)
    url = Column(String(500))
    api_key = Column(String(500))  # Encrypted
    is_active = Column(Boolean, default=True)
    source_type = Column(String(50))  # government, opensource, commercial
    rate_limit_per_minute = Column(Integer, default=10)
    rate_limit_per_hour = Column(Integer, default=1000)
    last_fetch = Column(DateTime, default=func.now())
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    
    # Relationships
    indicators = relationship("ThreatIndicator", back_populates="source")


class ThreatIndicator(Base):
    """Model for threat indicators"""
    __tablename__ = "threat_indicators"
    
    id = Column(Integer, primary_key=True, index=True)
    indicator_type = Column(String(50), nullable=False)  # ip, domain, url, hash, email
    value = Column(String(500), nullable=False)
    normalized_value = Column(String(500), nullable=False)  # For deduplication
    confidence_score = Column(Float, default=0.0)
    threat_level = Column(String(20), default="low")  # low, medium, high, critical
    tags = Column(JSON)  # Array of tags
    description = Column(Text)
    first_seen = Column(DateTime, default=func.now())
    last_seen = Column(DateTime, default=func.now())
    source_id = Column(Integer, ForeignKey("threat_sources.id"))
    external_id = Column(String(255))  # ID from external source
    metadata = Column(JSON)  # Additional metadata from source
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    
    # Relationships
    source = relationship("ThreatSource", back_populates="indicators")
    duplicates = relationship("IndicatorDuplicate", back_populates="indicator")
    
    # Indexes
    __table_args__ = (
        Index('idx_indicator_type_value', 'indicator_type', 'value'),
        Index('idx_normalized_value', 'normalized_value'),
        Index('idx_threat_level', 'threat_level'),
        Index('idx_first_seen', 'first_seen'),
    )


class IndicatorExclusion(Base):
    """Model for excluding indicators from API responses"""
    __tablename__ = "indicator_exclusions"
    
    id = Column(Integer, primary_key=True, index=True)
    indicator_type = Column(String(50), nullable=False)  # ip, domain, url, hash, email, or 'all'
    value = Column(String(500), nullable=False)  # Specific value or pattern
    pattern_type = Column(String(20), default="exact")  # exact, regex, wildcard
    reason = Column(Text)  # Reason for exclusion
    excluded_by = Column(String(255))  # User or system that created exclusion
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    
    # Indexes
    __table_args__ = (
        Index('idx_exclusion_type_value', 'indicator_type', 'value'),
        Index('idx_exclusion_pattern', 'pattern_type'),
    )


class IndicatorDuplicate(Base):
    """Model for tracking duplicate indicators"""
    __tablename__ = "indicator_duplicates"
    
    id = Column(Integer, primary_key=True, index=True)
    indicator_id = Column(Integer, ForeignKey("threat_indicators.id"))
    duplicate_indicator_id = Column(Integer, ForeignKey("threat_indicators.id"))
    similarity_score = Column(Float, nullable=False)
    created_at = Column(DateTime, default=func.now())
    
    # Relationships
    indicator = relationship("ThreatIndicator", back_populates="duplicates")


class ThreatCampaign(Base):
    """Model for threat campaigns"""
    __tablename__ = "threat_campaigns"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    description = Column(Text)
    threat_actors = Column(JSON)  # Array of threat actor names
    techniques = Column(JSON)  # MITRE ATT&CK techniques
    first_seen = Column(DateTime, default=func.now())
    last_seen = Column(DateTime, default=func.now())
    is_active = Column(Boolean, default=True)
    metadata = Column(JSON)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())


class FeedConfiguration(Base):
    """Model for feed configuration"""
    __tablename__ = "feed_configurations"
    
    id = Column(Integer, primary_key=True, index=True)
    source_name = Column(String(255), unique=True, nullable=False)
    is_enabled = Column(Boolean, default=True)
    api_key = Column(String(500))  # Encrypted
    base_url = Column(String(500))
    endpoints = Column(JSON)  # Array of endpoint configurations
    rate_limits = Column(JSON)  # Rate limiting configuration
    headers = Column(JSON)  # Custom headers
    parameters = Column(JSON)  # Custom parameters
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())


class FetchJob(Base):
    """Model for tracking fetch jobs"""
    __tablename__ = "fetch_jobs"
    
    id = Column(Integer, primary_key=True, index=True)
    source_name = Column(String(255), nullable=False)
    status = Column(String(20), default="pending")  # pending, running, completed, failed
    started_at = Column(DateTime)
    completed_at = Column(DateTime)
    indicators_found = Column(Integer, default=0)
    indicators_new = Column(Integer, default=0)
    error_message = Column(Text)
    metadata = Column(JSON)
    created_at = Column(DateTime, default=func.now())


class DarkWebSource(Base):
    """Model for dark web sources"""
    __tablename__ = "dark_web_sources"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    url = Column(String(500))
    description = Column(Text)
    is_active = Column(Boolean, default=True)
    requires_tor = Column(Boolean, default=True)
    last_scrape = Column(DateTime)
    scrape_interval_hours = Column(Integer, default=24)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())

