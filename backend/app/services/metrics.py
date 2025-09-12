from prometheus_client import Counter, Histogram, Gauge, Summary, generate_latest, CONTENT_TYPE_LATEST
from fastapi import Response
from loguru import logger

# Metrics definitions
INDICATORS_CREATED = Counter(
    'threat_indicators_created_total',
    'Total number of threat indicators created',
    ['source', 'indicator_type', 'threat_level']
)

INDICATORS_FETCHED = Counter(
    'threat_indicators_fetched_total',
    'Total number of threat indicators fetched from sources',
    ['source', 'status']
)

FEED_FETCH_DURATION = Histogram(
    'feed_fetch_duration_seconds',
    'Time spent fetching from threat intelligence feeds',
    ['source', 'status']
)

FEED_FETCH_ERRORS = Counter(
    'feed_fetch_errors_total',
    'Total number of feed fetch errors',
    ['source', 'error_type']
)

API_REQUESTS = Counter(
    'api_requests_total',
    'Total number of API requests',
    ['method', 'endpoint', 'status_code']
)

API_REQUEST_DURATION = Histogram(
    'api_request_duration_seconds',
    'Time spent processing API requests',
    ['method', 'endpoint']
)

ACTIVE_INDICATORS = Gauge(
    'active_indicators_total',
    'Total number of active threat indicators',
    ['indicator_type', 'threat_level']
)

ACTIVE_SOURCES = Gauge(
    'active_sources_total',
    'Total number of active threat intelligence sources',
    ['source_type']
)

DEDUPLICATION_PROCESSING_TIME = Summary(
    'deduplication_processing_time_seconds',
    'Time spent on deduplication processing'
)

DARKWEB_SCRAPES = Counter(
    'darkweb_scrapes_total',
    'Total number of dark web scraping attempts',
    ['source', 'status']
)


def setup_metrics():
    """Setup metrics collection"""
    logger.info("Setting up metrics collection")


def get_metrics():
    """Get metrics in Prometheus format"""
    return generate_latest()


def update_indicator_metrics(source: str, indicator_type: str, threat_level: str):
    """Update indicator creation metrics"""
    INDICATORS_CREATED.labels(
        source=source,
        indicator_type=indicator_type,
        threat_level=threat_level
    ).inc()


def update_feed_fetch_metrics(source: str, status: str, duration: float, error_type: str = None):
    """Update feed fetch metrics"""
    INDICATORS_FETCHED.labels(source=source, status=status).inc()
    FEED_FETCH_DURATION.labels(source=source, status=status).observe(duration)
    
    if error_type:
        FEED_FETCH_ERRORS.labels(source=source, error_type=error_type).inc()


def update_api_metrics(method: str, endpoint: str, status_code: int, duration: float):
    """Update API request metrics"""
    API_REQUESTS.labels(
        method=method,
        endpoint=endpoint,
        status_code=status_code
    ).inc()
    
    API_REQUEST_DURATION.labels(
        method=method,
        endpoint=endpoint
    ).observe(duration)


def update_active_indicators_metrics(indicators_by_type: dict, indicators_by_level: dict):
    """Update active indicators gauge metrics"""
    # Update by type
    for indicator_type, count in indicators_by_type.items():
        ACTIVE_INDICATORS.labels(
            indicator_type=indicator_type,
            threat_level="all"
        ).set(count)
    
    # Update by threat level
    for threat_level, count in indicators_by_level.items():
        ACTIVE_INDICATORS.labels(
            indicator_type="all",
            threat_level=threat_level
        ).set(count)


def update_active_sources_metrics(sources_by_type: dict):
    """Update active sources gauge metrics"""
    for source_type, count in sources_by_type.items():
        ACTIVE_SOURCES.labels(source_type=source_type).set(count)


def update_darkweb_metrics(source: str, status: str):
    """Update dark web scraping metrics"""
    DARKWEB_SCRAPES.labels(source=source, status=status).inc()


def get_metrics_response():
    """Get metrics response for FastAPI endpoint"""
    return Response(
        content=get_metrics(),
        media_type=CONTENT_TYPE_LATEST
    )
