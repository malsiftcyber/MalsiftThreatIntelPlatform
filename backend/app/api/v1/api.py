from fastapi import APIRouter
from app.api.v1.endpoints import indicators, sources, campaigns, feeds, jobs, darkweb, exclusions, auth, feed_comparison, edr

api_router = APIRouter()

# Include all endpoint routers
api_router.include_router(auth.router, prefix="/auth", tags=["authentication"])
api_router.include_router(indicators.router, prefix="/indicators", tags=["indicators"])
api_router.include_router(sources.router, prefix="/sources", tags=["sources"])
api_router.include_router(campaigns.router, prefix="/campaigns", tags=["campaigns"])
api_router.include_router(feeds.router, prefix="/feeds", tags=["feeds"])
api_router.include_router(jobs.router, prefix="/jobs", tags=["jobs"])
api_router.include_router(darkweb.router, prefix="/darkweb", tags=["darkweb"])
api_router.include_router(exclusions.router, prefix="/exclusions", tags=["exclusions"])
api_router.include_router(feed_comparison.router, prefix="/feed-comparison", tags=["feed-comparison"])
api_router.include_router(edr.router, prefix="/edr", tags=["edr-integration"])
