from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.v1.endpoints import auth, custom_parsers, ml_scoring

app = FastAPI(
    title="Malsift Threat Intelligence Platform API",
    description="A comprehensive threat intelligence platform API",
    version="1.0.0"
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(auth.router, prefix="/api/v1/auth", tags=["authentication"])
app.include_router(custom_parsers.router, prefix="/api/v1/custom-parsers", tags=["custom-parsers"])
app.include_router(ml_scoring.router, prefix="/api/v1/ml-scoring", tags=["ml-scoring"])

@app.get("/")
async def root():
    return {"message": "Malsift Threat Intelligence Platform API"}

@app.get("/health")
async def health_check():
    return {"status": "healthy"}
