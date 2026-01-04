from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings
from app.core.database import engine, Base
from app.api import auth, certificates, ca, audit, api_token, scep_client, scep
from app.services.ca_service import ca_service
from app.core.logging import get_logger

# Configure logging
logger = get_logger(__name__)

# Create database tables
Base.metadata.create_all(bind=engine)

# Initialize CA if not exists
try:
    ca_service.initialize_ca()
except Exception as e:
    logger.error(f"Failed to initialize CA: {e}")

# Create FastAPI app
app = FastAPI(
    title=settings.PROJECT_NAME,
    description="Certificate Authority Management Platform",
    version="1.0.0",
    docs_url=f"{settings.API_V1_PREFIX}/docs",
    redoc_url=f"{settings.API_V1_PREFIX}/redoc",
    openapi_url=f"{settings.API_V1_PREFIX}/openapi.json",
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173"],  # Frontend URLs
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(auth.router, prefix=settings.API_V1_PREFIX)
app.include_router(api_token.router, prefix=settings.API_V1_PREFIX)
app.include_router(ca.router, prefix=settings.API_V1_PREFIX)
app.include_router(certificates.router, prefix=settings.API_V1_PREFIX)
app.include_router(scep_client.router, prefix=settings.API_V1_PREFIX)
app.include_router(scep.router, prefix=settings.API_V1_PREFIX)
app.include_router(audit.router, prefix=settings.API_V1_PREFIX)


@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "name": settings.PROJECT_NAME,
        "version": "1.0.0",
        "docs": f"{settings.API_V1_PREFIX}/docs",
    }


@app.get("/health")
async def health():
    """Health check endpoint"""
    return {"status": "healthy"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)