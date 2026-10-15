from app.db import init_db
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.router import api_router
from app.core.config import settings


@asynccontextmanager
async def lifespan(_: FastAPI):
    await init_db()
    yield


app = FastAPI(
    title=settings.app_name,
    description="Network forensic investigation API for NetForensicX.",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router)


@app.get("/health", tags=["system"])
async def health():
    return {
        "status": "ok",
        "service": "netforensicx-api",
        "version": "0.1.0",
    }


@app.get("/", tags=["system"])
async def root():
    return {
        "name": "NetForensicX API",
        "docs": "/docs",
        "health": "/health",
    }
