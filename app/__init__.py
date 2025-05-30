# app/__init__.py

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError
from starlette.middleware.sessions import SessionMiddleware
import logging


from app.routers import (
    auth,
    admin,
    chat,
    doctor,
    ingest,
    receptionist,
    exam,
    quotation,
    documents,
    urls,
    simple_chat,
    vector_admin,
    auth_google,
)
from app.db.mongo import client, verify_mongodb_connection
from app.core.config import settings


def format_error_response(exc: Exception, status_code: int = 500):
    return {
        "success": False,
        "error": {
            "type": exc.__class__.__name__,
            "detail": str(exc),
            "status_code": status_code,
        },
    }


app = FastAPI(
    title="Healthcare AI Assistant",
    version="0.1.0",
    description="Backend for the Healthcare AI chatbot platform",
)

# ─── CORS ────────────────────────────────────────────────────────────────
origins = settings.frontend_urls
logging.info(f"Allowed CORS origins: {origins}")

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─── SESSION (for Authlib state) ───────────────────────────────────────
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.SECRET_KEY,  # from your .env
    same_site="lax",                 # allow cookie on OAuth redirect
    https_only=True,                 # ensure Secure cookie in prod
)

# ─── LIFECYCLE ─────────────────────────────────────────────────────────
@app.on_event("startup")
async def on_startup():
    await verify_mongodb_connection()

@app.on_event("shutdown")
async def on_shutdown():
    client.close()

# ─── HEALTH CHECK ────────────────────────────────────────────────────────
@app.get("/", tags=["root"], summary="Health check")
async def root():
    return {"status": "ok", "service": "Healthcare AI Assistant"}

# ─── ERROR HANDLERS ──────────────────────────────────────────────────────
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content=format_error_response(exc, exc.status_code),
    )

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=422,
        content=format_error_response(exc, 422),
    )

@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content=format_error_response(exc),
    )

# ─── ROUTERS ────────────────────────────────────────────────────────────
app.include_router(auth.router,         prefix="/auth")
app.include_router(admin.router,        prefix="/admin")
app.include_router(chat.router,         prefix="/chat")
app.include_router(simple_chat.router,  prefix="/chat")
app.include_router(doctor.router,       prefix="/doctors")
app.include_router(ingest.router,       prefix="/ingest")
app.include_router(receptionist.router, prefix="/reception")
app.include_router(exam.router,         prefix="/exam")
app.include_router(quotation.router,    prefix="/quote")
app.include_router(documents.router)
app.include_router(urls.router)
app.include_router(vector_admin.router)
app.include_router(auth_google.router)
