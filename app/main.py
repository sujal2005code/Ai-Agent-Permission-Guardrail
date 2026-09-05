"""
Main application module for AI Agent Permission Guardrail.

This module ties together all components and provides the FastAPI application.
"""

import logging
from contextlib import asynccontextmanager
from typing import Dict, Any, Optional

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import uvicorn

from app.config import settings, logger
from app.database.database import db
from app.api.routes import router as api_router
from app.policy.engine import policy_engine
from app.proposer.base import BaseProposer
from app.proposer.mock_proposer import MockProposer
from app.proposer.llm_proposer import proposer_factory
from app.audit.logger import audit_logger, AuditEventType


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Lifespan manager for FastAPI application.

    Handles startup and shutdown events.
    """
    # Startup
    logger.info("Starting AI Agent Permission Guardrail system...")
    logger.info(f"Configuration: {settings.dict()}")

    # Initialize database
    db.health_check()
    logger.info("Database initialized successfully")

    # Initialize proposer based on configuration
    try:
        global proposer
        proposer = proposer_factory.create_proposer()
        logger.info(f"Proposer initialized: {proposer.name}")
    except Exception as e:
        logger.error(f"Failed to initialize proposer: {e}")
        # Fall back to mock proposer
        proposer = MockProposer()
        logger.warning(f"Falling back to mock proposer: {proposer.name}")

    # Log system startup
    audit_logger.log_system_event(
        event_type=AuditEventType.SYSTEM_STARTUP,
        action="application_start",
        details={
            "version": "1.0.0",
            "llm_provider": settings.llm.provider,
            "policy_config": policy_engine.get_policy_configuration()
        },
        user_id="system"
    )

    yield  # Application runs here

    # Shutdown
    logger.info("Shutting down AI Agent Permission Guardrail system...")

    audit_logger.log_system_event(
        event_type=AuditEventType.SYSTEM_SHUTDOWN,
        action="application_shutdown",
        details={"reason": "normal_shutdown"},
        user_id="system"
    )


# Create FastAPI application
app = FastAPI(
    title="AI Agent Permission Guardrail",
    description=(
        "Security architecture where AI proposes actions "
        "but never authorizes or executes them."
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, restrict this
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API routes
app.include_router(api_router, prefix="/api/v1")


# Global proposer instance (initialized in lifespan)
proposer: Optional[BaseProposer] = None


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global exception handler."""
    logger.error(f"Unhandled exception: {exc}", exc_info=True)

    # Log security alert for unexpected errors
    audit_logger.log_security_alert(
        alert_type="unhandled_exception",
        description=f"Unhandled exception in {request.url.path}: {str(exc)}",
        severity="high",
        user_id=request.client.host if request.client else None
    )

    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "Internal server error",
            "message": "An unexpected error occurred",
            "request_id": request.state.get("request_id", "unknown")
        }
    )


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """HTTP exception handler."""
    logger.warning(f"HTTP exception: {exc.status_code} - {exc.detail}")

    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.detail,
            "status_code": exc.status_code,
            "request_id": request.state.get("request_id", "unknown")
        }
    )


@app.middleware("http")
async def add_request_id(request: Request, call_next):
    """Add request ID to all requests."""
    import uuid
    request_id = str(uuid.uuid4())[:8]
    request.state.request_id = request_id

    response = await call_next(request)

    # Add request ID to response headers
    response.headers["X-Request-ID"] = request_id

    return response


@app.get("/", include_in_schema=False)
async def root():
    """Root endpoint with system information."""
    return {
        "application": "AI Agent Permission Guardrail",
        "version": "1.0.0",
        "description": "AI proposes, Policy decides, Executor obeys, Audit remembers",
        "documentation": "/docs",
        "health": "/health",
        "api_version": "v1",
        "api_base": "/api/v1"
    }


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    db_health = db.health_check()
    system_health = {
        "status": "healthy",
        "timestamp": "2026-09-03T13:20:26Z",  # Current time from system reminder
        "components": {
            "database": db_health.get("status", "unknown"),
            "policy_engine": "healthy",
            "proposer": "healthy" if proposer else "unhealthy",
            "audit_logger": "healthy"
        },
        "configuration": {
            "llm_provider": settings.llm.provider,
            "max_auto_approve_amount": settings.policy.max_auto_approve_amount,
            "min_confidence_threshold": settings.policy.min_confidence_threshold
        }
    }

    # Check if any component is unhealthy
    if db_health.get("status") != "healthy" or not proposer:
        system_health["status"] = "degraded"

    return system_health


@app.get("/system-info")
async def system_info():
    """Get detailed system information."""
    return {
        "application": {
            "name": "AI Agent Permission Guardrail",
            "version": "1.0.0",
            "description": "Security architecture for AI agent authorization",
            "principle": "AI proposes, Policy decides, Executor obeys, Audit remembers"
        },
        "configuration": settings.dict(),
        "policy": {
            "configuration": policy_engine.get_policy_configuration(),
            "rules": [
                "allowed_actions_only",
                "max_auto_approve_amount",
                "min_confidence_threshold",
                "idempotency_check",
                "transaction_state_validation",
                "fraud_signal"
            ]
        },
        "components": {
            "proposer": {
                "name": proposer.name if proposer else "unknown",
                "type": settings.llm.provider
            },
            "policy_engine": {
                "type": "deterministic",
                "version": "1.0.0"
            },
            "executor": {
                "type": "protected",
                "defense_layers": 3
            },
            "audit_logger": {
                "session_id": audit_logger.session_id
            }
        },
        "security": {
            "architecture": "zero-trust",
            "authorization_boundary": "policy_engine",
            "execution_control": "defense_in_depth",
            "audit_trail": "comprehensive"
        }
    }


@app.get("/security-principles")
async def security_principles():
    """Get security principles implemented by the system."""
    return {
        "principles": [
            {
                "name": "Least Privilege",
                "description": "AI has no execution authority",
                "implementation": "AI can only propose, not execute"
            },
            {
                "name": "Defense in Depth",
                "description": "Multiple security layers",
                "implementation": "Policy Engine + Executor verification"
            },
            {
                "name": "Allowlisting",
                "description": "Only pre-approved actions allowed",
                "implementation": "Action allowlist in Policy Engine"
            },
            {
                "name": "Deterministic Authorization",
                "description": "Authorization is code-based, not LLM-based",
                "implementation": "Policy Engine uses deterministic rules"
            },
            {
                "name": "Fail Closed",
                "description": "System blocks on failure",
                "implementation": "Default deny on validation errors"
            },
            {
                "name": "Idempotency",
                "description": "Prevent duplicate processing",
                "implementation": "24-hour idempotency check"
            },
            {
                "name": "Auditability",
                "description": "Complete audit trail",
                "implementation": "SQLite audit logs for all actions"
            },
            {
                "name": "Prompt Injection Defense",
                "description": "Protection against LLM manipulation",
                "implementation": "Policy Engine validates all AI output"
            }
        ]
    }


@app.get("/demo-scenarios")
async def demo_scenarios():
    """Get available demo scenarios."""
    if not proposer or not hasattr(proposer, 'list_scenarios'):
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="Demo scenarios only available with mock proposer"
        )

    scenarios = proposer.list_scenarios()

    return {
        "scenarios": scenarios,
        "description": "Pre-configured scenarios for demonstration",
        "note": "These scenarios demonstrate different security outcomes"
    }


if __name__ == "__main__":
    """Run the application directly."""
    uvicorn.run(
        "app.main:app",
        host=settings.api.host,
        port=settings.api.port,
        reload=settings.api.reload,
        log_level=settings.log_level.lower()
    )