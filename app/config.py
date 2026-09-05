"""
Configuration management for the AI Agent Permission Guardrail system.

This module handles environment variables, default settings, and configuration
validation.
"""

import os
from typing import Literal, Optional
from pydantic import BaseModel, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
import logging


class LLMConfig(BaseModel):
    """Configuration for LLM providers."""

    provider: Literal["mock", "anthropic", "openai"] = Field(
        default="mock",
        description="LLM provider to use"
    )
    anthropic_api_key: Optional[str] = Field(
        default=None,
        description="Anthropic API key (required if provider is 'anthropic')"
    )
    openai_api_key: Optional[str] = Field(
        default=None,
        description="OpenAI API key (required if provider is 'openai')"
    )

    @field_validator('anthropic_api_key', 'openai_api_key')
    @classmethod
    def validate_api_keys(cls, v, info):
        """Validate API keys when provider is selected."""
        field_name = info.field_name
        provider = info.data.get('provider') if hasattr(info, 'data') else None

        if field_name == 'anthropic_api_key' and provider == 'anthropic' and not v:
            raise ValueError("ANTHROPIC_API_KEY is required when LLM_PROVIDER=anthropic")
        if field_name == 'openai_api_key' and provider == 'openai' and not v:
            raise ValueError("OPENAI_API_KEY is required when LLM_PROVIDER=openai")
        return v


class DatabaseConfig(BaseModel):
    """Configuration for database."""

    path: str = Field(
        default="data/guardrail.db",
        description="Path to SQLite database file"
    )


class PolicyConfig(BaseModel):
    """Configuration for policy engine."""

    max_auto_approve_amount: int = Field(
        default=2000,
        ge=0,
        description="Maximum amount (in base currency) that can be auto-approved"
    )
    min_confidence_threshold: float = Field(
        default=0.75,
        ge=0.0,
        le=1.0,
        description="Minimum AI confidence required for approval"
    )
    allowed_actions: list[str] = Field(
        default_factory=lambda: ["retry_payment", "flag_for_review"],
        description="List of actions that can be approved"
    )


class APIConfig(BaseModel):
    """Configuration for API server."""

    host: str = Field(default="0.0.0.0", description="API host address")
    port: int = Field(default=8000, ge=1, le=65535, description="API port")
    reload: bool = Field(default=True, description="Enable auto-reload in development")


class Settings(BaseSettings):
    """Main application settings."""

    # LLM configuration
    llm: LLMConfig = Field(default_factory=LLMConfig)

    # Database configuration
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)

    # Policy configuration
    policy: PolicyConfig = Field(default_factory=PolicyConfig)

    # API configuration
    api: APIConfig = Field(default_factory=APIConfig)

    # Logging
    log_level: str = Field(default="INFO")

    model_config = SettingsConfigDict(
        env_file=".env",
        env_nested_delimiter="__",
        case_sensitive=False,
        extra="ignore"
    )

    @classmethod
    def load(cls) -> "Settings":
        """Load settings from environment variables."""
        # Load environment variables from .env file if it exists
        from dotenv import load_dotenv
        load_dotenv()

        # Map environment variables to nested structure
        env_vars = {
            "llm__provider": os.getenv("LLM_PROVIDER", "mock"),
            "llm__anthropic_api_key": os.getenv("ANTHROPIC_API_KEY"),
            "llm__openai_api_key": os.getenv("OPENAI_API_KEY"),
            "database__path": os.getenv("DATABASE_PATH", "data/guardrail.db"),
            "policy__max_auto_approve_amount": int(os.getenv("MAX_AUTO_APPROVE_AMOUNT", "2000")),
            "policy__min_confidence_threshold": float(os.getenv("MIN_CONFIDENCE_THRESHOLD", "0.75")),
            "api__host": os.getenv("API_HOST", "0.0.0.0"),
            "api__port": int(os.getenv("API_PORT", "8000")),
            "api__reload": os.getenv("API_RELOAD", "true").lower() == "true",
            "log_level": os.getenv("LOG_LEVEL", "INFO"),
        }

        return cls(**env_vars)


def setup_logging(log_level: str = "INFO"):
    """Configure application logging."""
    level = getattr(logging, log_level.upper(), logging.INFO)

    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    # Set third-party loggers to WARNING level
    for logger_name in ["urllib3", "httpx", "asyncio"]:
        logging.getLogger(logger_name).setLevel(logging.WARNING)

    return logging.getLogger(__name__)


# Global settings instance
settings = Settings.load()
logger = setup_logging(settings.log_level)