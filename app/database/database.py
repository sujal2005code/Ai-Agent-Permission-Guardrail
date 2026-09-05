"""
Database connection and operations.

This module handles database initialization, connections, and basic CRUD operations
for the AI Agent Permission Guardrail system.
"""

import os
from pathlib import Path
from typing import Optional, Dict, Any, List
from contextlib import contextmanager
import logging

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.exc import SQLAlchemyError, IntegrityError

from app.database.models import Base, Transaction, Proposal, Decision, ExecutionResultDB, Review, PolicyVersion, AuditLog
from app.config import settings

logger = logging.getLogger(__name__)


class Database:
    """Database manager for the application."""

    def __init__(self):
        """Initialize database connection."""
        self.db_path = settings.database.path
        self._engine = None
        self._session_factory = None

    @property
    def engine(self):
        """Get or create database engine."""
        if self._engine is None:
            self._setup_database()
        return self._engine

    @property
    def session_factory(self):
        """Get or create session factory."""
        if self._session_factory is None:
            self._session_factory = sessionmaker(
                bind=self.engine,
                expire_on_commit=False,
                autocommit=False,
                autoflush=False
            )
        return self._session_factory

    def _setup_database(self):
        """Set up database connection and create tables if needed."""
        try:
            # Ensure data directory exists
            db_path = Path(self.db_path)
            db_path.parent.mkdir(parents=True, exist_ok=True)

            # Create SQLite engine
            db_url = f"sqlite:///{self.db_path}"
            logger.info(f"Connecting to database: {db_path.absolute()}")

            self._engine = create_engine(
                db_url,
                echo=False,  # Set to True for SQL debugging
                connect_args={"check_same_thread": False},
                pool_pre_ping=True
            )

            # Create tables
            self._create_tables()

            # Initialize default data
            self._initialize_default_data()

        except Exception as e:
            logger.error(f"Failed to setup database: {e}")
            raise

    def _create_tables(self):
        """Create all database tables."""
        try:
            Base.metadata.create_all(self._engine)
            logger.info("Database tables created successfully")
        except SQLAlchemyError as e:
            logger.error(f"Failed to create tables: {e}")
            raise

    def _initialize_default_data(self):
        """Initialize default data (policy versions, etc.)."""
        try:
            with self.get_session() as session:
                # Check if we already have a policy version
                existing_policy = session.query(PolicyVersion).first()
                if not existing_policy:
                    # Create initial policy version
                    initial_policy = PolicyVersion(
                        version="1.0.0",
                        policy_rules={
                            "allowed_actions": ["retry_payment", "flag_for_review"],
                            "max_auto_approve_amount": settings.policy.max_auto_approve_amount,
                            "min_confidence_threshold": settings.policy.min_confidence_threshold,
                            "evaluation_order": [
                                "schema_validation",
                                "allowed_actions_only",
                                "transaction_state_validation",
                                "idempotency_check",
                                "max_auto_approve_amount",
                                "min_confidence_threshold",
                                "fraud_signal",
                                "all_checks_passed"
                            ]
                        },
                        description="Initial policy version",
                        created_by="system"
                    )
                    session.add(initial_policy)
                    session.commit()
                    logger.info("Initial policy version created")

        except SQLAlchemyError as e:
            logger.warning(f"Failed to initialize default data: {e}")
            # Don't raise - this is non-critical

    @contextmanager
    def get_session(self):
        """Get a database session with automatic cleanup."""
        session: Optional[Session] = None
        try:
            session = self.session_factory()
            yield session
        except SQLAlchemyError as e:
            logger.error(f"Database session error: {e}")
            if session:
                session.rollback()
            raise
        finally:
            if session:
                session.close()

    def health_check(self) -> Dict[str, Any]:
        """Check database health."""
        try:
            with self.get_session() as session:
                # Execute a simple query
                result = session.execute(text("SELECT 1")).scalar()
                return {
                    "status": "healthy",
                    "database": self.db_path,
                    "tables": list(Base.metadata.tables.keys())
                }
        except Exception as e:
            logger.error(f"Database health check failed: {e}")
            return {
                "status": "unhealthy",
                "error": str(e),
                "database": self.db_path
            }

    def record_audit_log(self, event_type: str, action: str, details: Dict[str, Any],
                        entity_id: Optional[str] = None, entity_type: Optional[str] = None,
                        user_id: Optional[str] = None, ip_address: Optional[str] = None):
        """Record an audit log entry."""
        try:
            with self.get_session() as session:
                audit_log = AuditLog(
                    event_type=event_type,
                    entity_id=entity_id,
                    entity_type=entity_type,
                    action=action,
                    details=details,
                    user_id=user_id,
                    ip_address=ip_address
                )
                session.add(audit_log)
                session.commit()
                logger.debug(f"Audit log recorded: {event_type} - {action}")
        except SQLAlchemyError as e:
            logger.error(f"Failed to record audit log: {e}")

    def get_recent_audit_logs(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent audit logs."""
        try:
            with self.get_session() as session:
                logs = session.query(AuditLog).order_by(AuditLog.timestamp.desc()).limit(limit).all()
                return [
                    {
                        "id": str(log.id),
                        "event_type": log.event_type,
                        "entity_id": log.entity_id,
                        "entity_type": log.entity_type,
                        "action": log.action,
                        "details": log.details,
                        "user_id": log.user_id,
                        "ip_address": log.ip_address,
                        "timestamp": log.timestamp.isoformat() if log.timestamp else None
                    }
                    for log in logs
                ]
        except SQLAlchemyError as e:
            logger.error(f"Failed to get audit logs: {e}")
            return []

    def cleanup_old_records(self, days: int = 30):
        """Clean up records older than specified days."""
        try:
            with self.get_session() as session:
                # Get threshold date
                from datetime import datetime, timedelta
                threshold = datetime.utcnow() - timedelta(days=days)

                # Cleanup old audit logs (keep last N days)
                deleted_count = session.query(AuditLog).filter(AuditLog.timestamp < threshold).delete()
                session.commit()

                logger.info(f"Cleaned up {deleted_count} audit logs older than {days} days")

                return deleted_count
        except SQLAlchemyError as e:
            logger.error(f"Failed to cleanup old records: {e}")
            return 0

    def get_statistics(self) -> Dict[str, Any]:
        """Get database statistics."""
        try:
            with self.get_session() as session:
                stats = {
                    "tables": {},
                    "total_records": 0
                }

                # Count records in each table
                tables = [Proposal, Decision, ExecutionResultDB, Transaction, Review, PolicyVersion, AuditLog]
                for table in tables:
                    count = session.query(table).count()
                    stats["tables"][table.__tablename__] = count
                    stats["total_records"] += count

                # Get database size
                db_path = Path(self.db_path)
                if db_path.exists():
                    stats["database_size_bytes"] = db_path.stat().st_size
                    stats["database_size_mb"] = round(stats["database_size_bytes"] / (1024 * 1024), 2)

                return stats
        except SQLAlchemyError as e:
            logger.error(f"Failed to get statistics: {e}")
            return {"error": str(e)}


# Global database instance
db = Database()