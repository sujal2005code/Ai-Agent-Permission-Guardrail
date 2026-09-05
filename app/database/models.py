"""
SQLAlchemy models for database persistence.

This module defines the database schema for the AI Agent Permission Guardrail system.
"""

from datetime import datetime
from enum import Enum as PyEnum
from typing import Optional, Dict, Any
from uuid import uuid4, UUID
import json

from sqlalchemy import (
    Column, Integer, String, Float, Boolean, DateTime, Text,
    ForeignKey, JSON, Enum, UniqueConstraint, Index
)
from sqlalchemy.orm import declarative_base, relationship
from sqlalchemy.dialects.sqlite import JSON as SQLiteJSON
from sqlalchemy.sql import func

Base = declarative_base()


class TransactionStatusDB(PyEnum):
    """Database representation of transaction status."""

    PENDING = "pending"
    PROCESSING = "processing"
    SUCCESSFUL = "successful"
    FAILED = "failed"
    TIMEOUT = "timeout"
    TEMPORARY_FAILURE = "temporary_failure"
    REFUNDED = "refunded"
    CANCELLED = "cancelled"


class PolicyDecisionDB(PyEnum):
    """Database representation of policy decisions."""

    APPROVED = "approved"
    REJECTED = "rejected"
    ESCALATED = "escalated"


class Proposal(Base):
    """Stores AI-generated proposals."""

    __tablename__ = "proposals"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    transaction_id = Column(String(100), nullable=False, index=True)
    raw_input = Column(Text, nullable=False)  # Original event as JSON
    ai_action = Column(String(50), nullable=False)
    ai_confidence = Column(Float, nullable=False)
    ai_reasoning = Column(Text, nullable=False)
    timestamp = Column(DateTime(timezone=True), default=func.now(), nullable=False)

    # Relationships
    decisions = relationship("Decision", back_populates="proposal", cascade="all, delete-orphan")
    reviews = relationship("Review", back_populates="proposal", cascade="all, delete-orphan")

    __table_args__ = (
        Index("idx_proposals_transaction_timestamp", "transaction_id", "timestamp"),
        Index("idx_proposals_timestamp", "timestamp"),
    )

    def __repr__(self):
        return f"<Proposal(id={self.id}, transaction_id={self.transaction_id}, action={self.ai_action})>"


class Decision(Base):
    """Stores policy decisions."""

    __tablename__ = "decisions"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    proposal_id = Column(String(36), ForeignKey("proposals.id", ondelete="CASCADE"), nullable=False)
    decision = Column(Enum(PolicyDecisionDB), nullable=False)
    rule_triggered = Column(String(50), nullable=True)
    executed = Column(Boolean, default=False, nullable=False)
    risk_score = Column(Integer, default=0, nullable=False)
    risk_level = Column(String(20), nullable=False)
    reason = Column(Text, nullable=False)
    timestamp = Column(DateTime(timezone=True), default=func.now(), nullable=False)

    # Relationships
    proposal = relationship("Proposal", back_populates="decisions")
    execution_result = relationship("ExecutionResultDB", uselist=False, back_populates="decision", cascade="all, delete-orphan")
    review = relationship("Review", uselist=False, back_populates="decision", cascade="all, delete-orphan")

    __table_args__ = (
        Index("idx_decisions_proposal_id", "proposal_id"),
        Index("idx_decisions_decision", "decision"),
        Index("idx_decisions_timestamp", "timestamp"),
        Index("idx_decisions_risk_level", "risk_level"),
    )

    def __repr__(self):
        return f"<Decision(id={self.id}, proposal_id={self.proposal_id}, decision={self.decision})>"


class ExecutionResultDB(Base):
    """Stores execution results."""

    __tablename__ = "execution_results"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    decision_id = Column(String(36), ForeignKey("decisions.id", ondelete="CASCADE"), nullable=False)
    executed = Column(Boolean, nullable=False)
    action = Column(String(50), nullable=True)
    result = Column(Text, nullable=True)
    error = Column(Text, nullable=True)
    timestamp = Column(DateTime(timezone=True), default=func.now(), nullable=False)

    # Relationships
    decision = relationship("Decision", back_populates="execution_result", overlaps="execution_result")

    __table_args__ = (
        Index("idx_execution_results_decision_id", "decision_id"),
        Index("idx_execution_results_executed", "executed"),
        Index("idx_execution_results_timestamp", "timestamp"),
    )

    def __repr__(self):
        return f"<ExecutionResultDB(id={self.id}, decision_id={self.decision_id}, executed={self.executed})>"


class Transaction(Base):
    """Stores transaction information."""

    __tablename__ = "transactions"

    transaction_id = Column(String(100), primary_key=True)
    amount = Column(Float, nullable=False)
    currency = Column(String(3), nullable=False, default="INR")
    status = Column(Enum(TransactionStatusDB), nullable=False)
    failure_reason = Column(String(200), nullable=True)
    customer_history = Column(SQLiteJSON, default=dict)  # Using SQLite-specific JSON
    metadata_json = Column(SQLiteJSON, default=dict)  # Using SQLite-specific JSON (renamed to avoid reserved name)
    possible_fraud = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime(timezone=True), default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), default=func.now(), onupdate=func.now(), nullable=False)

    # Relationships
    reviews = relationship("Review", back_populates="transaction", cascade="all, delete-orphan")

    __table_args__ = (
        Index("idx_transactions_status", "status"),
        Index("idx_transactions_created_at", "created_at"),
        Index("idx_transactions_possible_fraud", "possible_fraud"),
    )

    def __repr__(self):
        return f"<Transaction(transaction_id={self.transaction_id}, amount={self.amount}, status={self.status})>"


class Review(Base):
    """Stores human review cases."""

    __tablename__ = "reviews"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    proposal_id = Column(String(36), ForeignKey("proposals.id", ondelete="CASCADE"), nullable=False)
    transaction_id = Column(String(100), ForeignKey("transactions.transaction_id", ondelete="CASCADE"), nullable=False)
    decision_id = Column(String(36), ForeignKey("decisions.id", ondelete="CASCADE"), nullable=False)
    reason = Column(Text, nullable=False)
    status = Column(String(20), nullable=False, default="pending")  # pending, approved, rejected
    created_at = Column(DateTime(timezone=True), default=func.now(), nullable=False)
    resolved_at = Column(DateTime(timezone=True), nullable=True)
    resolver_notes = Column(Text, nullable=True)

    # Relationships
    proposal = relationship("Proposal", back_populates="reviews")
    transaction = relationship("Transaction", back_populates="reviews")
    decision = relationship("Decision", back_populates="review")

    __table_args__ = (
        Index("idx_reviews_proposal_id", "proposal_id"),
        Index("idx_reviews_transaction_id", "transaction_id"),
        Index("idx_reviews_status", "status"),
        Index("idx_reviews_created_at", "created_at"),
        UniqueConstraint("proposal_id", "decision_id", name="uq_reviews_proposal_decision"),
    )

    def __repr__(self):
        return f"<Review(id={self.id}, proposal_id={self.proposal_id}, status={self.status})>"


class PolicyVersion(Base):
    """Stores policy versions for audit purposes."""

    __tablename__ = "policy_versions"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    version = Column(String(20), nullable=False)
    policy_rules = Column(SQLiteJSON, nullable=False)  # Full policy configuration
    description = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=func.now(), nullable=False)
    created_by = Column(String(100), nullable=True)

    __table_args__ = (
        Index("idx_policy_versions_version", "version"),
        Index("idx_policy_versions_created_at", "created_at"),
        UniqueConstraint("version", name="uq_policy_versions_version"),
    )

    def __repr__(self):
        return f"<PolicyVersion(id={self.id}, version={self.version})>"


class AuditLog(Base):
    """Comprehensive audit log for all system activities."""

    __tablename__ = "audit_logs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    event_type = Column(String(50), nullable=False)  # proposal, decision, execution, review, etc.
    entity_id = Column(String(36), nullable=True)  # ID of the related entity
    entity_type = Column(String(50), nullable=True)  # Type of entity
    action = Column(String(100), nullable=False)  # What happened
    details = Column(SQLiteJSON, default=dict)  # Detailed information
    user_id = Column(String(100), nullable=True)  # Who performed the action
    ip_address = Column(String(45), nullable=True)  # Source IP
    timestamp = Column(DateTime(timezone=True), default=func.now(), nullable=False)

    __table_args__ = (
        Index("idx_audit_logs_event_type", "event_type"),
        Index("idx_audit_logs_entity_id", "entity_id"),
        Index("idx_audit_logs_timestamp", "timestamp"),
        Index("idx_audit_logs_user_id", "user_id"),
    )

    def __repr__(self):
        return f"<AuditLog(id={self.id}, event_type={self.event_type}, action={self.action})>"