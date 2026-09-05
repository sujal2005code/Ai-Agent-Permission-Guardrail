"""
Data models for the Policy Engine.

This module defines Pydantic models for all data structures used in the
AI Agent Permission Guardrail system.
"""

from datetime import datetime
from enum import Enum
from typing import Optional, Dict, Any, List
from uuid import uuid4, UUID
from pydantic import BaseModel, Field, validator, field_validator


class TransactionStatus(str, Enum):
    """Status of a payment transaction."""

    PENDING = "pending"
    PROCESSING = "processing"
    SUCCESSFUL = "successful"
    FAILED = "failed"
    TIMEOUT = "timeout"
    TEMPORARY_FAILURE = "temporary_failure"
    REFUNDED = "refunded"
    CANCELLED = "cancelled"


class PaymentEvent(BaseModel):
    """Represents a payment transaction event."""

    transaction_id: str = Field(
        ...,
        min_length=1,
        max_length=100,
        description="Unique identifier for the transaction"
    )
    amount: float = Field(
        ...,
        ge=0.01,
        description="Transaction amount in base currency"
    )
    currency: str = Field(
        default="INR",
        min_length=3,
        max_length=3,
        description="Currency code (ISO 4217)"
    )
    status: TransactionStatus = Field(
        default=TransactionStatus.FAILED,
        description="Current transaction status"
    )
    failure_reason: Optional[str] = Field(
        default=None,
        max_length=500,
        description="Reason for transaction failure"
    )
    customer_history: Dict[str, Any] = Field(
        default_factory=dict,
        description="Customer transaction history metadata"
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Additional transaction metadata"
    )
    customer_note: Optional[str] = Field(
        default=None,
        max_length=1000,
        description="Customer-provided note (untrusted input)"
    )
    possible_fraud: bool = Field(
        default=False,
        description="Indicates potential fraud signals"
    )

    @validator('amount')
    @classmethod
    def validate_amount_precision(cls, v):
        """Validate amount precision."""
        if v <= 0:
            raise ValueError("Amount must be positive")
        # Round to 2 decimal places for currency
        return round(v, 2)

    @validator('currency')
    @classmethod
    def validate_currency(cls, v):
        """Validate currency code."""
        return v.upper()

    class Config:
        json_schema_extra = {
            "example": {
                "transaction_id": "TXN-1001",
                "amount": 850.00,
                "currency": "INR",
                "status": "failed",
                "failure_reason": "network_timeout",
                "customer_history": {"previous_failures": 0},
                "metadata": {"payment_method": "credit_card"},
                "customer_note": "Please retry this payment",
                "possible_fraud": False
            }
        }


class AIProposal(BaseModel):
    """Represents an AI-generated proposal for action."""

    action: str = Field(
        ...,
        min_length=1,
        max_length=50,
        description="Proposed action to take"
    )
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="AI confidence in the proposal (0.0 to 1.0)"
    )
    reasoning: str = Field(
        ...,
        min_length=10,
        max_length=1000,
        description="AI reasoning for the proposal"
    )

    @field_validator('confidence')
    @classmethod
    def validate_confidence(cls, v):
        """Validate confidence is within reasonable bounds."""
        if v < 0 or v > 1:
            raise ValueError("Confidence must be between 0 and 1")
        return round(v, 2)

    @field_validator('reasoning')
    @classmethod
    def validate_reasoning(cls, v):
        """Sanitize reasoning text."""
        # Remove any null bytes or control characters
        v = v.replace('\x00', '').strip()
        if not v or len(v) < 10:
            raise ValueError("Reasoning must be at least 10 characters")
        return v

    class Config:
        json_schema_extra = {
            "example": {
                "action": "retry_payment",
                "confidence": 0.92,
                "reasoning": "Temporary network timeout with healthy payment history suggests retrying."
            }
        }


class PolicyDecision(str, Enum):
    """Possible policy decisions."""

    APPROVED = "approved"
    REJECTED = "rejected"
    ESCALATED = "escalated"


class RiskLevel(str, Enum):
    """Risk levels based on score."""

    LOW = "low"  # 0-29
    MEDIUM = "medium"  # 30-59
    HIGH = "high"  # 60-79
    CRITICAL = "critical"  # 80-100


class PolicyRule(str, Enum):
    """Policy rules that can be triggered."""

    # Schema validation
    SCHEMA_VALIDATION = "schema_validation"

    # Action validation
    ALLOWED_ACTIONS_ONLY = "allowed_actions_only"
    TRANSACTION_STATE_VALIDATION = "transaction_state_validation"

    # Security rules
    IDEMPOTENCY_CHECK = "idempotency_check"
    MAX_AUTO_APPROVE_AMOUNT = "max_auto_approve_amount"
    MIN_CONFIDENCE_THRESHOLD = "min_confidence_threshold"
    FRAUD_SIGNAL = "fraud_signal"

    # Approval
    ALL_CHECKS_PASSED = "all_checks_passed"


class PolicyDecisionModel(BaseModel):
    """Represents a policy decision."""

    decision: PolicyDecision = Field(
        ...,
        description="Policy decision (approved, rejected, escalated)"
    )
    rule_triggered: Optional[PolicyRule] = Field(
        default=None,
        description="Specific rule that triggered the decision"
    )
    reason: str = Field(
        ...,
        description="Human-readable reason for the decision"
    )
    risk_score: int = Field(
        default=0,
        ge=0,
        le=100,
        description="Risk score (0-100)"
    )
    risk_level: RiskLevel = Field(
        default=RiskLevel.LOW,
        description="Risk level based on score"
    )

    @field_validator('risk_score')
    @classmethod
    def validate_risk_score(cls, v, info):
        """Validate risk score and determine risk level."""
        if v < 0 or v > 100:
            raise ValueError("Risk score must be between 0 and 100")

        # Determine risk level based on score
        if v < 30:
            risk_level = RiskLevel.LOW
        elif v < 60:
            risk_level = RiskLevel.MEDIUM
        elif v < 80:
            risk_level = RiskLevel.HIGH
        else:
            risk_level = RiskLevel.CRITICAL

        # Update risk level in data if available
        if info.data and 'risk_level' in info.data:
            info.data['risk_level'] = risk_level

        return v

    @field_validator('risk_level')
    @classmethod
    def validate_risk_level(cls, v, info):
        """Ensure risk level matches risk score."""
        if not info.data:
            return v

        risk_score = info.data.get('risk_score', 0)
        expected_level = (
            RiskLevel.LOW if risk_score < 30 else
            RiskLevel.MEDIUM if risk_score < 60 else
            RiskLevel.HIGH if risk_score < 80 else
            RiskLevel.CRITICAL
        )

        if v != expected_level:
            return expected_level
        return v

    class Config:
        json_schema_extra = {
            "example": {
                "decision": "approved",
                "rule_triggered": None,
                "reason": "All policy checks passed",
                "risk_score": 15,
                "risk_level": "low"
            }
        }


class ExecutionResult(BaseModel):
    """Represents the result of an execution attempt."""

    executed: bool = Field(
        ...,
        description="Whether execution was attempted"
    )
    action: Optional[str] = Field(
        default=None,
        description="Action that was executed (if any)"
    )
    result: Optional[str] = Field(
        default=None,
        description="Result of execution"
    )
    timestamp: datetime = Field(
        default_factory=datetime.utcnow,
        description="Execution timestamp"
    )
    error: Optional[str] = Field(
        default=None,
        description="Error message if execution failed"
    )

    class Config:
        json_schema_extra = {
            "example": {
                "executed": True,
                "action": "retry_payment",
                "result": "Payment retry simulated successfully",
                "timestamp": "2024-01-01T12:00:00Z",
                "error": None
            }
        }


class AuditRecord(BaseModel):
    """Represents a complete audit record."""

    id: UUID = Field(default_factory=uuid4)
    transaction_id: str = Field(...)
    event: PaymentEvent = Field(...)
    proposal: AIProposal = Field(...)
    decision: PolicyDecisionModel = Field(...)
    execution_result: Optional[ExecutionResult] = Field(default=None)
    timestamp: datetime = Field(default_factory=datetime.utcnow)

    class Config:
        json_schema_extra = {
            "example": {
                "id": "123e4567-e89b-12d3-a456-426614174000",
                "transaction_id": "TXN-1001",
                "event": {
                    "transaction_id": "TXN-1001",
                    "amount": 850.00,
                    "currency": "INR",
                    "status": "failed",
                    "failure_reason": "network_timeout",
                    "customer_history": {"previous_failures": 0},
                    "metadata": {},
                    "customer_note": None,
                    "possible_fraud": False
                },
                "proposal": {
                    "action": "retry_payment",
                    "confidence": 0.92,
                    "reasoning": "Temporary network timeout suggests retrying."
                },
                "decision": {
                    "decision": "approved",
                    "rule_triggered": None,
                    "reason": "All policy checks passed",
                    "risk_score": 15,
                    "risk_level": "low"
                },
                "execution_result": {
                    "executed": True,
                    "action": "retry_payment",
                    "result": "Payment retry simulated successfully",
                    "timestamp": "2024-01-01T12:00:00Z",
                    "error": None
                },
                "timestamp": "2024-01-01T12:00:00Z"
            }
        }