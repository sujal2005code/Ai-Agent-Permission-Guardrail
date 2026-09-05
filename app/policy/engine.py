"""
Deterministic Policy Engine.

This is the core authorization component that evaluates AI proposals against
security rules. The engine is completely deterministic and does not use any
LLM or probabilistic logic.

Key Principle: The AI proposes, the Policy Engine decides.
"""

import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, Tuple
from dataclasses import dataclass

from app.policy.models import (
    PaymentEvent, AIProposal, PolicyDecisionModel, PolicyDecision,
    PolicyRule, RiskLevel, TransactionStatus
)
from app.config import settings
from app.database.database import db

logger = logging.getLogger(__name__)


@dataclass
class RuleResult:
    """Result of evaluating a single policy rule."""

    passed: bool
    rule: Optional[PolicyRule] = None
    reason: Optional[str] = None
    risk_contribution: int = 0


class PolicyEngine:
    """Deterministic policy engine for evaluating AI proposals."""

    def __init__(self):
        """Initialize policy engine with configuration."""
        self.allowed_actions = set(settings.policy.allowed_actions)
        self.max_auto_approve_amount = settings.policy.max_auto_approve_amount
        self.min_confidence_threshold = settings.policy.min_confidence_threshold

        # Define evaluation order (most important security rules first)
        self.evaluation_order = [
            self._validate_schema,
            self._check_action_allowlist,
            self._validate_transaction_state,
            self._check_idempotency,
            self._check_amount_limit,
            self._check_confidence_threshold,
            self._check_fraud_signal,
        ]

        logger.info(f"Policy Engine initialized with allowed actions: {self.allowed_actions}")
        logger.info(f"Max auto-approve amount: {self.max_auto_approve_amount}")
        logger.info(f"Min confidence threshold: {self.min_confidence_threshold}")

    def evaluate(
        self,
        event: PaymentEvent,
        proposal: AIProposal,
        session_id: Optional[str] = None
    ) -> PolicyDecisionModel:
        """
        Evaluate an AI proposal against all policy rules.

        Args:
            event: The payment event
            proposal: The AI-generated proposal
            session_id: Optional session ID for logging

        Returns:
            Policy decision with risk assessment
        """
        logger.info(f"Evaluating proposal for transaction {event.transaction_id}")
        logger.debug(f"Event: {event.dict()}")
        logger.debug(f"Proposal: {proposal.dict()}")

        # Track rule results
        rule_results: Dict[str, RuleResult] = {}
        total_risk_score = 0
        decision = PolicyDecision.APPROVED
        triggered_rule = None
        decision_reason = "All policy checks passed"

        # Execute rules in deterministic order
        for rule_func in self.evaluation_order:
            rule_name = rule_func.__name__.replace("_check_", "").replace("_validate_", "")
            result = rule_func(event, proposal)

            rule_results[rule_name] = result

            if not result.passed:
                # First failure determines the decision
                if decision == PolicyDecision.APPROVED:
                    decision = self._determine_decision_from_rule(result.rule)
                    triggered_rule = result.rule
                    decision_reason = result.reason or f"Failed {rule_name} check"

            # Accumulate risk score
            total_risk_score += result.risk_contribution

        # Calculate final risk score
        risk_score = self._calculate_risk_score(event, proposal, total_risk_score)
        risk_level = self._determine_risk_level(risk_score)

        # Create final decision
        final_decision = PolicyDecisionModel(
            decision=decision,
            rule_triggered=triggered_rule,
            reason=decision_reason,
            risk_score=risk_score,
            risk_level=risk_level
        )

        # Log the decision
        logger.info(
            f"Policy decision for {event.transaction_id}: "
            f"{decision} (risk: {risk_level}, score: {risk_score})"
        )
        if triggered_rule:
            logger.info(f"Triggered rule: {triggered_rule} - {decision_reason}")

        # Record audit log
        self._record_audit_log(event, proposal, final_decision, session_id)

        return final_decision

    def _validate_schema(self, event: PaymentEvent, proposal: AIProposal) -> RuleResult:
        """Validate input schema and basic constraints."""
        try:
            # Amount must be positive
            if event.amount <= 0:
                return RuleResult(
                    passed=False,
                    rule=PolicyRule.SCHEMA_VALIDATION,
                    reason="Transaction amount must be positive",
                    risk_contribution=20
                )

            # Confidence must be valid
            if not (0 <= proposal.confidence <= 1):
                return RuleResult(
                    passed=False,
                    rule=PolicyRule.SCHEMA_VALIDATION,
                    reason=f"Invalid confidence value: {proposal.confidence}",
                    risk_contribution=30
                )

            # Action must not be empty
            if not proposal.action or not proposal.action.strip():
                return RuleResult(
                    passed=False,
                    rule=PolicyRule.SCHEMA_VALIDATION,
                    reason="Action cannot be empty",
                    risk_contribution=20
                )

            return RuleResult(passed=True, risk_contribution=0)

        except Exception as e:
            logger.error(f"Schema validation error: {e}")
            return RuleResult(
                passed=False,
                rule=PolicyRule.SCHEMA_VALIDATION,
                reason=f"Schema validation failed: {str(e)}",
                risk_contribution=50
            )

    def _check_action_allowlist(self, event: PaymentEvent, proposal: AIProposal) -> RuleResult:
        """Check if the proposed action is in the allowlist."""
        if proposal.action not in self.allowed_actions:
            logger.warning(
                f"Unauthorized action proposed: {proposal.action} "
                f"(allowed: {self.allowed_actions})"
            )
            return RuleResult(
                passed=False,
                rule=PolicyRule.ALLOWED_ACTIONS_ONLY,
                reason=f"Action '{proposal.action}' is not authorized",
                risk_contribution=40
            )

        return RuleResult(passed=True, risk_contribution=0)

    def _validate_transaction_state(self, event: PaymentEvent, proposal: AIProposal) -> RuleResult:
        """Validate that the proposed action matches transaction state."""
        # Map actions to allowed transaction states
        action_state_rules = {
            "retry_payment": {
                "allowed_states": [
                    TransactionStatus.FAILED,
                    TransactionStatus.TIMEOUT,
                    TransactionStatus.TEMPORARY_FAILURE
                ],
                "denied_states": [
                    TransactionStatus.SUCCESSFUL,
                    TransactionStatus.REFUNDED,
                    TransactionStatus.CANCELLED
                ]
            },
            "flag_for_review": {
                "allowed_states": list(TransactionStatus),  # All states allowed
                "denied_states": []
            }
        }

        rule = action_state_rules.get(proposal.action)
        if not rule:
            # Action not in our mapping - default to allowing but with risk
            return RuleResult(passed=True, risk_contribution=10)

        # Check if current state is denied for this action
        if event.status in rule["denied_states"]:
            return RuleResult(
                passed=False,
                rule=PolicyRule.TRANSACTION_STATE_VALIDATION,
                reason=(
                    f"Cannot perform '{proposal.action}' on transaction "
                    f"with status '{event.status.value}'"
                ),
                risk_contribution=25
            )

        # Check if action is appropriate for current state
        if rule["allowed_states"] and event.status not in rule["allowed_states"]:
            return RuleResult(
                passed=False,
                rule=PolicyRule.TRANSACTION_STATE_VALIDATION,
                reason=(
                    f"Action '{proposal.action}' is not appropriate for "
                    f"transaction status '{event.status.value}'"
                ),
                risk_contribution=20
            )

        return RuleResult(passed=True, risk_contribution=0)

    def _check_idempotency(self, event: PaymentEvent, proposal: AIProposal) -> RuleResult:
        """
        Check if this transaction has been processed before.

        REVISED: A transaction is considered "processed" if ANY execution attempt exists
        (whether successful or failed). This prevents duplicate processing entirely.

        A transaction is considered "processed" if:
        1. An execution result exists (any attempt was made to execute)
        2. executed=True (execution was attempted)
        3. Within the 24-hour idempotency window
        4. DOES NOT require error=None - ANY execution attempt blocks subsequent requests

        This matches the user's expectation: "First request → APPROVE + EXECUTE.
        Any immediate repeated request with the same ID → REJECT/BLOCK"
        """
        try:
            with db.get_session() as session:
                from app.database.models import ExecutionResultDB, Decision, Proposal as ProposalDB
                from sqlalchemy import and_

                time_threshold = datetime.utcnow() - timedelta(hours=24)

                # Check for ANY execution attempt through the relationship chain:
                # ExecutionResultDB -> Decision -> Proposal -> transaction_id
                # REMOVED: ExecutionResultDB.error == None condition
                # We now block on ANY execution attempt (successful or failed)
                execution_attempts = session.query(ExecutionResultDB).join(
                    Decision, ExecutionResultDB.decision_id == Decision.id
                ).join(
                    ProposalDB, Decision.proposal_id == ProposalDB.id
                ).filter(
                    and_(
                        ProposalDB.transaction_id == event.transaction_id,
                        ExecutionResultDB.executed == True,  # ANY execution attempt
                        ExecutionResultDB.timestamp > time_threshold
                    )
                ).count()

                if execution_attempts > 0:
                    logger.warning(
                        f"Idempotency check triggered for {event.transaction_id}: "
                        f"Found {execution_attempts} execution attempt(s) in the last 24 hours"
                    )
                    return RuleResult(
                        passed=False,
                        rule=PolicyRule.IDEMPOTENCY_CHECK,
                        reason=(
                            f"Transaction {event.transaction_id} has already been "
                            f"processed within the last 24 hours (any execution attempt)"
                        ),
                        risk_contribution=15
                    )

                return RuleResult(passed=True, risk_contribution=0)

        except Exception as e:
            logger.error(f"Idempotency check failed: {e}")
            # On error, fail closed - assume duplicate to be safe
            return RuleResult(
                passed=False,
                rule=PolicyRule.IDEMPOTENCY_CHECK,
                reason=f"Idempotency check failed: {str(e)}",
                risk_contribution=30
            )

    def _check_amount_limit(self, event: PaymentEvent, proposal: AIProposal) -> RuleResult:
        """Check if amount exceeds auto-approval limit."""
        if event.amount > self.max_auto_approve_amount:
            logger.info(
                f"Amount {event.amount} exceeds auto-approval limit "
                f"{self.max_auto_approve_amount}"
            )
            return RuleResult(
                passed=False,
                rule=PolicyRule.MAX_AUTO_APPROVE_AMOUNT,
                reason=(
                    f"Amount ₹{event.amount:.2f} exceeds automatic approval "
                    f"limit of ₹{self.max_auto_approve_amount}"
                ),
                risk_contribution=self._calculate_amount_risk(event.amount)
            )

        return RuleResult(passed=True, risk_contribution=0)

    def _check_confidence_threshold(self, event: PaymentEvent, proposal: AIProposal) -> RuleResult:
        """Check if AI confidence meets minimum threshold."""
        if proposal.confidence < self.min_confidence_threshold:
            logger.warning(
                f"AI confidence {proposal.confidence} below threshold "
                f"{self.min_confidence_threshold}"
            )
            return RuleResult(
                passed=False,
                rule=PolicyRule.MIN_CONFIDENCE_THRESHOLD,
                reason=(
                    f"AI confidence {proposal.confidence:.2f} is below "
                    f"minimum threshold of {self.min_confidence_threshold}"
                ),
                risk_contribution=self._calculate_confidence_risk(proposal.confidence)
            )

        return RuleResult(passed=True, risk_contribution=0)

    def _check_fraud_signal(self, event: PaymentEvent, proposal: AIProposal) -> RuleResult:
        """Check for fraud signals."""
        if event.possible_fraud:
            logger.warning(f"Fraud signal detected for transaction {event.transaction_id}")
            return RuleResult(
                passed=False,
                rule=PolicyRule.FRAUD_SIGNAL,
                reason="Potential fraud signal detected",
                risk_contribution=60
            )

        # Additional fraud checks can be added here
        # Example: check customer history, velocity, etc.

        return RuleResult(passed=True, risk_contribution=0)

    def _determine_decision_from_rule(self, rule: PolicyRule) -> PolicyDecision:
        """Map rule failure to appropriate decision."""
        # Some rules should escalate, others should reject
        escalation_rules = {
            PolicyRule.MAX_AUTO_APPROVE_AMOUNT,
            PolicyRule.FRAUD_SIGNAL
        }

        if rule in escalation_rules:
            return PolicyDecision.ESCALATED
        else:
            return PolicyDecision.REJECTED

    def _calculate_risk_score(
        self,
        event: PaymentEvent,
        proposal: AIProposal,
        base_risk: int
    ) -> int:
        """Calculate comprehensive risk score."""
        risk_score = base_risk

        # Amount-based risk
        amount_risk = min(100, int((event.amount / self.max_auto_approve_amount) * 50))
        risk_score += amount_risk

        # Confidence-based risk (inverse)
        confidence_risk = int((1 - proposal.confidence) * 40)
        risk_score += confidence_risk

        # Transaction status risk
        if event.status in [TransactionStatus.FAILED, TransactionStatus.TIMEOUT]:
            risk_score += 10

        # Fraud signal risk (already accounted for in base_risk)

        # Cap at 100
        return min(100, risk_score)

    def _calculate_amount_risk(self, amount: float) -> int:
        """Calculate risk contribution based on amount."""
        if amount <= 0:
            return 0

        ratio = amount / self.max_auto_approve_amount
        if ratio <= 1:
            return 0
        elif ratio <= 2:
            return 20
        elif ratio <= 5:
            return 40
        else:
            return 60

    def _calculate_confidence_risk(self, confidence: float) -> int:
        """Calculate risk contribution based on confidence."""
        if confidence >= self.min_confidence_threshold:
            return 0

        shortfall = self.min_confidence_threshold - confidence
        return min(50, int(shortfall * 100))

    def _determine_risk_level(self, risk_score: int) -> RiskLevel:
        """Determine risk level based on score."""
        if risk_score < 30:
            return RiskLevel.LOW
        elif risk_score < 60:
            return RiskLevel.MEDIUM
        elif risk_score < 80:
            return RiskLevel.HIGH
        else:
            return RiskLevel.CRITICAL

    def _record_audit_log(
        self,
        event: PaymentEvent,
        proposal: AIProposal,
        decision: PolicyDecisionModel,
        session_id: Optional[str]
    ):
        """Record policy evaluation in audit log."""
        try:
            db.record_audit_log(
                event_type="policy_evaluation",
                action="evaluate_proposal",
                details={
                    "transaction_id": event.transaction_id,
                    "amount": event.amount,
                    "currency": event.currency,
                    "proposed_action": proposal.action,
                    "confidence": proposal.confidence,
                    "decision": decision.decision.value,
                    "rule_triggered": decision.rule_triggered.value if decision.rule_triggered else None,
                    "risk_score": decision.risk_score,
                    "risk_level": decision.risk_level.value,
                    "session_id": session_id
                },
                entity_id=event.transaction_id,
                entity_type="transaction",
                user_id="policy_engine"
            )
        except Exception as e:
            logger.error(f"Failed to record policy audit log: {e}")

    def get_policy_configuration(self) -> Dict[str, Any]:
        """Get current policy configuration."""
        return {
            "allowed_actions": list(self.allowed_actions),
            "max_auto_approve_amount": self.max_auto_approve_amount,
            "min_confidence_threshold": self.min_confidence_threshold,
            "evaluation_order": [func.__name__ for func in self.evaluation_order]
        }


# Global policy engine instance
policy_engine = PolicyEngine()