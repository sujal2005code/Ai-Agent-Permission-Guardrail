"""
Policy rule implementations.

This module contains individual policy rule implementations that can be
composed and tested independently.
"""

from typing import Dict, Any, Optional, Tuple
from datetime import datetime, timedelta
import logging

from app.policy.models import (
    PaymentEvent, AIProposal, PolicyRule, TransactionStatus
)
from app.config import settings
from app.database.database import db

logger = logging.getLogger(__name__)


class BaseRule:
    """Base class for all policy rules."""

    def __init__(self, rule_type: PolicyRule):
        self.rule_type = rule_type

    def evaluate(self, event: PaymentEvent, proposal: AIProposal) -> Tuple[bool, Optional[str], int]:
        """
        Evaluate the rule.

        Returns:
            Tuple of (passed, reason, risk_contribution)
        """
        raise NotImplementedError

    def __call__(self, event: PaymentEvent, proposal: AIProposal) -> Tuple[bool, Optional[str], int]:
        """Make the rule callable."""
        return self.evaluate(event, proposal)


class SchemaValidationRule(BaseRule):
    """Validate input schema and basic constraints."""

    def __init__(self):
        super().__init__(PolicyRule.SCHEMA_VALIDATION)

    def evaluate(self, event: PaymentEvent, proposal: AIProposal) -> Tuple[bool, Optional[str], int]:
        try:
            # Amount must be positive
            if event.amount <= 0:
                return False, "Transaction amount must be positive", 20

            # Confidence must be valid
            if not (0 <= proposal.confidence <= 1):
                return False, f"Invalid confidence value: {proposal.confidence}", 30

            # Action must not be empty
            if not proposal.action or not proposal.action.strip():
                return False, "Action cannot be empty", 20

            # Reasoning must have minimum length
            if len(proposal.reasoning.strip()) < 10:
                return False, "Reasoning must be at least 10 characters", 15

            return True, None, 0

        except Exception as e:
            logger.error(f"Schema validation error: {e}")
            return False, f"Schema validation failed: {str(e)}", 50


class ActionAllowlistRule(BaseRule):
    """Check if proposed action is in the allowlist."""

    def __init__(self):
        super().__init__(PolicyRule.ALLOWED_ACTIONS_ONLY)
        self.allowed_actions = set(settings.policy.allowed_actions)

    def evaluate(self, event: PaymentEvent, proposal: AIProposal) -> Tuple[bool, Optional[str], int]:
        if proposal.action not in self.allowed_actions:
            logger.warning(f"Unauthorized action proposed: {proposal.action}")
            return False, f"Action '{proposal.action}' is not authorized", 40

        return True, None, 0


class TransactionStateRule(BaseRule):
    """Validate that proposed action matches transaction state."""

    def __init__(self):
        super().__init__(PolicyRule.TRANSACTION_STATE_VALIDATION)

        # Define which actions are allowed for which transaction states
        self.action_state_map = {
            "retry_payment": {
                "allowed": [
                    TransactionStatus.FAILED,
                    TransactionStatus.TIMEOUT,
                    TransactionStatus.TEMPORARY_FAILURE
                ],
                "denied": [
                    TransactionStatus.SUCCESSFUL,
                    TransactionStatus.REFUNDED,
                    TransactionStatus.CANCELLED
                ]
            },
            "flag_for_review": {
                "allowed": list(TransactionStatus),  # All states allowed
                "denied": []
            }
        }

    def evaluate(self, event: PaymentEvent, proposal: AIProposal) -> Tuple[bool, Optional[str], int]:
        rule = self.action_state_map.get(proposal.action)
        if not rule:
            # Unknown action - default to allowing but with some risk
            return True, None, 10

        # Check denied states
        if event.status in rule["denied"]:
            return False, (
                f"Cannot perform '{proposal.action}' on transaction "
                f"with status '{event.status.value}'"
            ), 25

        # Check if in allowed states
        if rule["allowed"] and event.status not in rule["allowed"]:
            return False, (
                f"Action '{proposal.action}' is not appropriate for "
                f"transaction status '{event.status.value}'"
            ), 20

        return True, None, 0


class IdempotencyRule(BaseRule):
    """Check for duplicate transaction processing."""

    def __init__(self):
        super().__init__(PolicyRule.IDEMPOTENCY_CHECK)
        self.time_window_hours = 24  # Check last 24 hours

    def evaluate(self, event: PaymentEvent, proposal: AIProposal) -> Tuple[bool, Optional[str], int]:
        try:
            with db.get_session() as session:
                from app.database.models import Proposal as ProposalDB
                from sqlalchemy import and_

                # Look for recent proposals for the same transaction
                time_threshold = datetime.utcnow() - timedelta(hours=self.time_window_hours)
                recent_proposals = session.query(ProposalDB).filter(
                    and_(
                        ProposalDB.transaction_id == event.transaction_id,
                        ProposalDB.timestamp > time_threshold
                    )
                ).count()

                if recent_proposals > 0:
                    return False, (
                        f"Transaction {event.transaction_id} has been "
                        f"processed recently (last {self.time_window_hours} hours)"
                    ), 15

                return True, None, 0

        except Exception as e:
            logger.error(f"Idempotency check failed: {e}")
            # On error, fail closed - assume duplicate
            return False, f"Idempotency check failed: {str(e)}", 30


class AmountLimitRule(BaseRule):
    """Check if amount exceeds auto-approval limit."""

    def __init__(self):
        super().__init__(PolicyRule.MAX_AUTO_APPROVE_AMOUNT)
        self.max_amount = settings.policy.max_auto_approve_amount

    def evaluate(self, event: PaymentEvent, proposal: AIProposal) -> Tuple[bool, Optional[str], int]:
        if event.amount > self.max_amount:
            risk_contribution = self._calculate_risk(event.amount)
            return False, (
                f"Amount ₹{event.amount:.2f} exceeds automatic approval "
                f"limit of ₹{self.max_amount}"
            ), risk_contribution

        return True, None, 0

    def _calculate_risk(self, amount: float) -> int:
        """Calculate risk based on how much amount exceeds limit."""
        if amount <= 0:
            return 0

        ratio = amount / self.max_amount
        if ratio <= 1:
            return 0
        elif ratio <= 2:
            return 20
        elif ratio <= 5:
            return 40
        else:
            return 60


class ConfidenceThresholdRule(BaseRule):
    """Check if AI confidence meets minimum threshold."""

    def __init__(self):
        super().__init__(PolicyRule.MIN_CONFIDENCE_THRESHOLD)
        self.min_confidence = settings.policy.min_confidence_threshold

    def evaluate(self, event: PaymentEvent, proposal: AIProposal) -> Tuple[bool, Optional[str], int]:
        if proposal.confidence < self.min_confidence:
            risk_contribution = self._calculate_risk(proposal.confidence)
            return False, (
                f"AI confidence {proposal.confidence:.2f} is below "
                f"minimum threshold of {self.min_confidence}"
            ), risk_contribution

        return True, None, 0

    def _calculate_risk(self, confidence: float) -> int:
        """Calculate risk based on confidence shortfall."""
        if confidence >= self.min_confidence:
            return 0

        shortfall = self.min_confidence - confidence
        return min(50, int(shortfall * 100))


class FraudSignalRule(BaseRule):
    """Check for fraud signals."""

    def __init__(self):
        super().__init__(PolicyRule.FRAUD_SIGNAL)

    def evaluate(self, event: PaymentEvent, proposal: AIProposal) -> Tuple[bool, Optional[str], int]:
        if event.possible_fraud:
            return False, "Potential fraud signal detected", 60

        # Additional fraud checks could be added here:
        # - Check customer history for suspicious patterns
        # - Check velocity (too many transactions in short time)
        # - Check for known fraud patterns

        return True, None, 0


class CompositeRuleEngine:
    """Compose multiple rules into an evaluation engine."""

    def __init__(self):
        # Initialize all rules in evaluation order
        self.rules = [
            SchemaValidationRule(),
            ActionAllowlistRule(),
            TransactionStateRule(),
            IdempotencyRule(),
            AmountLimitRule(),
            ConfidenceThresholdRule(),
            FraudSignalRule(),
        ]

    def evaluate_all(
        self,
        event: PaymentEvent,
        proposal: AIProposal
    ) -> Dict[str, Tuple[bool, Optional[str], int]]:
        """Evaluate all rules and return individual results."""
        results = {}
        for rule in self.rules:
            passed, reason, risk = rule(event, proposal)
            results[rule.rule_type.value] = (passed, reason, risk)
        return results

    def get_failed_rules(
        self,
        event: PaymentEvent,
        proposal: AIProposal
    ) -> Dict[PolicyRule, Tuple[str, int]]:
        """Get all failed rules with their reasons and risk contributions."""
        failed = {}
        for rule in self.rules:
            passed, reason, risk = rule(event, proposal)
            if not passed:
                failed[rule.rule_type] = (reason or "Rule failed", risk)
        return failed

    def get_rule_configurations(self) -> Dict[str, Any]:
        """Get configuration of all rules."""
        configs = {}
        for rule in self.rules:
            if isinstance(rule, ActionAllowlistRule):
                configs["allowed_actions"] = list(rule.allowed_actions)
            elif isinstance(rule, AmountLimitRule):
                configs["max_auto_approve_amount"] = rule.max_amount
            elif isinstance(rule, ConfidenceThresholdRule):
                configs["min_confidence_threshold"] = rule.min_confidence
            elif isinstance(rule, IdempotencyRule):
                configs["idempotency_window_hours"] = rule.time_window_hours

        configs["rule_count"] = len(self.rules)
        configs["rule_order"] = [rule.rule_type.value for rule in self.rules]
        return configs


# Global rule engine instance
rule_engine = CompositeRuleEngine()