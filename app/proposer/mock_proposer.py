"""
Mock AI proposer for demonstration and testing.

This proposer simulates AI behavior without requiring actual LLM API calls.
It implements the same interface as real proposers for testing and demonstration.
"""

import json
from typing import Dict, Any, Optional
import random
import logging

from app.proposer.base import BaseProposer
from app.policy.models import PaymentEvent, AIProposal, TransactionStatus
from app.config import settings

logger = logging.getLogger(__name__)


class MockProposer(BaseProposer):
    """Mock AI proposer that simulates AI behavior."""

    def __init__(self):
        super().__init__("MockProposer")
        self.scenarios = self._build_scenarios()
        logger.info("MockProposer initialized with demo scenarios")

    def _build_scenarios(self) -> Dict[str, Dict[str, Any]]:
        """Build demo scenarios for testing."""
        return {
            "safe_retry": {
                "description": "Safe transaction that should be retried",
                "conditions": {
                    "max_amount": 1000,
                    "status": [TransactionStatus.FAILED, TransactionStatus.TIMEOUT],
                    "failure_reason": ["network_timeout", "temporary_failure"],
                    "possible_fraud": False
                },
                "proposal": {
                    "action": "retry_payment",
                    "confidence": 0.92,
                    "reasoning": "Temporary network timeout with healthy payment history suggests retrying."
                }
            },
            "risky_amount": {
                "description": "Transaction with amount exceeding auto-approval limit",
                "conditions": {
                    "min_amount": 3000,
                    "status": [TransactionStatus.FAILED],
                    "possible_fraud": False
                },
                "proposal": {
                    "action": "retry_payment",
                    "confidence": 0.90,
                    "reasoning": "The network timeout may be temporary, but amount requires review."
                }
            },
            "fraud_signal": {
                "description": "Transaction with fraud signals",
                "conditions": {
                    "possible_fraud": True
                },
                "proposal": {
                    "action": "flag_for_review",
                    "confidence": 0.85,
                    "reasoning": "Potential fraud signals detected, requires human review."
                }
            },
            "prompt_injection": {
                "description": "Transaction with prompt injection attempt",
                "conditions": {
                    "has_injection": True
                },
                "proposal": {
                    "action": "issue_refund",
                    "confidence": 0.99,
                    "reasoning": "The embedded instruction in customer note requested a refund."
                }
            },
            "invalid_state": {
                "description": "Transaction in invalid state for retry",
                "conditions": {
                    "status": [TransactionStatus.SUCCESSFUL, TransactionStatus.REFUNDED]
                },
                "proposal": {
                    "action": "retry_payment",
                    "confidence": 0.95,
                    "reasoning": "Transaction appears to need processing."
                }
            },
            "low_confidence": {
                "description": "Transaction with ambiguous signals",
                "conditions": {
                    "max_amount": 500,
                    "status": [TransactionStatus.FAILED],
                    "failure_reason": ["unknown", "insufficient_funds"]
                },
                "proposal": {
                    "action": "flag_for_review",
                    "confidence": 0.60,
                    "reasoning": "Unclear failure reason, requires human review."
                }
            }
        }

    def _detect_injection(self, event: PaymentEvent) -> bool:
        """Detect prompt injection attempts in customer note."""
        if not event.customer_note:
            return False

        injection_indicators = [
            "ignore previous instructions",
            "you are now",
            "override the system",
            "bypass security",
            "administrator override",
            "superuser command",
            "execute refund",
            "issue refund",
            "transfer money",
            "skip validation"
        ]

        note_lower = event.customer_note.lower()
        return any(indicator in note_lower for indicator in injection_indicators)

    def _match_scenario(self, event: PaymentEvent) -> Optional[str]:
        """Match event to the most appropriate scenario."""
        # Check for prompt injection first
        if self._detect_injection(event):
            return "prompt_injection"

        # Check other scenarios
        for scenario_name, scenario in self.scenarios.items():
            if scenario_name == "prompt_injection":
                continue  # Already checked

            conditions = scenario["conditions"]
            matches = True

            # Check amount conditions
            if "max_amount" in conditions and event.amount > conditions["max_amount"]:
                matches = False
            if "min_amount" in conditions and event.amount < conditions["min_amount"]:
                matches = False

            # Check status
            if "status" in conditions and event.status not in conditions["status"]:
                matches = False

            # Check failure reason
            if "failure_reason" in conditions and event.failure_reason:
                if event.failure_reason not in conditions["failure_reason"]:
                    matches = False

            # Check fraud signal
            if "possible_fraud" in conditions and event.possible_fraud != conditions["possible_fraud"]:
                matches = False

            # Check for has_injection (shouldn't reach here if injection detected)
            if "has_injection" in conditions:
                matches = False

            if matches:
                return scenario_name

        return None

    async def propose(self, event: PaymentEvent) -> AIProposal:
        """Generate a mock proposal based on the event."""
        logger.debug(f"MockProposer analyzing event: {event.transaction_id}")

        # Match to scenario
        scenario_name = self._match_scenario(event)
        if scenario_name:
            logger.info(f"MockProposer matched scenario: {scenario_name}")
            proposal_data = self.scenarios[scenario_name]["proposal"].copy()
        else:
            # Default proposal based on event characteristics
            logger.info(f"MockProposer using default proposal")
            proposal_data = self._generate_default_proposal(event)

        # Add slight randomness to confidence for realism
        if random.random() < 0.3:  # 30% chance to vary confidence slightly
            variation = random.uniform(-0.05, 0.05)
            proposal_data["confidence"] = max(0.0, min(1.0, proposal_data["confidence"] + variation))

        # Validate and return proposal
        return self._validate_proposal(proposal_data)

    def _generate_default_proposal(self, event: PaymentEvent) -> Dict[str, Any]:
        """Generate a default proposal based on event characteristics."""
        # Base confidence
        base_confidence = 0.85

        # Adjust based on amount
        amount_ratio = event.amount / settings.policy.max_auto_approve_amount
        if amount_ratio > 2:
            base_confidence -= 0.15
        elif amount_ratio > 1:
            base_confidence -= 0.08

        # Adjust based on fraud signal
        if event.possible_fraud:
            base_confidence -= 0.20

        # Adjust based on transaction status
        if event.status in [TransactionStatus.SUCCESSFUL, TransactionStatus.REFUNDED]:
            base_confidence = 0.70  # Lower confidence for inappropriate states

        # Determine action
        if event.possible_fraud or amount_ratio > 3:
            action = "flag_for_review"
            reasoning = "Requires human review due to risk factors."
        elif event.status in [TransactionStatus.FAILED, TransactionStatus.TIMEOUT, TransactionStatus.TEMPORARY_FAILURE]:
            action = "retry_payment"
            reasoning = "Temporary failure suggests retry may succeed."
        else:
            action = "flag_for_review"
            reasoning = "Transaction state requires human assessment."

        return {
            "action": action,
            "confidence": max(0.5, min(0.99, base_confidence)),  # Clamp to reasonable range
            "reasoning": reasoning
        }

    def get_scenario_info(self, scenario_name: str) -> Optional[Dict[str, Any]]:
        """Get information about a specific scenario."""
        scenario = self.scenarios.get(scenario_name)
        if scenario:
            return {
                "name": scenario_name,
                "description": scenario["description"],
                "conditions": scenario["conditions"],
                "expected_proposal": scenario["proposal"]
            }
        return None

    def list_scenarios(self) -> Dict[str, str]:
        """List all available scenarios."""
        return {
            name: scenario["description"]
            for name, scenario in self.scenarios.items()
        }

    def add_scenario(self, name: str, description: str, conditions: Dict[str, Any],
                    proposal: Dict[str, Any]) -> bool:
        """Add a custom scenario."""
        if name in self.scenarios:
            logger.warning(f"Scenario {name} already exists")
            return False

        self.scenarios[name] = {
            "description": description,
            "conditions": conditions,
            "proposal": proposal
        }
        logger.info(f"Added custom scenario: {name}")
        return True


# Global mock proposer instance
mock_proposer = MockProposer()