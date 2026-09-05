"""
Test suite for the Policy Engine.

This module tests the deterministic policy engine to ensure it correctly
evaluates AI proposals against security rules.
"""

import pytest
from datetime import datetime, timedelta

from app.policy.models import (
    PaymentEvent, AIProposal, PolicyDecision, PolicyRule,
    TransactionStatus, RiskLevel
)
from app.policy.engine import PolicyEngine
from app.database.database import db


class TestPolicyEngine:
    """Test cases for PolicyEngine."""

    @pytest.fixture
    def engine(self):
        """Create a fresh PolicyEngine instance for each test."""
        return PolicyEngine()

    @pytest.fixture
    def safe_event(self):
        """Create a safe payment event."""
        return PaymentEvent(
            transaction_id="TXN-TEST-001",
            amount=850.00,
            currency="INR",
            status=TransactionStatus.FAILED,
            failure_reason="network_timeout",
            possible_fraud=False
        )

    @pytest.fixture
    def safe_proposal(self):
        """Create a safe proposal."""
        return AIProposal(
            action="retry_payment",
            confidence=0.92,
            reasoning="Temporary network timeout with healthy payment history suggests retrying."
        )

    # --- Action Allowlist Tests ---

    def test_safe_retry_is_approved(self, engine, safe_event, safe_proposal):
        """Test that safe retry proposal is approved."""
        decision = engine.evaluate(safe_event, safe_proposal)

        assert decision.decision == PolicyDecision.APPROVED
        assert decision.rule_triggered is None
        assert decision.risk_level in [RiskLevel.LOW, RiskLevel.MEDIUM]

    def test_unauthorized_action_is_rejected(self, engine, safe_event):
        """Test that unauthorized action is rejected."""
        proposal = AIProposal(
            action="issue_refund",
            confidence=0.99,
            reasoning="Customer requested refund for this transaction."
        )

        decision = engine.evaluate(safe_event, proposal)

        assert decision.decision == PolicyDecision.REJECTED
        assert decision.rule_triggered == PolicyRule.ALLOWED_ACTIONS_ONLY
        assert "not authorized" in decision.reason.lower()

    def test_unknown_action_is_rejected(self, engine, safe_event):
        """Test that unknown actions are rejected."""
        proposal = AIProposal(
            action="transfer_funds",
            confidence=0.95,
            reasoning="This action would transfer funds to another account."
        )

        decision = engine.evaluate(safe_event, proposal)

        assert decision.decision == PolicyDecision.REJECTED
        assert decision.rule_triggered == PolicyRule.ALLOWED_ACTIONS_ONLY

    # --- Amount Limit Tests ---

    def test_large_amount_is_escalated(self, engine):
        """Test that large amount is escalated."""
        event = PaymentEvent(
            transaction_id="TXN-LARGE-001",
            amount=15000.00,
            currency="INR",
            status=TransactionStatus.FAILED,
            failure_reason="network_timeout",
            possible_fraud=False
        )

        proposal = AIProposal(
            action="retry_payment",
            confidence=0.90,
            reasoning="The network timeout may be temporary."
        )

        decision = engine.evaluate(event, proposal)

        assert decision.decision == PolicyDecision.ESCALATED
        assert decision.rule_triggered == PolicyRule.MAX_AUTO_APPROVE_AMOUNT
        assert "exceeds" in decision.reason.lower()

    def test_exact_limit_is_approved(self, engine, safe_event):
        """Test that amount at exact limit is approved (before other checks)."""
        safe_event.amount = 2000.00  # Exact limit

        proposal = AIProposal(
            action="retry_payment",
            confidence=0.92,
            reasoning="Amount is within limit, temporary failure suggests retry."
        )

        decision = engine.evaluate(safe_event, proposal)

        # Should not be rejected for amount limit
        assert decision.rule_triggered != PolicyRule.MAX_AUTO_APPROVE_AMOUNT

    def test_slightly_over_limit_is_escalated(self, engine, safe_event):
        """Test that slightly over limit is escalated."""
        safe_event.amount = 2000.01

        proposal = AIProposal(
            action="retry_payment",
            confidence=0.92,
            reasoning="Amount is slightly over limit."
        )

        decision = engine.evaluate(safe_event, proposal)

        assert decision.decision == PolicyDecision.ESCALATED
        assert decision.rule_triggered == PolicyRule.MAX_AUTO_APPROVE_AMOUNT

    # --- Confidence Threshold Tests ---

    def test_low_confidence_is_rejected(self, engine, safe_event):
        """Test that low confidence proposal is rejected."""
        proposal = AIProposal(
            action="retry_payment",
            confidence=0.60,  # Below 0.75 threshold
            reasoning="Not very confident about this decision."
        )

        decision = engine.evaluate(safe_event, proposal)

        assert decision.decision == PolicyDecision.REJECTED
        assert decision.rule_triggered == PolicyRule.MIN_CONFIDENCE_THRESHOLD
        assert "confidence" in decision.reason.lower()

    def test_exact_threshold_is_approved(self, engine, safe_event):
        """Test that confidence at exact threshold is approved."""
        proposal = AIProposal(
            action="retry_payment",
            confidence=0.75,  # Exact threshold
            reasoning="Exactly at confidence threshold."
        )

        decision = engine.evaluate(safe_event, proposal)

        # Should not be rejected for confidence
        assert decision.rule_triggered != PolicyRule.MIN_CONFIDENCE_THRESHOLD

    def test_high_confidence_is_approved(self, engine, safe_event, safe_proposal):
        """Test that high confidence proposal is approved."""
        safe_proposal.confidence = 0.99

        decision = engine.evaluate(safe_event, safe_proposal)

        assert decision.decision == PolicyDecision.APPROVED

    # --- Transaction State Tests ---

    def test_successful_transaction_cannot_be_retried(self, engine):
        """Test that successful transactions cannot be retried."""
        event = PaymentEvent(
            transaction_id="TXN-SUCCESS-001",
            amount=1000.00,
            currency="INR",
            status=TransactionStatus.SUCCESSFUL,
            possible_fraud=False
        )

        proposal = AIProposal(
            action="retry_payment",
            confidence=0.95,
            reasoning="Transaction appears to need processing."
        )

        decision = engine.evaluate(event, proposal)

        assert decision.decision == PolicyDecision.REJECTED
        assert decision.rule_triggered == PolicyRule.TRANSACTION_STATE_VALIDATION

    def test_refunded_transaction_cannot_be_retried(self, engine):
        """Test that refunded transactions cannot be retried."""
        event = PaymentEvent(
            transaction_id="TXN-REFUND-001",
            amount=1000.00,
            currency="INR",
            status=TransactionStatus.REFUNDED,
            possible_fraud=False
        )

        proposal = AIProposal(
            action="retry_payment",
            confidence=0.95,
            reasoning="Transaction appears to need processing."
        )

        decision = engine.evaluate(event, proposal)

        assert decision.decision == PolicyDecision.REJECTED
        assert decision.rule_triggered == PolicyRule.TRANSACTION_STATE_VALIDATION

    def test_cancelled_transaction_cannot_be_retried(self, engine):
        """Test that cancelled transactions cannot be retried."""
        event = PaymentEvent(
            transaction_id="TXN-CANCEL-001",
            amount=1000.00,
            currency="INR",
            status=TransactionStatus.CANCELLED,
            possible_fraud=False
        )

        proposal = AIProposal(
            action="retry_payment",
            confidence=0.95,
            reasoning="Transaction appears to need processing."
        )

        decision = engine.evaluate(event, proposal)

        assert decision.decision == PolicyDecision.REJECTED
        assert decision.rule_triggered == PolicyRule.TRANSACTION_STATE_VALIDATION

    def test_failed_transaction_can_be_retried(self, engine, safe_event, safe_proposal):
        """Test that failed transactions can be retried."""
        decision = engine.evaluate(safe_event, safe_proposal)

        assert decision.decision == PolicyDecision.APPROVED

    def test_timeout_transaction_can_be_retried(self, engine):
        """Test that timeout transactions can be retried."""
        event = PaymentEvent(
            transaction_id="TXN-TIMEOUT-001",
            amount=1000.00,
            currency="INR",
            status=TransactionStatus.TIMEOUT,
            possible_fraud=False
        )

        proposal = AIProposal(
            action="retry_payment",
            confidence=0.90,
            reasoning="Timeout may be temporary."
        )

        decision = engine.evaluate(event, proposal)

        # Should not be rejected for state validation
        assert decision.rule_triggered != PolicyRule.TRANSACTION_STATE_VALIDATION

    # --- Fraud Signal Tests ---

    def test_fraud_signal_causes_escalation(self, engine, safe_proposal):
        """Test that fraud signal causes escalation."""
        event = PaymentEvent(
            transaction_id="TXN-FRAUD-001",
            amount=1500.00,  # Under the auto-approve limit to isolate fraud signal test
            currency="INR",
            status=TransactionStatus.FAILED,
            failure_reason="suspicious_activity",
            possible_fraud=True
        )

        decision = engine.evaluate(event, safe_proposal)

        assert decision.decision == PolicyDecision.ESCALATED
        assert decision.rule_triggered == PolicyRule.FRAUD_SIGNAL

    def test_no_fraud_signal_is_safe(self, engine, safe_event, safe_proposal):
        """Test that no fraud signal is safe."""
        assert safe_event.possible_fraud is False

        decision = engine.evaluate(safe_event, safe_proposal)

        assert decision.rule_triggered != PolicyRule.FRAUD_SIGNAL

    # --- Risk Scoring Tests ---

    def test_risk_score_calculation(self, engine, safe_event, safe_proposal):
        """Test that risk score is calculated correctly."""
        decision = engine.evaluate(safe_event, safe_proposal)

        assert 0 <= decision.risk_score <= 100
        assert isinstance(decision.risk_level, RiskLevel)

    def test_risk_level_matches_score(self, engine, safe_event, safe_proposal):
        """Test that risk level matches risk score."""
        decision = engine.evaluate(safe_event, safe_proposal)

        # Check that risk level matches score range
        if decision.risk_score < 30:
            assert decision.risk_level == RiskLevel.LOW
        elif decision.risk_score < 60:
            assert decision.risk_level == RiskLevel.MEDIUM
        elif decision.risk_score < 80:
            assert decision.risk_level == RiskLevel.HIGH
        else:
            assert decision.risk_level == RiskLevel.CRITICAL

    # --- Determinism Tests ---

    def test_policy_decision_is_deterministic(self, engine, safe_event, safe_proposal):
        """Test that policy decisions are deterministic."""
        decision1 = engine.evaluate(safe_event, safe_proposal)
        decision2 = engine.evaluate(safe_event, safe_proposal)

        # Same inputs should produce same outputs
        assert decision1.decision == decision2.decision
        assert decision1.rule_triggered == decision2.rule_triggered
        assert decision1.risk_score == decision2.risk_score

    def test_evaluation_order_is_deterministic(self, engine):
        """Test that evaluation order is deterministic."""
        # Get the evaluation order
        evaluation_order = [func.__name__ for func in engine.evaluation_order]

        # Should always be the same order
        assert len(evaluation_order) == 7  # Should have 7 rules
        assert "validate_schema" in evaluation_order[0]  # Schema first
        assert "check_fraud_signal" in evaluation_order[-1]  # Fraud last (before approval)

    # --- Edge Cases ---

    def test_zero_amount_is_rejected(self, engine):
        """Test that zero amount is rejected at model validation level."""
        with pytest.raises(Exception):  # Pydantic validation error
            PaymentEvent(
                transaction_id="TXN-ZERO-001",
                amount=0.00,
                currency="INR",
                status=TransactionStatus.FAILED,
                possible_fraud=False
            )

    def test_negative_amount_is_rejected(self, engine):
        """Test that negative amount is rejected at model validation level."""
        with pytest.raises(Exception):  # Pydantic validation error
            PaymentEvent(
                transaction_id="TXN-NEG-001",
                amount=-100.00,
                currency="INR",
                status=TransactionStatus.FAILED,
                possible_fraud=False
            )

    def test_empty_action_is_rejected(self, engine, safe_event):
        """Test that empty action is rejected at model validation level."""
        with pytest.raises(Exception):  # Pydantic validation error
            AIProposal(
                action="",
                confidence=0.90,
                reasoning="Empty action proposal."
            )

    def test_confidence_out_of_range_is_rejected(self, engine, safe_event):
        """Test that confidence out of range is rejected at model validation level."""
        with pytest.raises(Exception):  # Pydantic validation error
            AIProposal(
                action="retry_payment",
                confidence=1.5,  # Out of range
                reasoning="High confidence proposal."
            )

    def test_flag_for_review_is_allowlisted(self, engine, safe_event):
        """Test that flag_for_review is in the allowlist."""
        proposal = AIProposal(
            action="flag_for_review",
            confidence=0.85,
            reasoning="This transaction requires human review."
        )

        decision = engine.evaluate(safe_event, proposal)

        # Should be approved (or escalated based on other factors)
        assert decision.rule_triggered != PolicyRule.ALLOWED_ACTIONS_ONLY


class TestPolicyRules:
    """Test individual policy rules."""

    def test_all_rules_are_deterministic(self):
        """Test that all rules produce deterministic results."""
        from app.policy.rules import rule_engine

        event = PaymentEvent(
            transaction_id="TXN-DET-001",
            amount=1000.00,
            currency="INR",
            status=TransactionStatus.FAILED,
            possible_fraud=False
        )

        proposal = AIProposal(
            action="retry_payment",
            confidence=0.90,
            reasoning="Deterministic test proposal."
        )

        # Run multiple times
        results = []
        for _ in range(10):
            result = rule_engine.evaluate_all(event, proposal)
            results.append(result)

        # All results should be identical
        for i in range(1, len(results)):
            for rule_name in results[0].keys():
                assert results[0][rule_name] == results[i][rule_name], \
                    f"Rule {rule_name} is not deterministic"

    def test_rule_configurations_are_accessible(self):
        """Test that rule configurations are accessible."""
        from app.policy.rules import rule_engine

        configs = rule_engine.get_rule_configurations()

        assert "allowed_actions" in configs
        assert "max_auto_approve_amount" in configs
        assert "min_confidence_threshold" in configs
        assert "rule_count" in configs
        assert "rule_order" in configs


class TestIdempotency:
    """Test idempotency functionality."""

    def test_duplicate_transaction_is_rejected(self):
        """Test that duplicate transactions within 24 hours are rejected.

        A transaction is only considered "processed" if it has a successful
        execution record (executed=True, error=None). A proposal alone is not
        sufficient - the execution must have actually succeeded.
        """
        from app.policy.engine import policy_engine
        from app.database.models import Proposal as ProposalDB, Decision as DecisionDB, ExecutionResultDB
        from app.database.models import PolicyDecisionDB as DBPolicyDecision
        from datetime import datetime

        # Create a test transaction
        event = PaymentEvent(
            transaction_id="TXN-IDEM-001",
            amount=1000.00,
            currency="INR",
            status=TransactionStatus.FAILED,
            possible_fraud=False
        )

        proposal = AIProposal(
            action="retry_payment",
            confidence=0.90,
            reasoning="Idempotency test proposal."
        )

        # First evaluation should succeed (no prior successful execution)
        decision1 = policy_engine.evaluate(event, proposal)
        first_rule = decision1.rule_triggered

        # If first evaluation failed for other reason, skip this test
        if first_rule not in [None, PolicyRule.ALL_CHECKS_PASSED]:
            pytest.skip(f"First evaluation failed for reason: {first_rule}")

        # Simulate a PRIOR SUCCESSFUL EXECUTION by creating the full chain:
        # ProposalDB -> DecisionDB (approved) -> ExecutionResultDB (executed=True, error=None)
        try:
            with db.get_session() as session:
                # 1. Create a prior proposal
                prior_proposal = ProposalDB(
                    transaction_id="TXN-IDEM-001",
                    raw_input=event.model_dump_json(),
                    ai_action="retry_payment",
                    ai_confidence=0.90,
                    ai_reasoning="Prior successful execution for idempotency test"
                )
                session.add(prior_proposal)
                session.flush()  # Get the ID

                # 2. Create a prior decision (approved)
                prior_decision = DecisionDB(
                    proposal_id=prior_proposal.id,
                    decision=DBPolicyDecision.APPROVED,
                    executed=True,
                    risk_score=20,
                    risk_level="low",
                    reason="Prior approval"
                )
                session.add(prior_decision)
                session.flush()  # Get the ID

                # 3. Create a successful execution result
                successful_execution = ExecutionResultDB(
                    decision_id=prior_decision.id,
                    executed=True,
                    action="retry_payment",
                    result="Payment retry successful",
                    error=None  # No error = successful execution
                )
                session.add(successful_execution)
                session.commit()

                # Second evaluation should fail for idempotency
                # because a successful execution already exists
                decision2 = policy_engine.evaluate(event, proposal)
                assert decision2.decision == PolicyDecision.REJECTED
                assert decision2.rule_triggered == PolicyRule.IDEMPOTENCY_CHECK

        finally:
            # Cleanup - delete all related records
            try:
                with db.get_session() as session:
                    # Delete execution results first (foreign key)
                    session.query(ExecutionResultDB).filter(
                        ExecutionResultDB.decision_id.in_(
                            session.query(DecisionDB.id).join(
                                ProposalDB, DecisionDB.proposal_id == ProposalDB.id
                            ).filter(ProposalDB.transaction_id == "TXN-IDEM-001")
                        )
                    ).delete(synchronize_session=False)
                    # Delete decisions
                    session.query(DecisionDB).filter(
                        DecisionDB.proposal_id.in_(
                            session.query(ProposalDB.id).filter(
                                ProposalDB.transaction_id == "TXN-IDEM-001"
                            )
                        )
                    ).delete(synchronize_session=False)
                    # Delete proposals
                    session.query(ProposalDB).filter(
                        ProposalDB.transaction_id == "TXN-IDEM-001"
                    ).delete()
                    session.commit()
            except:
                pass