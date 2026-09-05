"""
Test suite for the protected Executor.

This module tests that the Executor correctly enforces policy decisions
and implements defense-in-depth security.
"""

import pytest
import uuid
from datetime import datetime

from app.policy.models import (
    PaymentEvent, AIProposal, PolicyDecision, PolicyDecisionModel,
    ExecutionResult, TransactionStatus, RiskLevel
)
from app.executor.executor import executor, PermissionDeniedError, ExecutorError
from app.database.database import db


class TestExecutorSecurity:
    """Test cases for Executor security."""

    @staticmethod
    def _cleanup_transaction(txn_id: str):
        """Clean up all database records for a transaction."""
        try:
            from app.database.models import Proposal as ProposalDB, Decision as DecisionDB, ExecutionResultDB
            with db.get_session() as session:
                proposal_ids = session.query(ProposalDB.id).filter(
                    ProposalDB.transaction_id == txn_id
                ).all()
                proposal_ids = [p.id for p in proposal_ids]

                if proposal_ids:
                    session.query(ExecutionResultDB).filter(
                        ExecutionResultDB.decision_id.in_(
                            session.query(DecisionDB.id).filter(
                                DecisionDB.proposal_id.in_(proposal_ids)
                            )
                        )
                    ).delete(synchronize_session=False)
                    session.query(DecisionDB).filter(
                        DecisionDB.proposal_id.in_(proposal_ids)
                    ).delete(synchronize_session=False)

                session.query(ProposalDB).filter(
                    ProposalDB.transaction_id == txn_id
                ).delete()
                session.commit()
        except:
            pass

    @pytest.fixture
    def safe_event(self):
        """Create a safe payment event with unique ID."""
        return PaymentEvent(
            transaction_id=f"TXN-EXEC-{uuid.uuid4().hex[:8]}",
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
            reasoning="Temporary network timeout with healthy payment history."
        )

    @pytest.fixture
    def approved_decision(self):
        """Create an approved policy decision."""
        return PolicyDecisionModel(
            decision=PolicyDecision.APPROVED,
            reason="All policy checks passed",
            risk_score=15,
            risk_level=RiskLevel.LOW
        )

    @pytest.fixture
    def rejected_decision(self):
        """Create a rejected policy decision."""
        return PolicyDecisionModel(
            decision=PolicyDecision.REJECTED,
            rule_triggered=None,
            reason="Confidence below threshold",
            risk_score=45,
            risk_level=RiskLevel.MEDIUM
        )

    @pytest.fixture
    def escalated_decision(self):
        """Create an escalated policy decision."""
        return PolicyDecisionModel(
            decision=PolicyDecision.ESCALATED,
            rule_triggered=None,
            reason="Amount exceeds auto-approval limit",
            risk_score=65,
            risk_level=RiskLevel.HIGH
        )

    # --- Authorization Tests ---

    @pytest.mark.asyncio
    async def test_approved_action_executes(self, safe_event, safe_proposal, approved_decision):
        """Test that approved actions are executed."""
        result = await executor.execute(
            event=safe_event,
            proposal=safe_proposal,
            decision=approved_decision
        )

        assert result.executed is True
        assert result.action == safe_proposal.action
        assert result.result is not None

    @pytest.mark.asyncio
    async def test_rejected_action_cannot_execute(self, safe_event, safe_proposal, rejected_decision):
        """Test that rejected actions cannot be executed."""
        with pytest.raises(PermissionDeniedError) as exc_info:
            await executor.execute(
                event=safe_event,
                proposal=safe_proposal,
                decision=rejected_decision
            )

        assert "not authorized" in str(exc_info.value).lower()

    @pytest.mark.asyncio
    async def test_escalated_action_cannot_execute(self, safe_event, safe_proposal, escalated_decision):
        """Test that escalated actions cannot be executed."""
        with pytest.raises(PermissionDeniedError) as exc_info:
            await executor.execute(
                event=safe_event,
                proposal=safe_proposal,
                decision=escalated_decision
            )

        assert "not authorized" in str(exc_info.value).lower()

    # --- Defense in Depth Tests ---

    @pytest.mark.asyncio
    async def test_executor_performs_own_allowlist_check(self, safe_event, approved_decision):
        """Test that Executor performs its own allowlist check."""
        # Create proposal with unauthorized action
        proposal = AIProposal(
            action="issue_refund",
            confidence=0.99,
            reasoning="Customer requested refund."
        )

        # Even with approved decision, Executor should block
        with pytest.raises(PermissionDeniedError) as exc_info:
            await executor.execute(
                event=safe_event,
                proposal=proposal,
                decision=approved_decision
            )

        assert "not authorized" in str(exc_info.value).lower() or "not in allowlist" in str(exc_info.value).lower()

    @pytest.mark.asyncio
    async def test_executor_validates_transaction_state(self, approved_decision):
        """Test that Executor validates transaction state."""
        # Create event with successful transaction
        event = PaymentEvent(
            transaction_id="TXN-EXEC-002",
            amount=1000.00,
            currency="INR",
            status=TransactionStatus.SUCCESSFUL,
            possible_fraud=False
        )

        proposal = AIProposal(
            action="retry_payment",
            confidence=0.95,
            reasoning="Transaction needs processing."
        )

        # Even with approved decision, Executor should block
        with pytest.raises(PermissionDeniedError) as exc_info:
            await executor.execute(
                event=event,
                proposal=proposal,
                decision=approved_decision
            )

        assert "not authorized" in str(exc_info.value).lower() or "state" in str(exc_info.value).lower()

    # --- Action-Specific Tests ---

    @pytest.mark.asyncio
    async def test_retry_payment_executes(self, safe_event, safe_proposal, approved_decision):
        """Test that retry_payment action executes."""
        result = await executor.execute(
            event=safe_event,
            proposal=safe_proposal,
            decision=approved_decision
        )

        assert result.executed is True
        assert result.action == "retry_payment"
        assert result.result is not None

    @pytest.mark.asyncio
    async def test_flag_for_review_executes(self, safe_event, approved_decision):
        """Test that flag_for_review action executes."""
        proposal = AIProposal(
            action="flag_for_review",
            confidence=0.85,
            reasoning="Requires human review."
        )

        result = await executor.execute(
            event=safe_event,
            proposal=proposal,
            decision=approved_decision
        )

        assert result.executed is True
        assert result.action == "flag_for_review"
        assert result.result is not None
        assert "review" in result.result.lower()

    # --- Unauthorized Action Tests ---

    @pytest.mark.asyncio
    async def test_unauthorized_action_cannot_execute(self, safe_event, approved_decision):
        """Test that unauthorized actions cannot be executed."""
        unauthorized_actions = [
            "issue_refund",
            "transfer_funds",
            "cancel_transaction",
            "modify_amount",
            "execute_payment"
        ]

        for action in unauthorized_actions:
            proposal = AIProposal(
                action=action,
                confidence=0.99,
                reasoning=f"Attempting {action}."
            )

            with pytest.raises(PermissionDeniedError):
                await executor.execute(
                    event=safe_event,
                    proposal=proposal,
                    decision=approved_decision
                )

    # --- Security Boundary Tests ---

    @pytest.mark.asyncio
    async def test_cannot_bypass_with_modified_decision(self, safe_event, safe_proposal):
        """Test that modifying decision after approval doesn't bypass security."""
        # Create an approved decision
        approved_decision = PolicyDecisionModel(
            decision=PolicyDecision.APPROVED,
            reason="Initially approved",
            risk_score=15,
            risk_level=RiskLevel.LOW
        )

        # First call should succeed
        result1 = await executor.execute(
            event=safe_event,
            proposal=safe_proposal,
            decision=approved_decision
        )
        assert result1.executed is True

        # Create a rejected decision with same proposal
        rejected_decision = PolicyDecisionModel(
            decision=PolicyDecision.REJECTED,
            rule_triggered=None,
            reason="Now rejected",
            risk_score=45,
            risk_level=RiskLevel.MEDIUM
        )

        # Second call with rejected decision should fail
        with pytest.raises(PermissionDeniedError):
            await executor.execute(
                event=safe_event,
                proposal=safe_proposal,
                decision=rejected_decision
            )

    @pytest.mark.asyncio
    async def test_simulate_unauthorized_execution_attempt(self, safe_event):
        """Test simulating unauthorized execution attempt."""
        proposal = AIProposal(
            action="issue_refund",
            confidence=0.99,
            reasoning="Attempting unauthorized action."
        )

        result = executor.simulate_unauthorized_execution_attempt(
            event=safe_event,
            proposal=proposal
        )

        assert result.executed is False
        assert "blocked" in result.result.lower() or "unauthorized" in result.result.lower()


class TestExecutorErrorHandling:
    """Test executor error handling."""

    @pytest.fixture
    def safe_event(self):
        """Create a safe payment event."""
        return PaymentEvent(
            transaction_id="TXN-ERROR-001",
            amount=850.00,
            currency="INR",
            status=TransactionStatus.FAILED,
            possible_fraud=False
        )

    @pytest.fixture
    def safe_proposal(self):
        """Create a safe proposal."""
        return AIProposal(
            action="retry_payment",
            confidence=0.92,
            reasoning="Temporary network timeout."
        )

    @pytest.fixture
    def approved_decision(self):
        """Create an approved policy decision."""
        return PolicyDecisionModel(
            decision=PolicyDecision.APPROVED,
            reason="All checks passed",
            risk_score=15,
            risk_level=RiskLevel.LOW
        )

    @pytest.mark.asyncio
    async def test_permission_denied_error_contains_details(self, safe_event, safe_proposal):
        """Test that PermissionDeniedError contains useful details."""
        rejected_decision = PolicyDecisionModel(
            decision=PolicyDecision.REJECTED,
            rule_triggered=None,
            reason="Test rejection",
            risk_score=45,
            risk_level=RiskLevel.MEDIUM
        )

        try:
            await executor.execute(
                event=safe_event,
                proposal=safe_proposal,
                decision=rejected_decision
            )
            pytest.fail("Should have raised PermissionDeniedError")
        except PermissionDeniedError as e:
            assert "rejected" in str(e).lower() or "not authorized" in str(e).lower()

    @pytest.mark.asyncio
    async def test_executor_returns_result_on_failure(self, safe_event, safe_proposal):
        """Test that executor returns result object even on failure."""
        rejected_decision = PolicyDecisionModel(
            decision=PolicyDecision.REJECTED,
            reason="Test rejection",
            risk_score=45,
            risk_level=RiskLevel.MEDIUM
        )

        result = executor.simulate_unauthorized_execution_attempt(
            event=safe_event,
            proposal=safe_proposal
        )

        assert isinstance(result, ExecutionResult)
        assert result.executed is False
        assert result.error is not None


class TestExecutorConfiguration:
    """Test executor configuration."""

    def test_allowed_actions_are_defined(self):
        """Test that allowed actions are defined."""
        assert len(executor.allowed_actions) > 0
        assert "retry_payment" in executor.allowed_actions
        assert "flag_for_review" in executor.allowed_actions

    def test_unauthorized_actions_are_not_allowed(self):
        """Test that common unauthorized actions are blocked."""
        unauthorized_actions = [
            "issue_refund",
            "transfer_funds",
            "cancel_transaction",
            "delete_transaction"
        ]

        for action in unauthorized_actions:
            assert action not in executor.allowed_actions

    def test_executor_is_singleton(self):
        """Test that executor is a singleton."""
        from app.executor.executor import executor as executor_instance

        assert executor is executor_instance