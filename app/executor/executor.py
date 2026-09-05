"""
Protected Executor module.

This module executes actions ONLY when authorized by the Policy Engine.
It implements defense-in-depth security with multiple verification layers.

Key Principle: The Executor obeys only approved decisions.
"""

import logging
from typing import Optional, Dict, Any
from datetime import datetime
import random

from app.policy.models import (
    PaymentEvent, AIProposal, PolicyDecisionModel, PolicyDecision,
    ExecutionResult, TransactionStatus
)
from app.config import settings
from app.database.database import db
from app.database.models import ExecutionResultDB

logger = logging.getLogger(__name__)


class ExecutorError(Exception):
    """Exception raised when execution fails."""

    def __init__(self, message: str, original_error: Optional[Exception] = None):
        super().__init__(message)
        self.original_error = original_error


class PermissionDeniedError(ExecutorError):
    """Exception raised when execution is not authorized."""


class Executor:
    """Protected executor that only executes approved actions."""

    def __init__(self):
        """Initialize executor with security configuration."""
        self.allowed_actions = set(settings.policy.allowed_actions)
        logger.info(f"Executor initialized with allowed actions: {self.allowed_actions}")

    async def execute(
        self,
        event: PaymentEvent,
        proposal: AIProposal,
        decision: PolicyDecisionModel,
        session_id: Optional[str] = None
    ) -> ExecutionResult:
        """
        Execute an action ONLY if authorized by policy decision.

        This method implements defense-in-depth security:
        1. Verify policy approval
        2. Verify action is in allowlist
        3. Verify transaction state is valid
        4. Execute action (simulated)
        5. Record result

        Args:
            event: The payment event
            proposal: The AI proposal
            decision: The policy decision
            session_id: Optional session ID for logging

        Returns:
            Execution result

        Raises:
            PermissionDeniedError: If execution is not authorized
            ExecutorError: If execution fails
        """
        logger.info(
            f"Executor processing transaction {event.transaction_id}, "
            f"proposal: {proposal.action}, decision: {decision.decision}"
        )

        # LAYER 1: Verify policy approval
        if decision.decision != PolicyDecision.APPROVED:
            error_msg = f"Execution not authorized: policy decision is {decision.decision}"
            logger.warning(error_msg)
            result = ExecutionResult(
                executed=False,
                error=error_msg,
                timestamp=datetime.utcnow()
            )
            self._record_execution(event, proposal, decision, result, session_id)
            raise PermissionDeniedError(error_msg)

        # LAYER 2: Defense in depth - verify action is in allowlist
        if proposal.action not in self.allowed_actions:
            error_msg = f"Action '{proposal.action}' is not in allowlist"
            logger.warning(error_msg)
            result = ExecutionResult(
                executed=False,
                error=error_msg,
                timestamp=datetime.utcnow()
            )
            self._record_execution(event, proposal, decision, result, session_id)
            raise PermissionDeniedError(error_msg)

        # LAYER 3: Defense in depth - verify transaction state
        if not self._is_transaction_state_valid(event, proposal):
            error_msg = f"Transaction state {event.status.value} is invalid for action {proposal.action}"
            logger.warning(error_msg)
            result = ExecutionResult(
                executed=False,
                error=error_msg,
                timestamp=datetime.utcnow()
            )
            self._record_execution(event, proposal, decision, result, session_id)
            raise PermissionDeniedError(error_msg)

        # LAYER 4: Defense in depth - verify idempotency
        # This is an independent check that mirrors the policy engine's idempotency check.
        # If policy engine passed but executor finds ANY execution attempt, block it.
        if self._has_recent_execution_attempt(event.transaction_id):
            error_msg = (
                f"Idempotency violation: Transaction {event.transaction_id} "
                f"has already been processed within the last 24 hours (any execution attempt)"
            )
            logger.warning(f"Executor idempotency check triggered: {error_msg}")
            result = ExecutionResult(
                executed=False,
                action=proposal.action,
                error=error_msg,
                timestamp=datetime.utcnow()
            )
            self._record_execution(event, proposal, decision, result, session_id)
            raise PermissionDeniedError(error_msg)

        try:
            # Execute the action (simulated for this demo)
            execution_result = await self._execute_action(event, proposal, session_id)

            # Record successful execution
            self._record_execution(event, proposal, decision, execution_result, session_id)

            logger.info(
                f"Executor successfully executed {proposal.action} "
                f"for transaction {event.transaction_id}"
            )

            return execution_result

        except Exception as e:
            logger.error(f"Execution failed: {e}")
            result = ExecutionResult(
                executed=False,
                action=proposal.action,
                error=str(e),
                timestamp=datetime.utcnow()
            )
            self._record_execution(event, proposal, decision, result, session_id)
            raise ExecutorError(f"Execution failed: {e}", e)

    def _is_transaction_state_valid(self, event: PaymentEvent, proposal: AIProposal) -> bool:
        """Validate that transaction state allows the proposed action."""
        # Define valid state-action mappings
        state_action_map = {
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

        rule = state_action_map.get(proposal.action)
        if not rule:
            return False  # Unknown action

        if event.status in rule["denied"]:
            return False

        if rule["allowed"] and event.status not in rule["allowed"]:
            return False

        return True

    def _has_recent_execution_attempt(self, transaction_id: str) -> bool:
        """
        Check if a transaction has been processed before.

        REVISED: Check for ANY execution attempt (not just successful ones).
        This matches the policy engine's updated idempotency check.

        Returns:
            True if ANY execution attempt exists within the 24-hour window
        """
        try:
            from datetime import timedelta
            from app.database.models import ExecutionResultDB, Decision, Proposal as ProposalDB
            from sqlalchemy import and_

            time_threshold = datetime.utcnow() - timedelta(hours=24)

            with db.get_session() as session:
                # Check for ANY execution attempt through relationship chain
                # REMOVED: ExecutionResultDB.error == None condition
                count = session.query(ExecutionResultDB).join(
                    Decision, ExecutionResultDB.decision_id == Decision.id
                ).join(
                    ProposalDB, Decision.proposal_id == ProposalDB.id
                ).filter(
                    and_(
                        ProposalDB.transaction_id == transaction_id,
                        ExecutionResultDB.executed == True,  # ANY execution attempt
                        ExecutionResultDB.timestamp > time_threshold
                    )
                ).count()

                return count > 0

        except Exception as e:
            logger.error(f"Executor idempotency check failed: {e}")
            # On error, fail closed - assume duplicate to be safe
            return True

    async def _execute_action(
        self,
        event: PaymentEvent,
        proposal: AIProposal,
        session_id: Optional[str]
    ) -> ExecutionResult:
        """
        Execute the actual action (simulated for this demo).

        In a real system, this would:
        - Call payment APIs
        - Update transaction status
        - Send notifications
        - etc.

        For this demo, we simulate the behavior.
        """
        logger.info(f"Simulating execution of {proposal.action} for {event.transaction_id}")

        if proposal.action == "retry_payment":
            return await self._execute_retry_payment(event, proposal, session_id)
        elif proposal.action == "flag_for_review":
            return await self._execute_flag_for_review(event, proposal, session_id)
        else:
            # This should never happen due to allowlist check, but defensive programming
            raise ExecutorError(f"Unknown action: {proposal.action}")

    async def _execute_retry_payment(
        self,
        event: PaymentEvent,
        proposal: AIProposal,
        session_id: Optional[str]
    ) -> ExecutionResult:
        """Simulate payment retry execution."""
        # In a real system, this would:
        # 1. Call payment gateway API
        # 2. Process the retry
        # 3. Update transaction status
        # 4. Return result

        # Simulate processing delay
        await asyncio.sleep(0.5)

        # Simulate success/failure based on scenario
        # For demo purposes, we use deterministic behavior based on transaction ID
        transaction_hash = hash(event.transaction_id) % 100

        if event.possible_fraud:
            # Fraud signals should have been caught by policy, but double-check
            result_text = "Payment retry blocked due to fraud signal"
            success = False
        elif transaction_hash < 80:  # 80% success rate for demo
            result_text = f"Payment retry successful for ₹{event.amount:.2f}"
            success = True
        else:
            result_text = f"Payment retry failed (simulated failure)"
            success = False

        return ExecutionResult(
            executed=True,
            action="retry_payment",
            result=result_text,
            timestamp=datetime.utcnow(),
            error=None if success else result_text
        )

    async def _execute_flag_for_review(
        self,
        event: PaymentEvent,
        proposal: AIProposal,
        session_id: Optional[str]
    ) -> ExecutionResult:
        """Simulate flagging transaction for human review."""
        # In a real system, this would:
        # 1. Create review ticket
        # 2. Notify review team
        # 3. Update transaction status
        # 4. Return result

        # Simulate processing delay
        await asyncio.sleep(0.3)

        try:
            with db.get_session() as session:
                from app.database.models import Review as ReviewDB

                # Create review record
                review = ReviewDB(
                    transaction_id=event.transaction_id,
                    reason=proposal.reasoning[:500],  # Truncate if too long
                    status="pending"
                )
                session.add(review)
                session.commit()

                review_id = review.id

            result_text = (
                f"Transaction flagged for review (ID: {review_id}). "
                f"Reason: {proposal.reasoning[:100]}..."
            )

            return ExecutionResult(
                executed=True,
                action="flag_for_review",
                result=result_text,
                timestamp=datetime.utcnow()
            )

        except Exception as e:
            logger.error(f"Failed to create review: {e}")
            return ExecutionResult(
                executed=True,  # Attempt was made
                action="flag_for_review",
                result="Failed to create review record",
                timestamp=datetime.utcnow(),
                error=str(e)
            )

    def _record_execution(
        self,
        event: PaymentEvent,
        proposal: AIProposal,
        decision: PolicyDecisionModel,
        execution_result: ExecutionResult,
        session_id: Optional[str]
    ):
        """Record execution attempt in database and audit log."""
        try:
            from app.database.models import (
                Proposal as ProposalDB, Decision as DecisionDB,
                ExecutionResultDB as ExecResultDB, PolicyDecisionDB
            )

            # Record in audit log
            db.record_audit_log(
                event_type="execution",
                action=proposal.action,
                details={
                    "transaction_id": event.transaction_id,
                    "amount": event.amount,
                    "proposal_action": proposal.action,
                    "policy_decision": decision.decision.value,
                    "executed": execution_result.executed,
                    "result": execution_result.result,
                    "error": execution_result.error,
                    "session_id": session_id
                },
                entity_id=event.transaction_id,
                entity_type="transaction",
                user_id="executor"
            )

            # Create database records for the execution result
            # This is needed for idempotency checking
            with db.get_session() as session:
                # 1. Create ProposalDB record
                proposal_db = ProposalDB(
                    transaction_id=event.transaction_id,
                    raw_input=event.model_dump_json(),
                    ai_action=proposal.action,
                    ai_confidence=proposal.confidence,
                    ai_reasoning=proposal.reasoning
                )
                session.add(proposal_db)
                session.flush()

                # 2. Create DecisionDB record
                decision_db = DecisionDB(
                    proposal_id=proposal_db.id,
                    decision=PolicyDecisionDB(decision.decision.value),
                    rule_triggered=decision.rule_triggered.value if decision.rule_triggered else None,
                    executed=execution_result.executed,
                    risk_score=decision.risk_score,
                    risk_level=decision.risk_level.value,
                    reason=decision.reason
                )
                session.add(decision_db)
                session.flush()

                # 3. Create ExecutionResultDB record
                exec_result_db = ExecResultDB(
                    decision_id=decision_db.id,
                    executed=execution_result.executed,
                    action=execution_result.action,
                    result=execution_result.result,
                    error=execution_result.error
                )
                session.add(exec_result_db)
                session.commit()

                logger.debug(f"Recorded execution: proposal_id={proposal_db.id}, decision_id={decision_db.id}, exec_id={exec_result_db.id}")

        except Exception as e:
            logger.error(f"Failed to record execution: {e}")
            # Don't raise - execution succeeded, just logging failed

    def simulate_unauthorized_execution_attempt(
        self,
        event: PaymentEvent,
        proposal: AIProposal,
        session_id: Optional[str] = None
    ) -> ExecutionResult:
        """
        Simulate what happens when unauthorized execution is attempted.

        This is for demonstration purposes to show that:
        - Direct execution bypassing policy is blocked
        - Unauthorized actions cannot be executed
        - Security boundaries are enforced
        """
        logger.warning(
            f"Simulating unauthorized execution attempt: "
            f"{proposal.action} for {event.transaction_id}"
        )

        # This simulates what happens if someone tries to call execute()
        # without proper authorization
        result = ExecutionResult(
            executed=False,
            action=proposal.action,
            result="BLOCKED: Unauthorized execution attempt",
            error="Permission denied: Policy Engine approval required",
            timestamp=datetime.utcnow()
        )

        # Record the blocked attempt
        try:
            db.record_audit_log(
                event_type="security_alert",
                action="unauthorized_execution_attempt",
                details={
                    "transaction_id": event.transaction_id,
                    "attempted_action": proposal.action,
                    "blocked": True,
                    "reason": "Direct execution attempt without policy approval",
                    "session_id": session_id
                },
                entity_id=event.transaction_id,
                entity_type="transaction",
                user_id="attacker"
            )
        except Exception as e:
            logger.error(f"Failed to record security alert: {e}")

        return result

    def get_execution_stats(self) -> Dict[str, Any]:
        """Get execution statistics."""
        try:
            with db.get_session() as session:
                # Count execution results
                total = session.query(ExecutionResultDB).count()
                successful = session.query(ExecutionResultDB).filter(
                    ExecutionResultDB.executed == True,
                    ExecutionResultDB.error.is_(None)
                ).count()
                failed = session.query(ExecutionResultDB).filter(
                    ExecutionResultDB.executed == True,
                    ExecutionResultDB.error.isnot(None)
                ).count()
                blocked = session.query(ExecutionResultDB).filter(
                    ExecutionResultDB.executed == False
                ).count()

                # Count by action
                actions = {}
                for action in self.allowed_actions:
                    count = session.query(ExecutionResultDB).filter(
                        ExecutionResultDB.action == action
                    ).count()
                    if count > 0:
                        actions[action] = count

                return {
                    "total_executions": total,
                    "successful": successful,
                    "failed": failed,
                    "blocked": blocked,
                    "by_action": actions,
                    "success_rate": (successful / total * 100) if total > 0 else 0
                }

        except Exception as e:
            logger.error(f"Failed to get execution stats: {e}")
            return {"error": str(e)}


# Global executor instance
executor = Executor()

# Import asyncio for async methods
import asyncio