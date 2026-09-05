"""
Audit logging system.

This module provides comprehensive audit logging for the entire system.
Every action, decision, and execution is recorded for accountability and traceability.

Key Principle: The Audit Log remembers everything.
"""

import json
import logging
from datetime import datetime
from typing import Dict, Any, Optional, List
from uuid import uuid4
from enum import Enum

from app.policy.models import PaymentEvent, AIProposal, PolicyDecisionModel, ExecutionResult
from app.database.database import db
from app.database.models import AuditLog as AuditLogDB

logger = logging.getLogger(__name__)


class AuditEventType(str, Enum):
    """Types of audit events."""

    # AI Events
    AI_PROPOSAL = "ai_proposal"
    AI_PROPOSAL_FAILED = "ai_proposal_failed"

    # Policy Events
    POLICY_EVALUATION = "policy_evaluation"
    POLICY_DECISION = "policy_decision"

    # Execution Events
    EXECUTION_ATTEMPT = "execution_attempt"
    EXECUTION_SUCCESS = "execution_success"
    EXECUTION_FAILED = "execution_failed"
    EXECUTION_BLOCKED = "execution_blocked"

    # Security Events
    UNAUTHORIZED_ATTEMPT = "unauthorized_attempt"
    POLICY_VIOLATION = "policy_violation"
    SECURITY_ALERT = "security_alert"

    # System Events
    SYSTEM_STARTUP = "system_startup"
    SYSTEM_SHUTDOWN = "system_shutdown"
    CONFIG_CHANGE = "config_change"

    # Review Events
    REVIEW_CREATED = "review_created"
    REVIEW_RESOLVED = "review_resolved"


class AuditLogger:
    """Main audit logger for the system."""

    def __init__(self):
        """Initialize audit logger."""
        self.session_id = str(uuid4())[:8]  # Short session ID for correlation
        logger.info(f"AuditLogger initialized with session ID: {self.session_id}")

    def log_proposal(
        self,
        event: PaymentEvent,
        proposal: Optional[AIProposal] = None,
        error: Optional[str] = None,
        proposer_name: Optional[str] = None,
        user_id: Optional[str] = None,
        ip_address: Optional[str] = None
    ) -> str:
        """Log AI proposal generation."""
        event_type = AuditEventType.AI_PROPOSAL_FAILED if error else AuditEventType.AI_PROPOSAL

        details = {
            "transaction_id": event.transaction_id,
            "amount": event.amount,
            "currency": event.currency,
            "status": event.status.value,
            "proposer": proposer_name,
            "session_id": self.session_id
        }

        if proposal:
            details.update({
                "proposed_action": proposal.action,
                "confidence": proposal.confidence,
                "reasoning_length": len(proposal.reasoning)
            })

        if error:
            details["error"] = error

        # Sanitize customer note (untrusted input)
        if event.customer_note:
            details["customer_note_present"] = True
            details["customer_note_length"] = len(event.customer_note)
            # Don't log actual content as it may contain sensitive data or injection attempts

        log_id = self._record_log(
            event_type=event_type.value,
            action="generate_proposal",
            details=details,
            entity_id=event.transaction_id,
            entity_type="transaction",
            user_id=user_id,
            ip_address=ip_address
        )

        logger.info(f"Logged proposal for {event.transaction_id}: {event_type.value}")
        return log_id

    def log_policy_decision(
        self,
        event: PaymentEvent,
        proposal: AIProposal,
        decision: PolicyDecisionModel,
        user_id: Optional[str] = None,
        ip_address: Optional[str] = None
    ) -> str:
        """Log policy decision."""
        details = {
            "transaction_id": event.transaction_id,
            "amount": event.amount,
            "proposed_action": proposal.action,
            "confidence": proposal.confidence,
            "decision": decision.decision.value,
            "rule_triggered": decision.rule_triggered.value if decision.rule_triggered else None,
            "risk_score": decision.risk_score,
            "risk_level": decision.risk_level.value,
            "reason": decision.reason,
            "session_id": self.session_id
        }

        log_id = self._record_log(
            event_type=AuditEventType.POLICY_DECISION.value,
            action="evaluate_policy",
            details=details,
            entity_id=event.transaction_id,
            entity_type="transaction",
            user_id=user_id,
            ip_address=ip_address
        )

        logger.info(f"Logged policy decision for {event.transaction_id}: {decision.decision.value}")
        return log_id

    def log_execution(
        self,
        event: PaymentEvent,
        proposal: AIProposal,
        decision: PolicyDecisionModel,
        execution_result: ExecutionResult,
        user_id: Optional[str] = None,
        ip_address: Optional[str] = None
    ) -> str:
        """Log execution attempt."""
        if not execution_result.executed:
            event_type = AuditEventType.EXECUTION_BLOCKED
        elif execution_result.error:
            event_type = AuditEventType.EXECUTION_FAILED
        else:
            event_type = AuditEventType.EXECUTION_SUCCESS

        details = {
            "transaction_id": event.transaction_id,
            "action": execution_result.action,
            "policy_decision": decision.decision.value,
            "executed": execution_result.executed,
            "result": execution_result.result,
            "error": execution_result.error,
            "timestamp": execution_result.timestamp.isoformat() if execution_result.timestamp else None,
            "session_id": self.session_id
        }

        log_id = self._record_log(
            event_type=event_type.value,
            action="execute_action",
            details=details,
            entity_id=event.transaction_id,
            entity_type="transaction",
            user_id=user_id,
            ip_address=ip_address
        )

        logger.info(f"Logged execution for {event.transaction_id}: {event_type.value}")
        return log_id

    def log_unauthorized_attempt(
        self,
        event: PaymentEvent,
        attempted_action: str,
        reason: str,
        user_id: Optional[str] = None,
        ip_address: Optional[str] = None
    ) -> str:
        """Log unauthorized execution attempt."""
        details = {
            "transaction_id": event.transaction_id,
            "attempted_action": attempted_action,
            "reason": reason,
            "blocked": True,
            "session_id": self.session_id
        }

        log_id = self._record_log(
            event_type=AuditEventType.UNAUTHORIZED_ATTEMPT.value,
            action="unauthorized_execution_attempt",
            details=details,
            entity_id=event.transaction_id,
            entity_type="transaction",
            user_id=user_id,
            ip_address=ip_address
        )

        logger.warning(f"Logged unauthorized attempt for {event.transaction_id}: {attempted_action}")
        return log_id

    def log_security_alert(
        self,
        alert_type: str,
        description: str,
        severity: str = "medium",
        related_entity_id: Optional[str] = None,
        related_entity_type: Optional[str] = None,
        user_id: Optional[str] = None,
        ip_address: Optional[str] = None
    ) -> str:
        """Log security alert."""
        details = {
            "alert_type": alert_type,
            "description": description,
            "severity": severity,
            "session_id": self.session_id,
            "timestamp": datetime.utcnow().isoformat()
        }

        log_id = self._record_log(
            event_type=AuditEventType.SECURITY_ALERT.value,
            action="security_alert",
            details=details,
            entity_id=related_entity_id,
            entity_type=related_entity_type,
            user_id=user_id,
            ip_address=ip_address
        )

        logger.warning(f"Logged security alert: {alert_type} - {description}")
        return log_id

    def log_system_event(
        self,
        event_type: AuditEventType,
        action: str,
        details: Dict[str, Any],
        user_id: Optional[str] = None,
        ip_address: Optional[str] = None
    ) -> str:
        """Log system-level event."""
        if "session_id" not in details:
            details["session_id"] = self.session_id

        log_id = self._record_log(
            event_type=event_type.value,
            action=action,
            details=details,
            user_id=user_id,
            ip_address=ip_address
        )

        logger.info(f"Logged system event: {event_type.value} - {action}")
        return log_id

    def _record_log(
        self,
        event_type: str,
        action: str,
        details: Dict[str, Any],
        entity_id: Optional[str] = None,
        entity_type: Optional[str] = None,
        user_id: Optional[str] = None,
        ip_address: Optional[str] = None
    ) -> str:
        """Record audit log entry."""
        try:
            log_id = str(uuid4())

            # Sanitize details - remove any sensitive information
            sanitized_details = self._sanitize_details(details)

            db.record_audit_log(
                event_type=event_type,
                entity_id=entity_id,
                entity_type=entity_type,
                action=action,
                details=sanitized_details,
                user_id=user_id,
                ip_address=ip_address
            )

            return log_id

        except Exception as e:
            logger.error(f"Failed to record audit log: {e}")
            # Still log to application logs as fallback
            logger.warning(f"Audit fallback - {event_type}: {action} - {details}")
            return f"error-{datetime.utcnow().timestamp()}"

    def _sanitize_details(self, details: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitize audit log details to remove sensitive information."""
        sanitized = details.copy()

        # Remove any potential secrets
        sensitive_keys = ["api_key", "secret", "password", "token", "key"]
        for key in list(sanitized.keys()):
            key_lower = key.lower()
            if any(sensitive in key_lower for sensitive in sensitive_keys):
                sanitized[key] = "[REDACTED]"

        # Truncate long values
        for key, value in sanitized.items():
            if isinstance(value, str) and len(value) > 1000:
                sanitized[key] = value[:1000] + "..."

        return sanitized

    def get_audit_trail(
        self,
        transaction_id: Optional[str] = None,
        event_type: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Get audit trail with filtering options."""
        try:
            return db.get_recent_audit_logs(limit)
        except Exception as e:
            logger.error(f"Failed to get audit trail: {e}")
            return []

    def export_audit_logs(
        self,
        format: str = "json",
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None
    ) -> Optional[str]:
        """Export audit logs in specified format."""
        try:
            logs = self.get_audit_trail(start_time=start_time, end_time=end_time, limit=1000)

            if format.lower() == "json":
                return json.dumps(logs, indent=2, default=str)
            elif format.lower() == "csv":
                # Simple CSV export
                if not logs:
                    return ""

                # Get all unique keys
                all_keys = set()
                for log in logs:
                    all_keys.update(log.keys())

                headers = sorted(all_keys)
                csv_lines = [",".join(headers)]

                for log in logs:
                    row = []
                    for header in headers:
                        value = log.get(header, "")
                        if isinstance(value, (dict, list)):
                            value = json.dumps(value)
                        row.append(str(value).replace(",", ";").replace("\n", " "))
                    csv_lines.append(",".join(row))

                return "\n".join(csv_lines)
            else:
                raise ValueError(f"Unsupported format: {format}")

        except Exception as e:
            logger.error(f"Failed to export audit logs: {e}")
            return None

    def get_statistics(self) -> Dict[str, Any]:
        """Get audit log statistics."""
        try:
            with db.get_session() as session:
                # Count by event type
                from sqlalchemy import func
                stats = session.query(
                    AuditLogDB.event_type,
                    func.count(AuditLogDB.id).label('count')
                ).group_by(AuditLogDB.event_type).all()

                event_type_counts = {event_type: count for event_type, count in stats}

                # Total count
                total = sum(event_type_counts.values())

                # Recent activity
                last_24h = session.query(AuditLogDB).filter(
                    AuditLogDB.timestamp > datetime.utcnow() - timedelta(hours=24)
                ).count()

                return {
                    "total_logs": total,
                    "logs_last_24h": last_24h,
                    "by_event_type": event_type_counts,
                    "session_id": self.session_id,
                    "database_path": db.db_path
                }

        except Exception as e:
            logger.error(f"Failed to get audit statistics: {e}")
            return {"error": str(e)}


# Global audit logger instance
audit_logger = AuditLogger()

# Import timedelta for time calculations
from datetime import timedelta