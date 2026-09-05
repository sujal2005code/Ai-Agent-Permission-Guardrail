"""
Pytest configuration and fixtures for the test suite.
"""

import pytest
import sys
from pathlib import Path

# Add the project root to the Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))


@pytest.fixture(scope="session")
def project_root_path():
    """Return the project root directory."""
    return Path(__file__).parent.parent


@pytest.fixture(scope="session")
def test_data_dir(project_root_path):
    """Return the test data directory."""
    return project_root_path / "data"


@pytest.fixture(scope="function")
def clean_database():
    """Clean database before and after each test."""
    from app.database.database import db

    # Setup: ensure database is initialized
    db.health_check()

    yield db

    # Teardown: cleanup is handled by the database module


@pytest.fixture(scope="function")
def sample_payment_event():
    """Create a sample payment event for testing."""
    from app.policy.models import PaymentEvent, TransactionStatus

    return PaymentEvent(
        transaction_id="TXN-TEST-001",
        amount=850.00,
        currency="INR",
        status=TransactionStatus.FAILED,
        failure_reason="network_timeout",
        customer_history={"previous_failures": 0},
        metadata={"payment_method": "credit_card"},
        customer_note="Please retry this payment",
        possible_fraud=False
    )


@pytest.fixture(scope="function")
def sample_proposal():
    """Create a sample AI proposal for testing."""
    from app.policy.models import AIProposal

    return AIProposal(
        action="retry_payment",
        confidence=0.92,
        reasoning="Temporary network timeout with healthy payment history suggests retrying."
    )


@pytest.fixture(scope="function")
def sample_approved_decision():
    """Create a sample approved policy decision."""
    from app.policy.models import PolicyDecisionModel, PolicyDecision, RiskLevel

    return PolicyDecisionModel(
        decision=PolicyDecision.APPROVED,
        rule_triggered=None,
        reason="All policy checks passed",
        risk_score=15,
        risk_level=RiskLevel.LOW
    )


@pytest.fixture(scope="function")
def sample_rejected_decision():
    """Create a sample rejected policy decision."""
    from app.policy.models import PolicyDecisionModel, PolicyDecision, PolicyRule, RiskLevel

    return PolicyDecisionModel(
        decision=PolicyDecision.REJECTED,
        rule_triggered=PolicyRule.MIN_CONFIDENCE_THRESHOLD,
        reason="Confidence below threshold",
        risk_score=45,
        risk_level=RiskLevel.MEDIUM
    )


@pytest.fixture(scope="function")
def sample_escalated_decision():
    """Create a sample escalated policy decision."""
    from app.policy.models import PolicyDecisionModel, PolicyDecision, PolicyRule, RiskLevel

    return PolicyDecisionModel(
        decision=PolicyDecision.ESCALATED,
        rule_triggered=PolicyRule.MAX_AUTO_APPROVE_AMOUNT,
        reason="Amount exceeds auto-approval limit",
        risk_score=65,
        risk_level=RiskLevel.HIGH
    )


@pytest.fixture
def mock_proposer():
    """Create a mock proposer for testing."""
    from app.proposer.mock_proposer import MockProposer
    return MockProposer()


@pytest.fixture
def policy_engine():
    """Create a policy engine for testing."""
    from app.policy.engine import PolicyEngine
    return PolicyEngine()


@pytest.fixture
def executor():
    """Get the executor instance for testing."""
    from app.executor.executor import executor as exec_instance
    return exec_instance
