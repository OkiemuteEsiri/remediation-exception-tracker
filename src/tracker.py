from datetime import date
from .models import ExceptionRecord, LifecycleState
from .policy import validate_policy, days_to_expiry

SEVERITY_WEIGHT = {"LOW": 5, "MEDIUM": 15, "HIGH": 30, "CRITICAL": 45}
CRITICALITY_WEIGHT = {"LOW": 0, "MEDIUM": 8, "HIGH": 15, "CRITICAL": 22}
CONTROL_REDUCTION = {"WEAK": 0, "MODERATE": 8, "STRONG": 15}


def risk_score(record: ExceptionRecord, as_of: date) -> int:
    score = SEVERITY_WEIGHT.get(record.severity.upper(), 10)
    score += CRITICALITY_WEIGHT.get(record.asset_criticality.upper(), 8)
    score += 12 if record.internet_exposed else 0
    score += 18 if record.known_exploited else 0
    score -= CONTROL_REDUCTION.get(record.control_strength.upper(), 0)

    remaining = days_to_expiry(record, as_of)
    if remaining < 0:
        score += 15
    elif remaining <= 30:
        score += 8

    return max(0, min(100, score))


def risk_tier(score: int) -> str:
    if score >= 75:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"


def lifecycle_state(record: ExceptionRecord, as_of: date) -> LifecycleState:
    policy = validate_policy(record)
    if not policy.valid:
        return LifecycleState.REJECTED
    if record.remediated and record.validation_evidence.strip():
        return LifecycleState.CLOSED
    remaining = days_to_expiry(record, as_of)
    if remaining < 0:
        return LifecycleState.EXPIRED
    if remaining <= 30:
        return LifecycleState.EXPIRING
    return LifecycleState.APPROVED


def evaluate(record: ExceptionRecord, as_of: date) -> dict:
    policy = validate_policy(record)
    score = risk_score(record, as_of)
    return {
        "exception_id": record.exception_id,
        "state": lifecycle_state(record, as_of).value,
        "risk_score": score,
        "risk_tier": risk_tier(score),
        "days_to_expiry": days_to_expiry(record, as_of),
        "policy_valid": policy.valid,
        "policy_findings": list(policy.findings),
    }
