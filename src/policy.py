from dataclasses import dataclass
from datetime import date
from .models import ExceptionRecord


@dataclass(frozen=True)
class PolicyResult:
    valid: bool
    findings: tuple[str, ...]


MAX_DURATION_DAYS = 180
REQUIRED_TEXT_FIELDS = (
    "owner",
    "justification",
    "compensating_control",
    "approval_reference",
)


def validate_policy(record: ExceptionRecord) -> PolicyResult:
    findings: list[str] = []

    for field in REQUIRED_TEXT_FIELDS:
        if not getattr(record, field).strip():
            findings.append(f"missing_{field}")

    if record.review_date < record.requested_on:
        findings.append("review_before_request")
    if record.expiry_date <= record.requested_on:
        findings.append("expiry_not_after_request")
    if record.review_date > record.expiry_date:
        findings.append("review_after_expiry")

    duration = (record.expiry_date - record.requested_on).days
    if duration > MAX_DURATION_DAYS:
        findings.append("duration_exceeds_policy")

    if record.remediated and not record.validation_evidence.strip():
        findings.append("remediation_missing_validation_evidence")

    return PolicyResult(valid=not findings, findings=tuple(findings))


def days_to_expiry(record: ExceptionRecord, as_of: date) -> int:
    return (record.expiry_date - as_of).days
