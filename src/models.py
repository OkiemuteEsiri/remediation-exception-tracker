from dataclasses import dataclass
from datetime import date
from enum import Enum


class LifecycleState(str, Enum):
    DRAFT = "DRAFT"
    PENDING_REVIEW = "PENDING_REVIEW"
    APPROVED = "APPROVED"
    EXPIRING = "EXPIRING"
    EXPIRED = "EXPIRED"
    REJECTED = "REJECTED"
    CLOSED = "CLOSED"


@dataclass(frozen=True)
class ExceptionRecord:
    exception_id: str
    cve: str
    severity: str
    asset_criticality: str
    internet_exposed: bool
    known_exploited: bool
    owner: str
    justification: str
    compensating_control: str
    control_strength: str
    approval_reference: str
    requested_on: date
    review_date: date
    expiry_date: date
    remediated: bool = False
    validation_evidence: str = ""
