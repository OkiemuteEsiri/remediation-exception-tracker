import unittest
from datetime import date
from src.models import ExceptionRecord, LifecycleState
from src.tracker import lifecycle_state, risk_score, risk_tier


class TrackerTests(unittest.TestCase):
    def record(self, **overrides):
        values = dict(
            exception_id="EX-100", cve="CVE-2099-0100", severity="CRITICAL",
            asset_criticality="CRITICAL", internet_exposed=True, known_exploited=True,
            owner="platform-team", justification="Synthetic vendor dependency",
            compensating_control="Isolation", control_strength="MODERATE",
            approval_reference="APR-100", requested_on=date(2026, 7, 1),
            review_date=date(2026, 8, 1), expiry_date=date(2026, 10, 1),
            remediated=False, validation_evidence="",
        )
        values.update(overrides)
        return ExceptionRecord(**values)

    def test_high_context_record_scores_critical(self):
        score = risk_score(self.record(), date(2026, 9, 15))
        self.assertEqual(risk_tier(score), "CRITICAL")

    def test_expiring_state(self):
        state = lifecycle_state(self.record(), date(2026, 9, 15))
        self.assertEqual(state, LifecycleState.EXPIRING)

    def test_expired_state(self):
        state = lifecycle_state(self.record(), date(2026, 10, 2))
        self.assertEqual(state, LifecycleState.EXPIRED)

    def test_closed_requires_evidence(self):
        record = self.record(remediated=True, validation_evidence="Synthetic rescan: condition absent")
        self.assertEqual(lifecycle_state(record, date(2026, 9, 15)), LifecycleState.CLOSED)

    def test_strong_control_reduces_score(self):
        weak = risk_score(self.record(control_strength="WEAK"), date(2026, 9, 1))
        strong = risk_score(self.record(control_strength="STRONG"), date(2026, 9, 1))
        self.assertLess(strong, weak)


if __name__ == "__main__":
    unittest.main()
