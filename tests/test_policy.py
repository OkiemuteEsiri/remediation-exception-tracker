import unittest
from datetime import date
from src.models import ExceptionRecord
from src.policy import validate_policy


class PolicyTests(unittest.TestCase):
    def base(self, **overrides):
        values = dict(
            exception_id="EX-001", cve="CVE-2099-0001", severity="HIGH",
            asset_criticality="HIGH", internet_exposed=False, known_exploited=False,
            owner="security-owner", justification="Legacy dependency pending upgrade",
            compensating_control="Network isolation and EDR monitoring", control_strength="STRONG",
            approval_reference="APR-001", requested_on=date(2026, 9, 1),
            review_date=date(2026, 10, 1), expiry_date=date(2026, 12, 1),
            remediated=False, validation_evidence="",
        )
        values.update(overrides)
        return ExceptionRecord(**values)

    def test_valid_record_passes(self):
        self.assertTrue(validate_policy(self.base()).valid)

    def test_missing_owner_rejected(self):
        result = validate_policy(self.base(owner=""))
        self.assertFalse(result.valid)
        self.assertIn("missing_owner", result.findings)

    def test_duration_over_180_days_rejected(self):
        result = validate_policy(self.base(expiry_date=date(2027, 6, 1)))
        self.assertIn("duration_exceeds_policy", result.findings)

    def test_remediation_requires_validation(self):
        result = validate_policy(self.base(remediated=True))
        self.assertIn("remediation_missing_validation_evidence", result.findings)


if __name__ == "__main__":
    unittest.main()
