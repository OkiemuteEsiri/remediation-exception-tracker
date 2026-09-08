# Governance Methodology

## Decision Standard

A remediation exception is a temporary, documented risk decision. It must not be used to hide vulnerabilities, alter scanner evidence, or imply that technical risk has been removed.

## Required Evidence

Every request should include:

- accountable owner;
- affected vulnerability or control condition;
- business justification;
- compensating control;
- approval reference;
- review date;
- expiry date;
- technical context sufficient to assess severity and exposure.

## Review Workflow

1. Validate record completeness and chronology.
2. Confirm the vulnerability remains technically present.
3. Assess asset criticality and external exposure.
4. Confirm whether credible exploitation evidence exists.
5. Evaluate compensating-control strength.
6. Assign risk score/tier.
7. Escalate high/critical requests according to policy.
8. Approve only for a bounded period.
9. Review before expiry.
10. Close only after remediation evidence is independently revalidated.

## Exception Ageing

Long-duration exceptions represent accumulating security debt. This reference policy caps a single request at 180 days. A production program may use stricter thresholds by severity or asset class.

## Metrics

Useful governance metrics include total active exceptions, expiring in 30 days, expired exceptions, invalid requests, critical-risk exceptions, median exception duration, repeat renewals, and closure validation success rate.

## Risk Communication

The score is a prioritization aid, not a mathematical prediction of breach probability. Reviewers should retain the underlying evidence so the decision remains explainable and auditable.
