# Remediation Exception Tracker

A recruiter-facing vulnerability governance project for managing remediation exceptions as controlled, time-bound risk decisions rather than permanent vulnerability suppressions.

## Problem

Security teams frequently need temporary exceptions when a vulnerability cannot be remediated immediately because of application compatibility, operational dependencies, vendor constraints, or approved business risk. Poorly governed exceptions can become invisible security debt.

This project demonstrates a defensive workflow that:

- normalizes exception requests;
- validates required governance evidence;
- assigns risk tiers from vulnerability and asset context;
- enforces expiry and review windows;
- identifies overdue, expiring, and invalid exceptions;
- tracks compensating controls;
- produces management metrics and validation artifacts.

All sample records are synthetic. No employer, client, production asset, credential, or confidential information is used.

## Architecture

```text
Synthetic Requests
      |
      v
Request Parser --> Policy Validator --> Risk Engine
                                      |
                                      v
                               Lifecycle Engine
                                      |
                         +------------+-------------+
                         |                          |
                         v                          v
                  Analyst Findings           KPI / Report
                         |                          |
                         +------------+-------------+
                                      v
                            Remediation Validation
```

## Repository Structure

```text
src/
  models.py       typed exception model and lifecycle states
  policy.py       governance policy and validation rules
  tracker.py      risk/lifecycle evaluation engine
  reporting.py    portfolio metrics and reporting

data/
  synthetic_exceptions.csv
tests/
  test_policy.py
  test_tracker.py
docs/
  architecture.md
  governance-methodology.md
  remediation-validation.md
reports/
  example-executive-report.md
.github/workflows/
  tests.yml
```

## Governance Model

An exception is considered valid only when the request has an accountable owner, business justification, compensating control, approval reference, review date, and expiry date. The engine also checks temporal consistency and whether the exception has exceeded configurable maximum duration.

Risk classification combines:

- vulnerability severity;
- asset criticality;
- internet exposure;
- known-exploited status;
- compensating-control strength;
- time remaining before expiry.

The model is intentionally transparent and deterministic so that security reviewers can explain why a request receives a specific risk classification.

## Lifecycle States

`DRAFT -> PENDING_REVIEW -> APPROVED -> EXPIRING -> EXPIRED -> CLOSED`

Invalid evidence can place a request in `REJECTED`. Closure requires remediation or documented risk retirement plus validation evidence.

## Example Usage

```bash
python -m src.reporting data/synthetic_exceptions.csv
python -m unittest discover -s tests -v
```

## Example Output

```text
Exception portfolio: 6
Approved/active: 2
Expiring <= 30 days: 1
Expired: 1
Policy-invalid: 1
Critical-risk exceptions: 1
```

## Security Engineering Controls

- explicit ownership and accountability;
- time-bounded exceptions;
- maximum-duration policy;
- approval and evidence requirements;
- compensating-control documentation;
- high-risk escalation;
- expiry monitoring;
- remediation revalidation before closure;
- metrics that expose accumulated security debt.

## Validation Philosophy

An exception does **not** change the technical state of a vulnerability. It changes how risk is governed for a limited period. When remediation is reported complete, the underlying condition should be revalidated using the authoritative security control or scanner before the exception is closed.

## MITRE ATT&CK Context

This project is defensive governance rather than adversary emulation. ATT&CK technique mappings should be attached to exception records when they materially improve risk communication. For example, exposed identity weaknesses may relate to Valid Accounts (`T1078`) and externally exposed services may increase Initial Access opportunities (`T1190`). Mapping is contextual and is not used as a substitute for vulnerability severity or exploitability evidence.

## Skills Demonstrated

- vulnerability management governance;
- risk acceptance and exception lifecycle design;
- Python security automation;
- policy-as-code concepts;
- security metrics and reporting;
- remediation validation;
- test-driven defensive engineering;
- auditable risk communication.

## Limitations

This is a synthetic engineering portfolio project, not a production GRC platform. It does not integrate with ticketing systems, scanners, identity providers, or approval platforms. Authentication, persistence, RBAC, notification delivery, and enterprise audit logging would be required for production use.

## Roadmap

- JSON schema validation;
- configurable policy profiles;
- ServiceNow/Jira-style adapter interfaces using mock clients;
- exception ageing trends;
- signed approval evidence model;
- dashboard export;
- richer ATT&CK/context enrichment;
- automated revalidation adapters using synthetic fixtures.

## Safe Use

Use only synthetic, lab, or properly authorized data. Never place credentials, sensitive vulnerability exports, customer information, or production exception records in this repository.
