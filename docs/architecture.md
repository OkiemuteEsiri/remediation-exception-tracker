# Architecture

## Objective

Provide a small, auditable reference implementation for governing vulnerability remediation exceptions without connecting to production systems.

## Components

1. **Input layer** – synthetic CSV records represent exception requests and technical risk context.
2. **Domain model** – immutable typed records define required fields and lifecycle concepts.
3. **Policy validator** – enforces mandatory evidence, review/expiry chronology, maximum exception duration, and closure evidence.
4. **Risk engine** – produces an explainable 0–100 score using severity, asset criticality, exposure, known-exploited context, compensating controls, and expiry pressure.
5. **Lifecycle engine** – derives APPROVED, EXPIRING, EXPIRED, REJECTED, or CLOSED states from policy and time context.
6. **Reporting layer** – aggregates exception portfolio metrics for management review.

## Trust Boundaries

This repository intentionally has no authentication, database, scanner, ticketing, or approval-system connection. Production implementations should treat all imported records as untrusted input and should enforce RBAC, immutable audit history, schema validation, encryption, retention policy, and approved system-to-system identities.

## Design Principles

- deterministic decisions over opaque scoring;
- evidence before approval;
- expiry by default;
- technical vulnerability state remains distinct from governance state;
- closure requires validation evidence;
- synthetic fixtures permit safe testing and demonstration.
