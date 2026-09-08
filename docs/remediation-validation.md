# Remediation Validation Playbook

## Purpose

Ensure an exception is closed because the underlying condition was actually remediated, not merely because a ticket was updated.

## Validation Sequence

1. Identify the authoritative finding and affected synthetic asset identifier.
2. Confirm the remediation change was implemented.
3. Re-run the appropriate authoritative validation source in an approved environment.
4. Verify the original vulnerable condition is absent.
5. Check for replacement or regression findings introduced by the change.
6. Attach validation evidence or a reference to immutable evidence storage.
7. Mark the exception remediated only after evidence is available.
8. Transition to CLOSED and retain the historical decision record.

## Evidence Quality

Strong evidence is reproducible and independently attributable to the affected condition. Examples include a clean rescan, compliant configuration check, patched package/version inventory, or defensive control validation. A free-text statement such as "fixed" is insufficient.

## Failed Validation

If the condition remains present, keep the exception open, document the failed validation, reassess compensating controls, and review the remaining exception period. Expired exceptions should be escalated rather than silently renewed.

## Safety

This portfolio uses synthetic evidence only. Production evidence may contain sensitive hostnames, vulnerability details, identities, or operational metadata and should remain in approved enterprise systems.
