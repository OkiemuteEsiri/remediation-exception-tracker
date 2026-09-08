import csv
import sys
from datetime import date, datetime
from .models import ExceptionRecord
from .tracker import evaluate


def _bool(value: str) -> bool:
    return value.strip().lower() in {"true", "1", "yes", "y"}


def _date(value: str) -> date:
    return datetime.strptime(value, "%Y-%m-%d").date()


def load_records(path: str) -> list[ExceptionRecord]:
    records: list[ExceptionRecord] = []
    with open(path, newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            records.append(ExceptionRecord(
                exception_id=row["exception_id"], cve=row["cve"], severity=row["severity"],
                asset_criticality=row["asset_criticality"], internet_exposed=_bool(row["internet_exposed"]),
                known_exploited=_bool(row["known_exploited"]), owner=row["owner"],
                justification=row["justification"], compensating_control=row["compensating_control"],
                control_strength=row["control_strength"], approval_reference=row["approval_reference"],
                requested_on=_date(row["requested_on"]), review_date=_date(row["review_date"]),
                expiry_date=_date(row["expiry_date"]), remediated=_bool(row["remediated"]),
                validation_evidence=row["validation_evidence"],
            ))
    return records


def summarize(records: list[ExceptionRecord], as_of: date) -> dict:
    evaluated = [evaluate(record, as_of) for record in records]
    return {
        "total": len(evaluated),
        "active": sum(x["state"] == "APPROVED" for x in evaluated),
        "expiring": sum(x["state"] == "EXPIRING" for x in evaluated),
        "expired": sum(x["state"] == "EXPIRED" for x in evaluated),
        "closed": sum(x["state"] == "CLOSED" for x in evaluated),
        "policy_invalid": sum(not x["policy_valid"] for x in evaluated),
        "critical_risk": sum(x["risk_tier"] == "CRITICAL" for x in evaluated),
    }


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: python -m src.reporting <csv-path>")
    records = load_records(sys.argv[1])
    metrics = summarize(records, date.today())
    for key, value in metrics.items():
        print(f"{key}: {value}")
