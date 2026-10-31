
import hashlib
import json
import sqlite3

from pathlib import Path
from datetime import datetime, timezone
from collections.abc import Iterable

from sentinellite.models import SecurityAlert


VALID_SEVERITIES = {
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
}

VALID_STATUSES = {
    "NEW",
    "ACKNOWLEDGED",
    "RESOLVED",
}


def get_connection(db_path: str | Path):
    """Create a SQLite database connection."""

    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    return sqlite3.connect(str(path))


def initialize_database(db_path: str | Path) -> None:
    """Create the centralized security alerts database."""

    with get_connection(db_path) as connection:

        connection.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                alert_id INTEGER PRIMARY KEY AUTOINCREMENT,
                fingerprint TEXT NOT NULL UNIQUE,
                rule_name TEXT NOT NULL,
                severity TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                source_ips TEXT NOT NULL,
                usernames TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                failed_attempts INTEGER NOT NULL,
                description TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'NEW',
                occurrence_count INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_alerts_severity
            ON alerts(severity)
        """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_alerts_status
            ON alerts(status)
        """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_alerts_last_seen
            ON alerts(last_seen)
        """)


def create_fingerprint(alert: SecurityAlert) -> str:
    """
    Generate a stable fingerprint for duplicate detection.
    """

    source_ips = sorted(set(
        alert.source_ips
        or (
            (alert.source_ip,)
            if alert.source_ip != "MULTIPLE"
            else ()
        )
    ))

    identity = {
        "rule_name": alert.rule_name,
        "source_ip": alert.source_ip,
        "source_ips": source_ips,
        "usernames": sorted(set(alert.usernames)),
    }

    serialized = json.dumps(
        identity,
        sort_keys=True,
    )

    return hashlib.sha256(
        serialized.encode("utf-8")
    ).hexdigest()


def store_alerts(
    alerts: Iterable[SecurityAlert],
    db_path: str | Path,
) -> int:
    """
    Store security alerts in SQLite.

    Repeated alerts with the same fingerprint are
    updated instead of being inserted as duplicates.

    Returns the number of alerts processed.
    """

    initialize_database(db_path)

    processed = 0

    with get_connection(db_path) as connection:

        for alert in alerts:

            severity = alert.severity.upper()

            if severity not in VALID_SEVERITIES:
                raise ValueError(
                    f"Invalid alert severity: {severity}"
                )

            source_ips = sorted(set(
                alert.source_ips
                or (
                    (alert.source_ip,)
                    if alert.source_ip != "MULTIPLE"
                    else ()
                )
            ))

            usernames = sorted(set(alert.usernames))

            fingerprint = create_fingerprint(alert)

            now = datetime.now(timezone.utc).isoformat()

            connection.execute("""
                
INSERT INTO alerts (
    fingerprint,
    rule_name,
    severity,
    source_ip,
    source_ips,
    usernames,
    first_seen,
    last_seen,
    failed_attempts,
    description,
    created_at,
    updated_at
)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)

ON CONFLICT(fingerprint) DO UPDATE SET

    first_seen = MIN(
        alerts.first_seen,
        excluded.first_seen
    ),

    last_seen = MAX(
        alerts.last_seen,
        excluded.last_seen
    ),

    failed_attempts = MAX(
        alerts.failed_attempts,
        excluded.failed_attempts
    ),

    severity = excluded.severity,
    description = excluded.description,

    occurrence_count =
        alerts.occurrence_count +
        CASE
            WHEN excluded.last_seen > alerts.last_seen
            THEN 1
            ELSE 0
        END,

    updated_at = excluded.updated_at

            """, (
                fingerprint,
                alert.rule_name,
                severity,
                alert.source_ip,
                json.dumps(source_ips),
                json.dumps(usernames),
                alert.first_seen.isoformat(),
                alert.last_seen.isoformat(),
                alert.failed_attempts,
                alert.description,
                now,
                now,
            ))

            processed += 1

    return processed


def get_alerts(
    db_path: str | Path,
    severity: str | None = None,
    status: str | None = None,
) -> list[dict]:
    """
    Retrieve alerts with optional severity and status filters.
    """

    initialize_database(db_path)

    query = "SELECT * FROM alerts"
    conditions = []
    parameters = []

    if severity is not None:

        severity = severity.upper()

        if severity not in VALID_SEVERITIES:
            raise ValueError("Invalid severity filter.")

        conditions.append("severity = ?")
        parameters.append(severity)

    if status is not None:

        status = status.upper()

        if status not in VALID_STATUSES:
            raise ValueError("Invalid status filter.")

        conditions.append("status = ?")
        parameters.append(status)

    if conditions:
        query += " WHERE " + " AND ".join(conditions)

    query += """
        ORDER BY
            CASE severity
                WHEN 'CRITICAL' THEN 0
                WHEN 'HIGH' THEN 1
                WHEN 'MEDIUM' THEN 2
                WHEN 'LOW' THEN 3
            END,
            last_seen DESC
    """

    with get_connection(db_path) as connection:

        connection.row_factory = sqlite3.Row

        rows = connection.execute(
            query,
            parameters,
        ).fetchall()

        results = []

        for row in rows:

            item = dict(row)

            item["source_ips"] = json.loads(
                item["source_ips"]
            )

            item["usernames"] = json.loads(
                item["usernames"]
            )

            results.append(item)

        return results


def update_alert_status(
    alert_id: int,
    status: str,
    db_path: str | Path,
) -> bool:
    """
    Update incident investigation status.

    Available statuses:
    NEW, ACKNOWLEDGED, RESOLVED.
    """

    status = status.upper()

    if status not in VALID_STATUSES:
        raise ValueError(
            f"Invalid incident status: {status}"
        )

    initialize_database(db_path)

    with get_connection(db_path) as connection:

        cursor = connection.execute("""
            UPDATE alerts
            SET status = ?,
                updated_at = ?
            WHERE alert_id = ?
        """, (
            status,
            datetime.now(timezone.utc).isoformat(),
            alert_id,
        ))

        return cursor.rowcount > 0


def get_alert_summary(
    db_path: str | Path,
) -> dict:
    """Return centralized alert statistics."""

    initialize_database(db_path)

    summary = {
        "total": 0,
        "by_severity": {
            severity: 0
            for severity in (
                "CRITICAL",
                "HIGH",
                "MEDIUM",
                "LOW",
            )
        },
        "by_status": {
            status: 0
            for status in VALID_STATUSES
        },
    }

    with get_connection(db_path) as connection:

        total = connection.execute(
            "SELECT COUNT(*) FROM alerts"
        ).fetchone()[0]

        summary["total"] = total

        severity_rows = connection.execute("""
            SELECT severity, COUNT(*)
            FROM alerts
            GROUP BY severity
        """).fetchall()

        for severity, count in severity_rows:
            summary["by_severity"][severity] = count

        status_rows = connection.execute("""
            SELECT status, COUNT(*)
            FROM alerts
            GROUP BY status
        """).fetchall()

        for status, count in status_rows:
            summary["by_status"][status] = count

    return summary
