
import csv
import ipaddress

from pathlib import Path
from datetime import datetime
from collections import defaultdict
from collections.abc import Iterable

from sentinellite.models import (
    SecurityEvent,
    SecurityAlert,
    IPReputation,
)


REQUIRED_COLUMNS = [
    "ip_address",
    "reputation",
    "confidence",
    "source",
    "last_seen",
]

VALID_REPUTATIONS = {
    "malicious",
    "suspicious",
    "clean",
}


def load_ip_reputation(
    csv_path: str | Path,
) -> list[IPReputation]:
    """
    Load and validate IP reputation indicators
    from a CSV intelligence database.
    """

    path = Path(csv_path)

    if not path.exists():
        raise FileNotFoundError(
            f"Threat intelligence file not found: {path}"
        )

    indicators = []
    seen_ips = set()

    with path.open(
        mode="r",
        encoding="utf-8-sig",
        newline="",
    ) as file:

        reader = csv.DictReader(file)

        if reader.fieldnames is None:
            raise ValueError("Threat intelligence CSV is empty.")

        missing_columns = [
            column
            for column in REQUIRED_COLUMNS
            if column not in reader.fieldnames
        ]

        if missing_columns:
            raise ValueError(
                f"Missing CSV columns: {missing_columns}"
            )

        for row_number, row in enumerate(reader, start=2):

            try:
                values = {
                    column: (row.get(column) or "").strip()
                    for column in REQUIRED_COLUMNS
                }

                if not all(values.values()):
                    raise ValueError(
                        "One or more required fields are empty."
                    )

                normalized_ip = str(
                    ipaddress.ip_address(values["ip_address"])
                )

                if normalized_ip in seen_ips:
                    raise ValueError(
                        f"Duplicate IP indicator: {normalized_ip}"
                    )

                reputation = values["reputation"].lower()

                if reputation not in VALID_REPUTATIONS:
                    raise ValueError(
                        f"Invalid reputation: {reputation}"
                    )

                confidence = int(values["confidence"])

                if not 0 <= confidence <= 100:
                    raise ValueError(
                        "Confidence must be between 0 and 100."
                    )

                last_seen = datetime.fromisoformat(
                    values["last_seen"]
                )

                indicator = IPReputation(
                    ip_address=normalized_ip,
                    reputation=reputation,
                    confidence=confidence,
                    source=values["source"],
                    last_seen=last_seen,
                )

                indicators.append(indicator)
                seen_ips.add(normalized_ip)

            except ValueError as error:
                raise ValueError(
                    f"Invalid intelligence data on CSV "
                    f"row {row_number}: {error}"
                ) from error

    return indicators


def analyze_ip_reputation(
    events: Iterable[SecurityEvent],
    indicators: list[IPReputation],
) -> list[SecurityAlert]:
    """
    Compare observed source IP addresses against
    the local threat intelligence database.

    Malicious IPs generate HIGH alerts.
    Suspicious IPs generate MEDIUM alerts.
    Clean and unknown IPs do not generate alerts.
    """

    reputation_by_ip = {
        indicator.ip_address: indicator
        for indicator in indicators
    }

    events_by_ip = defaultdict(list)

    for event in events:

        if event.event_type != "login":
            continue

        try:
            normalized_ip = str(
                ipaddress.ip_address(event.source_ip)
            )
        except ValueError:
            continue

        events_by_ip[normalized_ip].append(event)

    alerts = []

    for source_ip, ip_events in events_by_ip.items():

        indicator = reputation_by_ip.get(source_ip)

        if indicator is None:
            continue

        if indicator.reputation == "clean":
            continue

        severity = (
            "HIGH"
            if indicator.reputation == "malicious"
            else "MEDIUM"
        )

        usernames = tuple(sorted({
            event.username
            for event in ip_events
        }))

        failed_attempts = sum(
            1
            for event in ip_events
            if event.status == "failed"
        )

        alert = SecurityAlert(
            source_ip=source_ip,
            first_seen=min(
                event.timestamp for event in ip_events
            ),
            last_seen=max(
                event.timestamp for event in ip_events
            ),
            failed_attempts=failed_attempts,
            usernames=usernames,
            severity=severity,
            rule_name="THREAT-INTEL-IP-001",
            description=(
                f"Observed activity from {source_ip} matched "
                f"a {indicator.reputation} IP indicator. "
                f"Confidence: {indicator.confidence}%. "
                f"Intelligence source: {indicator.source}. "
                f"Observed login events: {len(ip_events)}."
            ),
            source_ips=(source_ip,),
        )

        alerts.append(alert)

    return sorted(
        alerts,
        key=lambda alert: alert.first_seen,
    )
