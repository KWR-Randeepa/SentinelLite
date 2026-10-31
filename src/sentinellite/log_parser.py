
import csv
from pathlib import Path
from datetime import datetime

from sentinellite.models import SecurityEvent


REQUIRED_COLUMNS = [
    "timestamp",
    "username",
    "source_ip",
    "event_type",
    "status",
]


def load_events(csv_path: str | Path) -> list[SecurityEvent]:
    """
    Read authentication events from a CSV file
    and convert them into SecurityEvent objects.
    """

    path = Path(csv_path)

    if not path.exists():
        raise FileNotFoundError(
            f"Security log file not found: {path}"
        )

    events = []

    with path.open(
        mode="r",
        encoding="utf-8-sig",
        newline=""
    ) as file:

        reader = csv.DictReader(file)

        if reader.fieldnames is None:
            raise ValueError("CSV file is empty.")

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

                event = SecurityEvent(
                    timestamp=datetime.fromisoformat(
                        values["timestamp"]
                    ),
                    username=values["username"],
                    source_ip=values["source_ip"],
                    event_type=values["event_type"].lower(),
                    status=values["status"].lower(),
                )

                events.append(event)

            except ValueError as error:
                raise ValueError(
                    f"Invalid data on CSV row {row_number}: {error}"
                ) from error

    return events
