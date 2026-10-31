
from datetime import datetime, timedelta

import pytest

from sentinellite.models import SecurityAlert

from sentinellite.alert_manager import (
    initialize_database,
    store_alerts,
    get_alerts,
    update_alert_status,
    get_alert_summary,
)


BASE_TIME = datetime(2026, 10, 31, 10, 0, 0)


def make_alert(
    source_ip="203.0.113.10",
    severity="HIGH",
    rule_name="AUTH-BRUTE-FORCE-001",
    username="admin",
):

    return SecurityAlert(
        source_ip=source_ip,
        first_seen=BASE_TIME,
        last_seen=BASE_TIME + timedelta(minutes=5),
        failed_attempts=5,
        usernames=(username,),
        severity=severity,
        rule_name=rule_name,
        description="Test security alert",
    )


def test_initialize_database(tmp_path):

    db = tmp_path / "alerts.db"

    initialize_database(db)

    summary = get_alert_summary(db)

    assert summary["total"] == 0


def test_store_and_retrieve_alert(tmp_path):

    db = tmp_path / "alerts.db"

    alert = make_alert()

    processed = store_alerts([alert], db)

    results = get_alerts(db)

    assert processed == 1
    assert len(results) == 1
    assert results[0]["severity"] == "HIGH"
    assert results[0]["status"] == "NEW"
    assert results[0]["rule_name"] == "AUTH-BRUTE-FORCE-001"


def test_duplicate_alerts_are_merged(tmp_path):

    db = tmp_path / "alerts.db"

    alert = make_alert()

    store_alerts([alert], db)
    store_alerts([alert], db)

    results = get_alerts(db)

    assert len(results) == 1
    assert results[0]["occurrence_count"] == 2


def test_filter_alerts_by_severity(tmp_path):

    db = tmp_path / "alerts.db"

    alerts = [
        make_alert(
            source_ip="203.0.113.10",
            severity="HIGH",
        ),
        make_alert(
            source_ip="198.51.100.20",
            severity="MEDIUM",
            username="user2",
        ),
    ]

    store_alerts(alerts, db)

    results = get_alerts(
        db,
        severity="HIGH",
    )

    assert len(results) == 1
    assert results[0]["severity"] == "HIGH"


def test_update_alert_status(tmp_path):

    db = tmp_path / "alerts.db"

    store_alerts([make_alert()], db)

    results = get_alerts(db)

    alert_id = results[0]["alert_id"]

    updated = update_alert_status(
        alert_id,
        "ACKNOWLEDGED",
        db,
    )

    assert updated is True
    assert get_alerts(db)[0]["status"] == "ACKNOWLEDGED"


def test_invalid_status_should_raise_error(tmp_path):

    db = tmp_path / "alerts.db"

    with pytest.raises(ValueError):

        update_alert_status(
            1,
            "INVALID",
            db,
        )


def test_invalid_severity_should_raise_error(tmp_path):

    db = tmp_path / "alerts.db"

    invalid_alert = make_alert(
        severity="UNKNOWN",
    )

    with pytest.raises(ValueError):

        store_alerts([invalid_alert], db)


def test_alert_summary(tmp_path):

    db = tmp_path / "alerts.db"

    alerts = [
        make_alert(
            source_ip="203.0.113.10",
            severity="HIGH",
        ),
        make_alert(
            source_ip="198.51.100.20",
            severity="MEDIUM",
            username="user2",
        ),
        make_alert(
            source_ip="192.0.2.30",
            severity="CRITICAL",
            username="user3",
        ),
    ]

    store_alerts(alerts, db)

    summary = get_alert_summary(db)

    assert summary["total"] == 3
    assert summary["by_severity"]["HIGH"] == 1
    assert summary["by_severity"]["MEDIUM"] == 1
    assert summary["by_severity"]["CRITICAL"] == 1
    assert summary["by_status"]["NEW"] == 3
