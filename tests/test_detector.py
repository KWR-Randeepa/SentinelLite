
from datetime import datetime, timedelta

import pytest

from sentinellite.models import SecurityEvent
from sentinellite.detector import (
    detect_brute_force,
    detect_password_spraying,
)


BASE_TIME = datetime(2026, 10, 31, 10, 0, 0)


def make_event(
    minutes,
    source_ip="203.0.113.10",
    status="failed",
    event_type="login",
    username="admin",
):
    return SecurityEvent(
        timestamp=BASE_TIME + timedelta(minutes=minutes),
        username=username,
        source_ip=source_ip,
        event_type=event_type,
        status=status,
    )


def test_detect_brute_force_attack():
    events = [
        make_event(0),
        make_event(1),
        make_event(2),
        make_event(3),
        make_event(4),
    ]

    alerts = detect_brute_force(events)

    assert len(alerts) == 1
    assert alerts[0].severity == "HIGH"
    assert alerts[0].failed_attempts == 5


def test_four_failed_attempts_should_not_trigger_alert():
    events = [
        make_event(0),
        make_event(1),
        make_event(2),
        make_event(3),
    ]

    alerts = detect_brute_force(events)

    assert len(alerts) == 0


def test_successful_logins_should_not_trigger_alert():
    events = [
        make_event(i, status="success")
        for i in range(5)
    ]

    alerts = detect_brute_force(events)

    assert len(alerts) == 0


def test_attempts_outside_time_window_should_not_alert():
    events = [
        make_event(0),
        make_event(1),
        make_event(2),
        make_event(3),
        make_event(6),
    ]

    alerts = detect_brute_force(events)

    assert len(alerts) == 0


def test_different_ips_should_be_analyzed_separately():
    events = [
        make_event(i, source_ip="203.0.113.10")
        for i in range(3)
    ]

    events += [
        make_event(
            i,
            source_ip="198.51.100.20"
        )
        for i in range(3)
    ]

    alerts = detect_brute_force(events)

    assert len(alerts) == 0


def test_non_login_events_should_be_ignored():
    events = [
        make_event(i, event_type="logout")
        for i in range(5)
    ]

    alerts = detect_brute_force(events)

    assert len(alerts) == 0


def test_unsorted_events_should_still_be_detected():
    events = [
        make_event(4),
        make_event(0),
        make_event(3),
        make_event(1),
        make_event(2),
    ]

    alerts = detect_brute_force(events)

    assert len(alerts) == 1


def test_invalid_threshold_should_raise_error():
    with pytest.raises(ValueError):
        detect_brute_force([], threshold=1)


def test_invalid_time_window_should_raise_error():
    with pytest.raises(ValueError):
        detect_brute_force([], window_minutes=0)


def test_detect_password_spraying():
    events = [
        make_event(i, username=f"user{i}")
        for i in range(5)
    ]

    alerts = detect_password_spraying(events)

    assert len(alerts) == 1
    assert alerts[0].severity == "HIGH"
    assert alerts[0].failed_attempts == 5
    assert len(alerts[0].usernames) == 5
    assert alerts[0].rule_name == "AUTH-PASSWORD-SPRAY-001"


def test_four_unique_usernames_should_not_trigger_alert():
    events = [
        make_event(i, username=f"user{i}")
        for i in range(4)
    ]

    alerts = detect_password_spraying(events)

    assert len(alerts) == 0


def test_repeated_same_username_should_not_trigger_spraying():
    events = [
        make_event(i, username="admin")
        for i in range(6)
    ]

    alerts = detect_password_spraying(events)

    assert len(alerts) == 0


def test_password_spraying_outside_time_window():
    events = [
        make_event(i, username=f"user{i}")
        for i in [0, 2, 4, 6, 12]
    ]

    alerts = detect_password_spraying(events)

    assert len(alerts) == 0


def test_successful_logins_should_not_trigger_spraying():
    events = [
        make_event(
            i,
            username=f"user{i}",
            status="success"
        )
        for i in range(5)
    ]

    alerts = detect_password_spraying(events)

    assert len(alerts) == 0
