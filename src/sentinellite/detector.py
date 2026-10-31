
from collections import defaultdict
from datetime import timedelta
from collections.abc import Iterable

from sentinellite.models import SecurityEvent, SecurityAlert


def detect_brute_force(
    events: Iterable[SecurityEvent],
    threshold: int = 5,
    window_minutes: int = 5,
) -> list[SecurityAlert]:
    """
    Detect repeated failed login attempts from the same IP.

    Default rule:
    5 or more failed login attempts within 5 minutes.
    """

    if threshold < 2:
        raise ValueError("Threshold must be at least 2.")

    if window_minutes <= 0:
        raise ValueError("Window must be greater than 0.")

    failed_by_ip = defaultdict(list)

    # Group failed login events by source IP.
    for event in events:
        if (
            event.event_type == "login"
            and event.status == "failed"
        ):
            failed_by_ip[event.source_ip].append(event)

    alerts = []
    time_window = timedelta(minutes=window_minutes)

    # Analyze each source IP independently.
    for source_ip, ip_events in failed_by_ip.items():

        ip_events.sort(key=lambda event: event.timestamp)

        left = 0

        for right, current_event in enumerate(ip_events):

            # Remove events outside the time window.
            while (
                current_event.timestamp
                - ip_events[left].timestamp
                > time_window
            ):
                left += 1

            attempts = right - left + 1

            if attempts >= threshold:

                # Capture all events in the first qualifying window.
                window_start = ip_events[left].timestamp
                window_end = window_start + time_window

                matched_events = [
                    event
                    for event in ip_events[left:]
                    if event.timestamp <= window_end
                ]

                usernames = tuple(sorted({
                    event.username
                    for event in matched_events
                }))

                alert = SecurityAlert(
                    source_ip=source_ip,
                    first_seen=matched_events[0].timestamp,
                    last_seen=matched_events[-1].timestamp,
                    failed_attempts=len(matched_events),
                    usernames=usernames,
                    severity="HIGH",
                    rule_name="AUTH-BRUTE-FORCE-001",
                    description=(
                        f"Detected {len(matched_events)} failed "
                        f"login attempts from {source_ip} "
                        f"within {window_minutes} minutes."
                    ),
                )

                alerts.append(alert)

                # Generate only one alert per IP per analysis.
                break

    return sorted(
        alerts,
        key=lambda alert: alert.first_seen
    )
