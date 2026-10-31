
from pathlib import Path

from sentinellite.log_parser import load_events
from sentinellite.detector import (
    detect_brute_force,
    detect_password_spraying,
    detect_distributed_brute_force,
    detect_suspicious_login_after_failures,
)
from sentinellite.threat_intel import (
    load_ip_reputation,
    analyze_ip_reputation,
)
from sentinellite.alert_manager import (
    store_alerts,
    get_alert_summary,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]

LOG_FILE = PROJECT_ROOT / "sample_logs" / "authentication.csv"

INTEL_FILE = PROJECT_ROOT / "sample_logs" / "ip_reputation.csv"

DATABASE_FILE = PROJECT_ROOT / "data" / "sentinellite.db"


def run_analysis() -> dict:
    """
    Execute all SentinelLite detection engines
    and centralize the resulting security alerts.
    """

    # Step 1: Load authentication events.
    events = load_events(LOG_FILE)

    # Step 2: Load threat intelligence.
    indicators = load_ip_reputation(INTEL_FILE)

    # Step 3: Execute all detection engines.
    alerts = []

    alerts.extend(detect_brute_force(events))

    alerts.extend(detect_password_spraying(events))

    alerts.extend(detect_distributed_brute_force(events))

    alerts.extend(
        detect_suspicious_login_after_failures(events)
    )

    alerts.extend(
        analyze_ip_reputation(events, indicators)
    )

    # Step 4: Store alerts in the central database.
    processed = store_alerts(
        alerts,
        DATABASE_FILE,
    )

    # Step 5: Generate summary.
    summary = get_alert_summary(DATABASE_FILE)

    return {
        "events_processed": len(events),
        "indicators_loaded": len(indicators),
        "alerts_generated": len(alerts),
        "alerts_processed": processed,
        "summary": summary,
        "database": str(DATABASE_FILE),
    }
