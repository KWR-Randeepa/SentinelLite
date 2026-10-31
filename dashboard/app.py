
import sys
from pathlib import Path

import pandas as pd
import streamlit as st


# Locate the project and Python source directory.
PROJECT_ROOT = Path(__file__).resolve().parents[1]

sys.path.insert(
    0,
    str(PROJECT_ROOT / "src"),
)

from sentinellite.pipeline import run_analysis

from sentinellite.alert_manager import (
    get_alerts,
    get_alert_summary,
    update_alert_status,
)


DATABASE_FILE = PROJECT_ROOT / "data" / "sentinellite.db"


# --------------------------------------------------
# PAGE CONFIGURATION
# --------------------------------------------------

st.set_page_config(
    page_title="SentinelLite | SOC Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# --------------------------------------------------
# HEADER
# --------------------------------------------------

st.title("🛡️ SentinelLite")

st.caption(
    "Security Operations Center | Threat Monitoring & Incident Management"
)

st.info(
    "Portfolio demonstration: This dashboard analyzes "
    "sample authentication logs. It is not yet a live "
    "production monitoring system."
)


# --------------------------------------------------
# SIDEBAR
# --------------------------------------------------

st.sidebar.title("🛡️ SentinelLite")

st.sidebar.markdown("### Navigation")

page = st.sidebar.radio(
    "Select Module",
    [
        "Security Overview",
        "Security Alerts",
        "Incident Management",
    ],
)

st.sidebar.divider()

st.sidebar.markdown("### Analysis Controls")

if st.sidebar.button(
    "▶ Run Security Analysis",
    use_container_width=True,
):
    try:
        with st.spinner("Analyzing security events..."):

            result = run_analysis()

        st.sidebar.success(
            f"Analysis completed: "
            f"{result['alerts_generated']} alerts generated."
        )

        st.rerun()

    except Exception as error:

        st.sidebar.error(
            f"Analysis failed: {error}"
        )


if st.sidebar.button(
    "↻ Refresh Dashboard",
    use_container_width=True,
):
    st.rerun()


st.sidebar.divider()

st.sidebar.caption(
    "SentinelLite | Educational Cybersecurity Project"
)


# --------------------------------------------------
# LOAD ALERT DATA
# --------------------------------------------------

summary = get_alert_summary(DATABASE_FILE)

all_alerts = get_alerts(DATABASE_FILE)


# --------------------------------------------------
# SECURITY OVERVIEW
# --------------------------------------------------

if page == "Security Overview":

    st.header("Security Overview")

    st.markdown(
        "Centralized security monitoring and threat analytics."
    )

    # KPI metrics
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric(
            "Total Alerts",
            summary["total"],
        )

    with col2:
        st.metric(
            "Critical Alerts",
            summary["by_severity"]["CRITICAL"],
        )

    with col3:
        st.metric(
            "High Alerts",
            summary["by_severity"]["HIGH"],
        )

    with col4:
        open_incidents = (
            summary["by_status"]["NEW"]
            + summary["by_status"]["ACKNOWLEDGED"]
        )

        st.metric(
            "Open Incidents",
            open_incidents,
        )

    st.divider()

    # Charts
    chart_col1, chart_col2 = st.columns(2)

    with chart_col1:

        st.subheader("Alert Severity Distribution")

        severity_data = pd.DataFrame({
            "Severity": list(
                summary["by_severity"].keys()
            ),
            "Alerts": list(
                summary["by_severity"].values()
            ),
        })

        severity_data = severity_data.set_index(
            "Severity"
        )

        st.bar_chart(severity_data)

    with chart_col2:

        st.subheader("Incident Status Distribution")

        status_data = pd.DataFrame({
            "Status": list(
                summary["by_status"].keys()
            ),
            "Incidents": list(
                summary["by_status"].values()
            ),
        })

        status_data = status_data.set_index(
            "Status"
        )

        st.bar_chart(status_data)

    st.divider()

    st.subheader("Recent Security Alerts")

    if all_alerts:

        recent = all_alerts[:10]

        recent_data = pd.DataFrame([
            {
                "ID": alert["alert_id"],
                "Severity": alert["severity"],
                "Detection Rule": alert["rule_name"],
                "Source IP": alert["source_ip"],
                "Status": alert["status"],
            }
            for alert in recent
        ])

        st.dataframe(
            recent_data,
            use_container_width=True,
            hide_index=True,
        )

    else:

        st.info(
            "No security alerts available. "
            "Run Security Analysis to generate alerts."
        )


# --------------------------------------------------
# SECURITY ALERTS
# --------------------------------------------------

elif page == "Security Alerts":

    st.header("Security Alerts")

    st.caption(
        "Review, filter and investigate detected security events."
    )

    filter_col1, filter_col2 = st.columns(2)

    with filter_col1:

        severity_filter = st.selectbox(
            "Filter by Severity",
            [
                "ALL",
                "CRITICAL",
                "HIGH",
                "MEDIUM",
                "LOW",
            ],
        )

    with filter_col2:

        status_filter = st.selectbox(
            "Filter by Status",
            [
                "ALL",
                "NEW",
                "ACKNOWLEDGED",
                "RESOLVED",
            ],
        )

    filtered_alerts = get_alerts(
        DATABASE_FILE,
        severity=(
            None
            if severity_filter == "ALL"
            else severity_filter
        ),
        status=(
            None
            if status_filter == "ALL"
            else status_filter
        ),
    )

    st.write(
        f"Matching alerts: {len(filtered_alerts)}"
    )

    if filtered_alerts:

        alert_data = pd.DataFrame([
            {
                "Alert ID": alert["alert_id"],
                "Severity": alert["severity"],
                "Rule": alert["rule_name"],
                "Source IP": alert["source_ip"],
                "Source IPs": ", ".join(
                    alert["source_ips"]
                ),
                "Usernames": ", ".join(
                    alert["usernames"]
                ),
                "Failed Attempts": alert["failed_attempts"],
                "Status": alert["status"],
                "Occurrences": alert["occurrence_count"],
                "First Seen": alert["first_seen"],
                "Last Seen": alert["last_seen"],
                "Description": alert["description"],
            }
            for alert in filtered_alerts
        ])

        st.dataframe(
            alert_data,
            use_container_width=True,
            hide_index=True,
        )

        selected_alert = st.selectbox(
            "Select an alert for investigation",
            filtered_alerts,
            format_func=lambda alert: (
                f"#{alert['alert_id']} | "
                f"{alert['severity']} | "
                f"{alert['rule_name']}"
            ),
        )

        if selected_alert:

            with st.expander(
                "View Alert Investigation Details",
                expanded=True,
            ):

                st.write(
                    "**Detection rule:**",
                    selected_alert["rule_name"],
                )

                st.write(
                    "**Description:**",
                    selected_alert["description"],
                )

                st.write(
                    "**Source IP addresses:**",
                    ", ".join(selected_alert["source_ips"]),
                )

                st.write(
                    "**Affected usernames:**",
                    ", ".join(selected_alert["usernames"]),
                )

                st.write(
                    "**Current status:**",
                    selected_alert["status"],
                )

    else:

        st.info(
            "No alerts match the selected filters."
        )


# --------------------------------------------------
# INCIDENT MANAGEMENT
# --------------------------------------------------

elif page == "Incident Management":

    st.header("Incident Management")

    st.caption(
        "Manage security incidents and investigation progress."
    )

    status_col1, status_col2, status_col3 = st.columns(3)

    with status_col1:
        st.metric(
            "New",
            summary["by_status"]["NEW"],
        )

    with status_col2:
        st.metric(
            "Acknowledged",
            summary["by_status"]["ACKNOWLEDGED"],
        )

    with status_col3:
        st.metric(
            "Resolved",
            summary["by_status"]["RESOLVED"],
        )

    st.divider()

    if all_alerts:

        selected_id = st.selectbox(
            "Select Incident ID",
            [alert["alert_id"] for alert in all_alerts],
        )

        selected_record = next(
            alert
            for alert in all_alerts
            if alert["alert_id"] == selected_id
        )

        st.write(
            f"**Detection:** {selected_record['rule_name']}"
        )

        st.write(
            f"**Severity:** {selected_record['severity']}"
        )

        st.write(
            f"**Current Status:** {selected_record['status']}"
        )

        new_status = st.selectbox(
            "Update Investigation Status",
            [
                "NEW",
                "ACKNOWLEDGED",
                "RESOLVED",
            ],
            index=[
                "NEW",
                "ACKNOWLEDGED",
                "RESOLVED",
            ].index(selected_record["status"]),
        )

        if st.button(
            "Update Incident Status",
            type="primary",
        ):

            updated = update_alert_status(
                selected_id,
                new_status,
                DATABASE_FILE,
            )

            if updated:

                st.success(
                    "Incident status updated successfully."
                )

                st.rerun()

            else:

                st.error(
                    "Unable to update incident status."
                )

    else:

        st.info(
            "No incidents available for management."
        )


# --------------------------------------------------
# FOOTER
# --------------------------------------------------

st.divider()

st.caption(
    "SentinelLite | Python Security Monitoring Platform | "
    "Educational Portfolio Project"
)
