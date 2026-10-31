#  SentinelLite
### Lightweight Security Monitoring & Threat Detection Platform

**SentinelLite** is a Python-based security monitoring prototype designed to analyze authentication logs, identify suspicious login activity, detect common authentication attacks, and manage security alerts through a centralized SOC dashboard.

Built as a hands-on cybersecurity portfolio project, SentinelLite demonstrates practical Blue Team concepts, security event analysis, threat intelligence, incident management, and automated testing.

##  Key Features

### Threat Detection
- Brute-force attack detection
- Password spraying detection
- Distributed brute-force detection
- Suspicious login sequence detection
- IP reputation analysis

### Security Alert Management
- Centralized alert collection
- Severity classification
- Duplicate alert handling
- SQLite-based alert storage
- Incident status tracking
- Alert filtering and investigation

### SOC Dashboard
- Security overview and KPI metrics
- Alert severity visualization
- Incident status monitoring
- Security alert investigation
- Incident status management

##  Technology Stack

| Technology | Purpose |
|---|---|
| Python | Core development |
| Pandas | Data analysis |
| Streamlit | SOC dashboard |
| SQLite | Alert storage |
| Pytest | Automated testing |
| Git & GitHub | Version control |

##  Project Architecture

```text
SentinelLite/
│
├── .streamlit/
│   └── config.toml
│
├── dashboard/
│   └── app.py
│
├── src/
│   └── sentinellite/
│       ├── models.py
│       ├── log_parser.py
│       ├── detector.py
│       ├── threat_intel.py
│       ├── alert_manager.py
│       └── pipeline.py
│
├── sample_logs/
│   ├── authentication.csv
│   └── ip_reputation.csv
│
├── tests/
│   ├── test_detector.py
│   └── test_alert_manager.py
│
├── data/
├── docs/
├── screenshots/
│
├── requirements.txt
├── pytest.ini
├── .gitignore
└── README.md
```

## 🔍 Detection Capabilities

| Detection Rule | Description |
|---|---|
| AUTH-BRUTE-FORCE-001 | Repeated failed login attempts |
| AUTH-PASSWORD-SPRAY-001 | Multiple accounts targeted from one IP |
| AUTH-DISTRIBUTED-BRUTE-FORCE-001 | Multiple IPs targeting one account |
| AUTH-SUSPICIOUS-LOGIN-AFTER-FAILURES-001 | Successful login following repeated failures |
| THREAT-INTEL-IP-001 | IP reputation matching |

##  Installation & Setup

### 1. Clone the repository

```bash
git clone https://github.com/KWR-Randeepa/SentinelLite.git
cd SentinelLite
```

### 2. Create a virtual environment

```bash
python -m venv .venv
```

### 3. Activate the environment (Windows)

```powershell
.\.venv\Scripts\Activate.ps1
```

### 4. Install dependencies

```bash
python -m pip install -r requirements.txt
```

### 5. Run automated tests

```bash
python -m pytest -v
```

### 6. Launch the SOC dashboard

```bash
python -m streamlit run dashboard/app.py
```

Open:

```text
http://localhost:8501
```

##  Security Monitoring Workflow

1. Load authentication logs from CSV.
2. Parse and validate security events.
3. Execute threat detection algorithms.
4. Compare observed IPs against local reputation indicators.
5. Generate structured security alerts.
6. Store and manage alerts using SQLite.
7. Investigate incidents through the Streamlit dashboard.

##  Testing

SentinelLite uses Pytest to validate:

- Detection thresholds
- Time-window calculations
- Multiple source IP analysis
- Username-based attack detection
- Suspicious login sequences
- IP reputation validation
- Duplicate alert handling
- Alert filtering and status updates

##  Screenshots

Dashboard screenshots will be added to the `screenshots/` directory.

Planned screenshots:
- Security overview
- Security alerts
- Incident management

##  Limitations

SentinelLite is an educational cybersecurity prototype.

- Uses CSV-based batch log analysis.
- Uses a simulated local IP reputation dataset.
- Does not currently provide continuous live monitoring.
- Does not replace enterprise SIEM platforms.
- Detection alerts are investigation indicators, not proof of compromise.

##  Learning Objectives

This project demonstrates practical experience with:

- Cybersecurity fundamentals
- Blue Team security monitoring
- Authentication log analysis
- Threat detection engineering
- IP reputation analysis
- Security alert management
- Python application development
- Database integration
- Automated software testing


Cybersecurity Enthusiast

GitHub: https://github.com/KWR-Randeepa

