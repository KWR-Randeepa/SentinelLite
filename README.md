
# SentinelLite 🛡️

### Lightweight Security Monitoring & Threat Detection Platform

SentinelLite is a Python-based cybersecurity project designed to analyze authentication logs, identify suspicious login behavior, and detect potential brute-force attacks.

The project demonstrates practical cybersecurity concepts, Python programming, security log analysis, threat detection, and automated testing.

## 🎯 Project Objectives

- Analyze authentication security logs.
- Detect repeated failed login attempts.
- Identify suspicious source IP addresses.
- Generate structured security alerts.
- Reduce false-positive detections through testing.
- Build a foundation for a lightweight SOC monitoring platform.

## 🚀 Current Features

- CSV authentication log parser.
- Structured security event model.
- IP-based brute-force detection.
- Configurable detection threshold.
- Configurable time window.
- HIGH severity security alerts.
- Automated unit testing with Pytest.

## 🛠️ Technologies

| Technology | Purpose |
|---|---|
| Python | Core application |
| Pandas | Data analysis |
| Streamlit | Planned dashboard |
| SQLite | Planned event storage |
| Pytest | Automated testing |
| Git | Version control |

## 🏗️ Project Architecture

```text
SentinelLite/
├── src/
│   └── sentinellite/
│       ├── __init__.py
│       ├── models.py
│       ├── log_parser.py
│       └── detector.py
├── dashboard/
│   └── app.py
├── rules/
├── sample_logs/
│   └── authentication.csv
├── tests/
│   └── test_detector.py
├── docs/
├── screenshots/
├── pytest.ini
├── requirements.txt
├── .gitignore
└── README.md
```

## 🔍 Detection Logic

Current detection rule:

- Event type: Login
- Status: Failed
- Threshold: 5 attempts
- Time window: 5 minutes
- Grouping: Source IP
- Alert severity: HIGH

Rule identifier:

`AUTH-BRUTE-FORCE-001`

## 💻 Installation

Clone the repository:

```bash
git clone https://github.com/YOUR-USERNAME/SentinelLite.git
cd SentinelLite
```

Create a virtual environment:

```bash
python -m venv .venv
```

Activate on Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

## 🧪 Run Tests

```bash
python -m pytest -v
```

## 🔐 Security Testing

The project currently includes automated tests for:

- Brute-force detection.
- Failed login thresholds.
- Successful login filtering.
- Time-window validation.
- Multiple source IP addresses.
- Unsorted authentication events.
- Invalid detection configurations.

## 📊 Development Roadmap

- [x] Project structure and environment setup
- [x] Security event data model
- [x] Authentication log parser
- [x] Brute-force detection engine
- [x] Automated detection tests
- [ ] Additional threat detection rules
- [ ] SQLite event storage
- [ ] Streamlit SOC dashboard
- [ ] MITRE ATT&CK mapping
- [ ] Incident reporting
- [ ] Docker deployment

## ⚠️ Disclaimer

SentinelLite is an educational cybersecurity project.

It uses synthetic security logs for testing and demonstration. It is not a replacement for enterprise SIEM platforms or production security monitoring systems.

## 👨‍💻 Author

Developed as a hands-on cybersecurity learning and portfolio project.

**Focus Areas:** Cybersecurity | Python | Blue Team | Threat Detection | Security Monitoring
