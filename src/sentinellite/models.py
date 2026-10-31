
from dataclasses import dataclass
from datetime import datetime


@dataclass
class SecurityEvent:
    timestamp: datetime
    username: str
    source_ip: str
    event_type: str
    status: str


@dataclass
class SecurityAlert:
    source_ip: str
    first_seen: datetime
    last_seen: datetime
    failed_attempts: int
    usernames: tuple[str, ...]
    severity: str
    rule_name: str
    description: str
    source_ips: tuple[str, ...] = ()