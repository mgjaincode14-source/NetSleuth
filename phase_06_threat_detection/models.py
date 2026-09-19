"""
NetSleuth AI - Phase 6 Threat Detection Models & Data Structures
"""

import time
import uuid
from enum import IntEnum
from dataclasses import dataclass, field, asdict
from typing import Dict, Any, Optional


class Severity(IntEnum):
    INFO = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5

    def __str__(self) -> str:
        return self.name

    @property
    def label(self) -> str:
        return self.name


@dataclass
class Alert:
    rule_id: str
    rule_name: str
    severity: Severity
    src_ip: str
    dst_ip: str
    dst_port: Optional[int] = None
    protocol: str = "UNKNOWN"
    details: Dict[str, Any] = field(default_factory=dict)
    recommendation: str = ""
    timestamp: float = field(default_factory=time.time)
    alert_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.name
        return data


class ThreatRule:
    """Base class for all rule-based threat detection logic."""

    rule_id: str = "RULE_BASE"
    rule_name: str = "Base Threat Rule"
    default_severity: Severity = Severity.INFO
    cooldown_seconds: float = 5.0

    def evaluate(self, packet: Dict[str, Any], state: Dict[str, Any]) -> Optional[Alert]:
        """
        Evaluate a single packet against current state.
        Returns an Alert if a threat condition is met, else None.
        """
        raise NotImplementedError("Subclasses must implement evaluate()")
