"""Shared result types."""
from __future__ import annotations

from dataclasses import asdict, dataclass

# status: what we observed
PASS, WARN, FAIL, INFO = "pass", "warn", "fail", "info"


@dataclass
class Finding:
    id: str
    category: str      # "Encryption", "Browser protections", "Cookies", "Domain and email"
    title: str
    status: str        # pass | warn | fail | info
    detail: str        # what was observed, in plain language
    penalty: int = 0   # points lost when status is fail (half when warn)
    severity: str = "low"   # high | medium | low
    fix: str = ""      # how to fix it
    evidence: str = ""  # raw header / value seen (untrusted, render as text)
    reference: str = ""  # link to further reading

    def to_dict(self) -> dict:
        d = asdict(self)
        d["evidence"] = d["evidence"][:600]
        return d
