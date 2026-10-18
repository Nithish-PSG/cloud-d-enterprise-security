from dataclasses import dataclass, field
from typing import Any


@dataclass
class DataRecord:
    """One in-memory record stored by a simulated cloud node.

    Uploaded row contents stay inside the local Python process. API responses
    intentionally expose record counts and opaque IDs only.
    """

    id: str
    record_type: str
    value: int
    owner: str
    is_compromised: bool = False
    source: str = "seeded"
    payload: dict[str, Any] = field(default_factory=dict, repr=False)
    content: bytes = field(default=b"", repr=False)

    def compromise(self) -> None:
        self.is_compromised = True

    def restore(self) -> None:
        self.is_compromised = False
