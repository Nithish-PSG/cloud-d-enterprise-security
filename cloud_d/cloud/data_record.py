from dataclasses import dataclass, field
from typing import Any


@dataclass
class DataRecord:
    """A compact simulation record; uploaded source rows remain in encrypted storage."""

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
