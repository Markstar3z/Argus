from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Service:
    port: int
    protocol: str
    name: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None


@dataclass
class Asset:
    ip: str
    status: str = "unknown"
    mac: Optional[str] = None
    hostname: Optional[str] = None
    services: list[Service] = field(default_factory=list)
