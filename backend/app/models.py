"""Pydantic models shared by the API and WebSocket layer.

These models mirror the packet metadata that the analyzer exposes to
frontend clients. They intentionally avoid payload fields and focus
only on header‑level information for ethical, educational use.
"""

from __future__ import annotations

from datetime import datetime
from typing import Dict, List, Optional

from pydantic import BaseModel


class PacketModel(BaseModel):
    """Single captured packet in a JSON‑friendly form."""

    timestamp: datetime
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: str
    length: int


class AnomalyEventModel(BaseModel):
    timestamp: datetime
    description: str


class StatsModel(BaseModel):
    total_packets: int
    protocol_counts: Dict[str, int]
    anomalies: List[AnomalyEventModel]


class PacketMessage(BaseModel):
    """Envelope for messages sent over the WebSocket.

    type:
        "packet"   – new packet metadata
        "anomaly"  – anomaly event
        "stats"    – aggregate stats snapshot (optional)
    """

    type: str
    data: dict
