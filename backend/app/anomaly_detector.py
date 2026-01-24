"""Simple in‑memory anomaly detection for the packet analyzer backend.

This module tracks:

* total packet count
* protocol distribution
* potential port scans (many destination ports from one source)
* traffic spikes (many packets in a short time window)

It is stateful but designed for a single‑process demo environment.
"""

from __future__ import annotations

from collections import Counter, deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Deque, Dict, List, Optional, Set

from .models import AnomalyEventModel, PacketModel, StatsModel


@dataclass
class _InternalAnomaly:
    timestamp: datetime
    description: str


class AnomalyDetector:
    def __init__(
        self,
        window_seconds: int = 10,
        port_scan_threshold: int = 20,
        rate_threshold: int = 200,
    ) -> None:
        self.window_seconds = window_seconds
        self.port_scan_threshold = port_scan_threshold
        self.rate_threshold = rate_threshold

        self.total_packets: int = 0
        self.protocol_counts: Counter[str] = Counter()

        self._packet_times: Deque[datetime] = deque()
        self._ports_by_src: Dict[str, Set[int]] = {}
        self._anomalies: List[_InternalAnomaly] = []

    # ------------------------------------------------------------------

    def observe(self, pkt: PacketModel) -> Optional[AnomalyEventModel]:
        """Update internal statistics with a new packet.

        Returns an AnomalyEventModel if a new anomaly is detected,
        otherwise returns None.
        """

        self.total_packets += 1
        self.protocol_counts[pkt.protocol] += 1

        now = pkt.timestamp if isinstance(pkt.timestamp, datetime) else datetime.now()

        self._packet_times.append(now)
        cutoff = now - timedelta(seconds=self.window_seconds)
        while self._packet_times and self._packet_times[0] < cutoff:
            self._packet_times.popleft()

        new_anomaly: Optional[AnomalyEventModel] = None

        # High‑rate detection
        if len(self._packet_times) > self.rate_threshold:
            new_anomaly = self._record_anomaly(
                now,
                f"High packet rate: {len(self._packet_times)} packets "
                f"within {self.window_seconds}s window.",
            )

        # Port‑scan style behavior
        if pkt.src_ip and pkt.dst_port is not None:
            ports = self._ports_by_src.setdefault(pkt.src_ip, set())
            ports.add(pkt.dst_port)
            if len(ports) >= self.port_scan_threshold:
                new_anomaly = self._record_anomaly(
                    now,
                    "Potential port scan from "
                    f"{pkt.src_ip}: {len(ports)} unique destination ports "
                    f"within {self.window_seconds}s.",
                )

        return new_anomaly

    # ------------------------------------------------------------------

    def _record_anomaly(self, when: datetime, desc: str) -> Optional[AnomalyEventModel]:
        if self._anomalies and self._anomalies[-1].description == desc:
            return None
        internal = _InternalAnomaly(timestamp=when, description=desc)
        self._anomalies.append(internal)
        return AnomalyEventModel(timestamp=when, description=desc)

    def snapshot(self) -> StatsModel:
        return StatsModel(
            total_packets=self.total_packets,
            protocol_counts=dict(self.protocol_counts),
            anomalies=[
                AnomalyEventModel(timestamp=a.timestamp, description=a.description)
                for a in self._anomalies
            ],
        )
