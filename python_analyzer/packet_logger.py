"""Logging and basic anomaly detection for the Network Packet Analyzer.

The logger stores metadata about captured packets and derives simple
statistics that help illustrate real‑world network monitoring concepts
such as protocol distribution, traffic rates, and suspicious patterns.

Suspicious patterns implemented here are intentionally *basic* and meant
for teaching only:

* Port scanning attempts: a single source IP contacting many different
  destination ports in a short time window.
* Abnormally high packet rate: more than N packets observed across the
  network within a sliding time window.
"""

from __future__ import annotations

from collections import Counter, deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Deque, Dict, List, Set

from .packet_analysis import PacketSummary


@dataclass
class AnomalyEvent:
    timestamp: datetime
    description: str


class PacketLogger:
    """Log packet metadata and compute summary statistics.

    Parameters
    ----------
    log_path:
        Text file to append human‑readable packet records to.
    port_scan_threshold:
        Number of distinct destination ports from a single source
        within the time window considered as a port scan attempt.
    rate_threshold:
        Number of packets across all sources in the window considered
        an abnormally high rate.
    window_seconds:
        Size of the sliding detection window in seconds.
    """

    def __init__(
        self,
        log_path: Path,
        port_scan_threshold: int = 20,
        rate_threshold: int = 200,
        window_seconds: int = 10,
    ) -> None:
        self.log_path = log_path
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

        self.total_packets: int = 0
        self.protocol_counts: Counter[str] = Counter()

        # Sliding‑window state used for anomaly detection.
        self.window_seconds = window_seconds
        self._packet_times: Deque[datetime] = deque()
        self._ports_by_src: Dict[str, Set[int]] = {}

        self.port_scan_threshold = port_scan_threshold
        self.rate_threshold = rate_threshold

        self.anomalies: List[AnomalyEvent] = []

        # Write header if the log file is empty.
        if not self.log_path.exists() or self.log_path.stat().st_size == 0:
            with self.log_path.open("w", encoding="utf-8") as f:
                f.write(
                    "timestamp,src_ip,src_port,dst_ip,dst_port,protocol,length\n"
                )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def log_packet(self, summary: PacketSummary) -> None:
        """Record a packet to disk and update statistics.

        Only header‑level metadata is logged so that the file can be
        safely shared in a classroom or training environment.
        """

        self.total_packets += 1
        self.protocol_counts[summary.protocol] += 1

        # Append a CSV‑style line for easy post‑processing.
        with self.log_path.open("a", encoding="utf-8") as f:
            f.write(
                f"{summary.timestamp.isoformat()},"
                f"{summary.src_ip},{summary.src_port or ''},"
                f"{summary.dst_ip},{summary.dst_port or ''},"
                f"{summary.protocol},{summary.length}\n"
            )

        self._update_detection_state(summary)

    def generate_summary_report(self, report_path: Path) -> str:
        """Persist a human‑readable summary and return it as a string."""

        lines: List[str] = []
        lines.append("Network Packet Analyzer Summary Report")
        lines.append("=" * 40)
        lines.append(f"Generated at: {datetime.now().isoformat()}")
        lines.append("")

        lines.append(f"Total packets captured: {self.total_packets}")
        lines.append("Protocol‑wise packet counts:")
        for proto, count in sorted(self.protocol_counts.items()):
            lines.append(f"  {proto}: {count}")

        lines.append("")
        lines.append("Detected anomalies:")
        if not self.anomalies:
            lines.append("  None detected in the observation window.")
        else:
            for event in self.anomalies:
                lines.append(f"  [{event.timestamp.isoformat()}] {event.description}")

        content = "\n".join(lines) + "\n"
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(content, encoding="utf-8")
        return content

    # ------------------------------------------------------------------
    # Internal helpers – anomaly detection logic
    # ------------------------------------------------------------------

    def _update_detection_state(self, summary: PacketSummary) -> None:
        now = summary.timestamp
        self._packet_times.append(now)

        # Drop timestamps that fall outside the sliding window.
        cutoff = now - timedelta(seconds=self.window_seconds)
        while self._packet_times and self._packet_times[0] < cutoff:
            self._packet_times.popleft()

        # High‑rate traffic: many packets observed in a short period.
        if len(self._packet_times) > self.rate_threshold:
            self._record_anomaly(
                now,
                f"High packet rate detected: {len(self._packet_times)} "
                f"packets within {self.window_seconds}s window.",
            )

        # Port‑scan detection: a host targets many unique destination
        # ports in the same time window. This is a simplistic heuristic
        # used to illustrate the idea rather than a production‑grade IDS.
        if summary.src_ip and summary.dst_port is not None:
            ports = self._ports_by_src.setdefault(summary.src_ip, set())
            ports.add(summary.dst_port)
            if len(ports) >= self.port_scan_threshold:
                self._record_anomaly(
                    now,
                    "Potential port scan from "
                    f"{summary.src_ip}: {len(ports)} unique destination ports "
                    f"within {self.window_seconds}s.",
                )

    def _record_anomaly(self, when: datetime, description: str) -> None:
        # Avoid recording the same description twice in a row to keep
        # reports compact and readable.
        if self.anomalies and self.anomalies[-1].description == description:
            return
        self.anomalies.append(AnomalyEvent(timestamp=when, description=description))
