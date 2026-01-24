"""Simple protocol‑level filters for the Network Packet Analyzer.

Filters operate on PacketSummary instances and never inspect payloads.
This keeps the tool safe and focused on protocol behavior.
"""

from typing import Optional

from .packet_analysis import PacketSummary

# Common TCP ports used by HTTP‑based traffic.
_HTTP_PORTS = {80, 8080, 8000, 443}


def is_tcp(summary: PacketSummary) -> bool:
    return summary.protocol.upper() == "TCP"


def is_udp(summary: PacketSummary) -> bool:
    return summary.protocol.upper() == "UDP"


def is_icmp(summary: PacketSummary) -> bool:
    return summary.protocol.upper() == "ICMP"


def is_http(summary: PacketSummary) -> bool:
    """Best‑effort HTTP classification based on well‑known ports.

    This is intentionally simple: we assume that traffic using a common
    HTTP/HTTPS port is HTTP‑like. Deep packet inspection is deliberately
    avoided for ethical reasons.
    """

    if not is_tcp(summary):
        return False

    ports = {summary.src_port, summary.dst_port}
    return any(p in _HTTP_PORTS for p in ports if p is not None)


def packet_matches_filter(summary: PacketSummary, protocol_filter: Optional[str]) -> bool:
    """Return True if the packet matches the requested protocol filter.

    Parameters
    ----------
    summary:
        Packet metadata to test.
    protocol_filter:
        One of {"tcp", "udp", "icmp", "http"} or None for no filtering.
    """

    if protocol_filter is None:
        return True

    pf = protocol_filter.lower()
    if pf == "tcp":
        return is_tcp(summary)
    if pf == "udp":
        return is_udp(summary)
    if pf == "icmp":
        return is_icmp(summary)
    if pf == "http":
        return is_http(summary)

    # Unknown filter string -> fail closed by excluding the packet.
    return False
