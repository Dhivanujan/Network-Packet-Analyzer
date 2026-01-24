"""Packet header analysis utilities for the Network Packet Analyzer.

This module focuses on decoding protocol headers (Ethernet, IPv4, TCP, UDP, ICMP)
from raw packets provided by scapy. It intentionally avoids any kind of payload
inspection to keep the tool aligned with ethical traffic analysis and learning.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from scapy.packet import Packet
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP, ICMP


@dataclass
class PacketSummary:
    """Light‑weight view of a packet for display, logging and detection.

    Fields focus on *metadata only* (addresses, ports, protocol, size,
    and timestamp) so that students can reason about traffic patterns and
    protocol behavior without touching application payloads.
    """

    timestamp: datetime
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: str
    length: int


def _get_protocol_name(pkt: Packet) -> str:
    """Return a human‑readable protocol name based on scapy layers.

    The order of checks roughly follows the OSI model: we first confirm that
    an IPv4 header is present, then look for transport‑layer headers such as
    TCP, UDP and ICMP.
    """

    if IP in pkt:
        if TCP in pkt:
            return "TCP"
        if UDP in pkt:
            return "UDP"
        if ICMP in pkt:
            return "ICMP"
        return "IP"
    return "OTHER"


def analyze_packet(pkt: Packet) -> Optional[PacketSummary]:
    """Extract key header fields from a scapy packet.

    Parameters
    ----------
    pkt:
        A scapy Packet instance captured from the wire.

    Returns
    -------
    PacketSummary | None
        Parsed metadata about the packet, or None if the packet does not
        contain IPv4 and is therefore skipped for simplicity.
    """

    # Link‑layer header (Ethernet) provides the frame container but we focus
    # our analysis on the network and transport layers.
    if Ether not in pkt:
        return None

    if IP not in pkt:
        # For an educational analyzer we ignore non‑IPv4 traffic to keep
        # parsing logic straightforward (no IPv6, ARP, etc.).
        return None

    ip_layer = pkt[IP]

    src_ip = ip_layer.src
    dst_ip = ip_layer.dst
    protocol = _get_protocol_name(pkt)

    src_port: Optional[int] = None
    dst_port: Optional[int] = None

    # Transport‑layer ports (TCP/UDP) are useful to understand application
    # protocols on top (e.g. HTTP on TCP/80).
    if TCP in pkt:
        tcp_layer = pkt[TCP]
        src_port = int(tcp_layer.sport)
        dst_port = int(tcp_layer.dport)
    elif UDP in pkt:
        udp_layer = pkt[UDP]
        src_port = int(udp_layer.sport)
        dst_port = int(udp_layer.dport)

    # Packet size at the IP layer, which is a close approximation of the
    # number of bytes actually carried over the network for this datagram.
    length = int(len(pkt))

    return PacketSummary(
        timestamp=datetime.now(),
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        length=length,
    )
