"""Packet header analysis utilities for the FastAPI backend.

This module converts raw scapy packets into PacketModel instances that
can safely be sent to the frontend.
"""

from __future__ import annotations

from typing import Optional

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether
from scapy.packet import Packet

from .models import PacketModel


def _protocol_name(pkt: Packet) -> str:
    if IP in pkt:
        if TCP in pkt:
            return "TCP"
        if UDP in pkt:
            return "UDP"
        if ICMP in pkt:
            return "ICMP"
        return "IP"
    return "OTHER"


def analyze_packet(pkt: Packet) -> Optional[PacketModel]:
    """Extract high‑level metadata from a scapy packet.

    Non‑IPv4 packets are ignored to keep the demo compact.
    """

    if Ether not in pkt or IP not in pkt:
        return None

    ip = pkt[IP]
    src_ip = ip.src
    dst_ip = ip.dst
    protocol = _protocol_name(pkt)

    src_port = None
    dst_port = None

    if TCP in pkt:
        tcp = pkt[TCP]
        src_port = int(tcp.sport)
        dst_port = int(tcp.dport)
    elif UDP in pkt:
        udp = pkt[UDP]
        src_port = int(udp.sport)
        dst_port = int(udp.dport)

    length = int(len(pkt))

    return PacketModel(
        timestamp=pkt.time,  # scapy timestamp (float seconds) is handled by Pydantic
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        length=length,
    )
