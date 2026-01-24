"""Background packet capture using scapy for the FastAPI backend.

Capture runs in a separate daemon thread and forwards analyzed packets
into an asyncio queue that the WebSocket broadcaster consumes.
"""

from __future__ import annotations

import asyncio
import threading
from typing import Callable, Optional

from scapy.all import sniff, get_if_list, conf
from scapy.packet import Packet

from .models import PacketModel
from .packet_analysis import analyze_packet


def list_interfaces() -> list[str]:
    """Return a list of interface names detected by scapy."""

    return list(get_if_list())


def default_interface() -> Optional[str]:
    try:
        return str(conf.iface)
    except Exception:
        return None


def start_capture(
    packet_queue: "asyncio.Queue[PacketModel]",
    interface: Optional[str] = None,
    bpf_filter: Optional[str] = None,
) -> threading.Thread:
    """Start packet capture in a background thread.

    Parameters
    ----------
    packet_queue:
        Asyncio queue where analyzed PacketModel instances will be
        scheduled for delivery.
    interface:
        Name of the OS interface to capture from. If None, scapy's
        default interface is used.
    bpf_filter:
        Optional BPF expression (e.g. "tcp", "udp", "icmp").
    """

    loop = asyncio.get_event_loop()

    def _handle_raw(pkt: Packet) -> None:
        model = analyze_packet(pkt)
        if model is None:
            return
        # Schedule a put_nowait on the event loop from this worker thread.
        loop.call_soon_threadsafe(packet_queue.put_nowait, model)

    def _worker() -> None:
        sniff(
            iface=interface or default_interface(),
            prn=_handle_raw,
            store=False,
            filter=bpf_filter,
        )

    thread = threading.Thread(target=_worker, name="packet-capture", daemon=True)
    thread.start()
    return thread
