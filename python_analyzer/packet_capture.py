"""Live packet capture utilities built on top of scapy.

This module abstracts away the scapy sniffing calls and provides
simple helpers for listing interfaces and capturing traffic from a
selected interface.
"""

from typing import Callable, Iterable, Optional

from scapy.all import sniff, get_if_list, conf
from scapy.packet import Packet


def list_interfaces() -> Iterable[str]:
    """Return the list of capture interfaces detected by scapy.

    On Windows, this typically maps to Npcap interfaces. On Linux and
    macOS, these are standard OS network interfaces (e.g. eth0, wlan0).
    """

    return get_if_list()


def guess_default_interface() -> Optional[str]:
    """Return scapy's idea of the default interface, if available."""

    try:
        return conf.iface  # type: ignore[no-any-return]
    except Exception:
        return None


def capture_packets(
    interface: str,
    packet_handler: Callable[[Packet], None],
    bpf_filter: Optional[str] = None,
    count: int = 0,
) -> None:
    """Start a blocking capture loop on the given interface.

    Parameters
    ----------
    interface:
        OS/network interface name to listen on.
    packet_handler:
        Callback invoked for every captured packet.
    bpf_filter:
        Optional Berkeley Packet Filter (BPF) expression understood by
        libpcap/Npcap (e.g. "tcp", "udp", "icmp").
    count:
        Number of packets to capture. A value of 0 means "run until
        interrupted".

    Notes
    -----
    * Capturing usually requires administrative/root privileges.
    * On Windows you must install Npcap; on Linux and macOS libpcap is
      typically available out of the box.
    """

    sniff(
        iface=interface,
        prn=packet_handler,
        filter=bpf_filter,
        store=False,
        count=count,
    )
