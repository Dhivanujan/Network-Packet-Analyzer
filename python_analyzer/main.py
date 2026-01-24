"""Entry point for the Python Network Packet Analyzer.

This script wires together live capture, header analysis, protocol
filtering, logging, basic anomaly detection and a real‑time terminal
view of network packets.

The analyzer is intentionally conservative: it only looks at protocol
metadata (headers) and never inspects application payloads, making it
suitable for ethical learning and monitoring on networks you own or are
explicitly allowed to analyze.
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

from scapy.packet import Packet

from .packet_analysis import PacketSummary, analyze_packet
from .packet_capture import capture_packets, list_interfaces, guess_default_interface
from .packet_filter import packet_matches_filter
from .packet_logger import PacketLogger


def _print_banner() -> None:
    print("=" * 80)
    print(" Python Network Packet Analyzer (educational use only)")
    print("=" * 80)


def _parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Capture and analyze live network packets using scapy. "
            "Use only on networks you own or are authorized to monitor."
        )
    )

    parser.add_argument(
        "-i",
        "--interface",
        help="Network interface to capture from. If omitted, a default is used when possible.",
    )
    parser.add_argument(
        "-f",
        "--filter",
        choices=["tcp", "udp", "icmp", "http"],
        help="Protocol filter to apply at analysis level.",
    )
    parser.add_argument(
        "-b",
        "--bpf",
        help=(
            "Optional BPF capture filter (e.g. 'tcp', 'udp', 'icmp'). "
            "This is passed directly to libpcap/Npcap."
        ),
    )
    parser.add_argument(
        "-l",
        "--log-file",
        default="logs/packets.log",
        help="Path to the packet log file (default: logs/packets.log).",
    )
    parser.add_argument(
        "-r",
        "--report-file",
        default="logs/summary_report.txt",
        help="Path to the summary report written at exit.",
    )
    parser.add_argument(
        "--port-scan-threshold",
        type=int,
        default=20,
        help="Unique destination ports from one source in window to flag a port scan.",
    )
    parser.add_argument(
        "--rate-threshold",
        type=int,
        default=200,
        help="Packets in window to flag abnormally high packet rate.",
    )
    parser.add_argument(
        "--window-seconds",
        type=int,
        default=10,
        help="Sliding window size in seconds for anomaly detection.",
    )

    return parser.parse_args(argv)


def _select_interface(cli_interface: Optional[str]) -> str:
    if cli_interface:
        return cli_interface

    default = guess_default_interface()
    if default:
        return str(default)

    interfaces = list(list_interfaces())
    if not interfaces:
        raise RuntimeError("No capture interfaces found.")

    print("Available interfaces:")
    for idx, name in enumerate(interfaces):
        print(f"  [{idx}] {name}")

    while True:
        choice = input("Select interface index: ").strip()
        if not choice.isdigit():
            print("Please enter a numeric index.")
            continue
        index = int(choice)
        if 0 <= index < len(interfaces):
            return interfaces[index]
        print("Index out of range. Try again.")


def _format_summary_line(summary: PacketSummary) -> str:
    timestamp = summary.timestamp.strftime("%H:%M:%S")
    src = f"{summary.src_ip}:{summary.src_port or '-'}"
    dst = f"{summary.dst_ip}:{summary.dst_port or '-'}"
    return (
        f"[{timestamp}] {summary.protocol:<5} {src:<22} -> {dst:<22} "
        f"len={summary.length}"
    )


def run(argv: Optional[list[str]] = None) -> int:
    _print_banner()

    args = _parse_args(argv)
    try:
        interface = _select_interface(args.interface)
    except RuntimeError as exc:
        print(f"Error: {exc}")
        return 1

    base_dir = Path(__file__).resolve().parent
    log_path = (base_dir / args.log_file).resolve()
    report_path = (base_dir / args.report_file).resolve()

    logger = PacketLogger(
        log_path=log_path,
        port_scan_threshold=args.port_scan_threshold,
        rate_threshold=args.rate_threshold,
        window_seconds=args.window_seconds,
    )

    print(f"Using interface: {interface}")
    print(f"Logging packets to: {log_path}")
    print("Press Ctrl+C to stop capture and generate summary report.\n")

    def handle_packet(pkt: Packet) -> None:
        summary = analyze_packet(pkt)
        if summary is None:
            return

        if not packet_matches_filter(summary, args.filter):
            return

        logger.log_packet(summary)
        print(_format_summary_line(summary))

    try:
        capture_packets(
            interface=interface,
            packet_handler=handle_packet,
            bpf_filter=args.bpf,
            count=0,
        )
    except KeyboardInterrupt:
        # User requested a graceful shutdown.
        print("\nCapture interrupted by user.")
    except PermissionError:
        print(
            "Permission error: capturing packets typically requires administrator/root "
            "rights. Try running the script with elevated privileges."
        )
        return 1
    except Exception as exc:  # pragma: no cover - defensive catch‑all
        print(f"Unexpected error during capture: {exc}")
        return 1

    print("\nGenerating summary report...")
    summary_text = logger.generate_summary_report(report_path)
    print(summary_text)
    print(f"Summary report written to: {report_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(run(sys.argv[1:]))
