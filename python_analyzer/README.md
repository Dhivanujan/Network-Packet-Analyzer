# Python Network Packet Analyzer

> Educational, ethical network monitoring tool built with Python and scapy.

## Overview

This project implements a modular network packet analyzer to help students and
junior security engineers understand how real network traffic looks on the
wire. It focuses on **header‑level metadata** – Ethernet, IPv4, TCP, UDP and
ICMP – and avoids inspecting payloads.

Key capabilities:

- Capture live packets from a chosen network interface using scapy.
- Decode and display important header fields (IP addresses, ports, protocol,
  packet size, timestamp).
- Apply simple protocol filters (TCP, UDP, ICMP, HTTP‑like ports).
- Detect basic suspicious patterns:
  - Potential port scanning attempts.
  - Abnormally high packet rates.
- Log all observed packets to a text file.
- Generate a human‑readable summary report at the end of a capture.

> **Ethical use only** – run this tool only on networks that you own or have
> explicit written permission to analyze.

## Project Structure

```text
python_analyzer/
├─ main.py              # Application entry point
├─ packet_capture.py    # Live capture helpers (interfaces, sniffing)
├─ packet_analysis.py   # Header decoding and PacketSummary model
├─ packet_filter.py     # Protocol‑level filtering helpers
├─ packet_logger.py     # Logging, statistics, anomaly detection
└─ logs/
   ├─ packets.log       # Packet‑by‑packet CSV‑style log (created at runtime)
   └─ summary_report.txt# Human‑readable summary report (created at runtime)
```

## Requirements

- Python 3.8 or newer
- Administrator/root privileges for packet capture
- Libraries:
  - scapy

On Windows you must have **Npcap** installed. On Linux and macOS, libpcap is
usually available by default.

### Install dependencies

From the `python_analyzer` directory:

```bash
pip install scapy
```

On Windows, download and install Npcap from:

- https://npcap.com/

## How to Run

From the project root:

```bash
cd python_analyzer
python -m main --help
```

Example: capture all TCP traffic on a specific interface and log to the default
location:

```bash
python -m main -i YOUR_INTERFACE_NAME -f tcp
```

If you omit `-i`, the tool will try to use scapy's default interface and, if
that fails, will show you a numbered list of interfaces to choose from.

- Press **Ctrl+C** to stop capturing.
- At exit, a summary report is written to `logs/summary_report.txt`.

### Example Output (terminal)

```text
================================================================================
 Python Network Packet Analyzer (educational use only)
================================================================================
Using interface: eth0
Logging packets to: /path/to/python_analyzer/logs/packets.log
Press Ctrl+C to stop capture and generate summary report.

[12:34:56] TCP   192.168.1.10:54231     -> 93.184.216.34:80      len=60
[12:34:56] TCP   192.168.1.10:54232     -> 93.184.216.34:80      len=60
[12:34:57] ICMP  192.168.1.10:-         -> 1.1.1.1:-             len=84
...
Capture interrupted by user.

Network Packet Analyzer Summary Report
========================================
Generated at: 2026-01-24T12:35:10

Total packets captured: 1234
Protocol‑wise packet counts:
  ICMP: 12
  TCP: 1100
  UDP: 122

Detected anomalies:
  [2026-01-24T12:34:59] Potential port scan from 192.168.1.50: 25 unique destination ports within 10s.
  [2026-01-24T12:35:03] High packet rate detected: 250 packets within 10s window.
```

## Key Networking Concepts (high‑level)

The code is heavily commented, but at a glance:

- **Ethernet (Layer 2)** – defines how frames are delivered between directly
  connected devices. scapy exposes this as the `Ether` layer.
- **IP (Layer 3)** – provides logical addressing (IPv4 addresses) so packets
  can be routed across multiple networks. Represented as the `IP` layer.
- **TCP/UDP (Layer 4)** – transport protocols using ports to identify
  application endpoints:
  - **TCP**: connection‑oriented, reliable (e.g. HTTP, HTTPS, SSH).
  - **UDP**: connectionless, best‑effort (e.g. DNS, many streaming protocols).
- **ICMP** – control and diagnostic protocol (e.g. used by `ping`).

The analyzer focuses on:

- Source/destination IP addresses.
- Source/destination ports (TCP/UDP).
- Protocol name (TCP/UDP/ICMP/IP/OTHER).
- Packet length (approximate bytes on the wire).
- Timestamp when the packet was observed.

## Ethics and Legal Notice

- Use this tool **only** on networks and systems you own or are explicitly
  authorized to monitor.
- Do **not** use it to intercept, store or inspect credentials, private
  messages, or other sensitive payloads.
- The authors and distributors of this code take no responsibility for misuse.

This project is designed as a learning aid for courses, final‑year projects,
entry‑level security work and lab environments.

---

*Ensure clean architecture, accurate protocol parsing, real‑time performance,
and beginner‑friendly explanations.*
