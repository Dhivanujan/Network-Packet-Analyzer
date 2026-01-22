📡 Network Packet Analyzer
📌 Project Overview

The Network Packet Analyzer is a networking tool designed to capture, inspect, and analyze network traffic in real time. It decodes packets at multiple layers of the OSI model and provides meaningful insights such as protocol distribution, traffic statistics, and detection of suspicious network behavior.

This project demonstrates a strong understanding of computer networking fundamentals, packet-level analysis, and network security concepts.

🎯 Objectives

Capture live network packets from a network interface
Decode and analyze packets at different protocol layers
Filter traffic based on protocol, IP, and ports
Generate traffic statistics and summaries
Detect abnormal or suspicious traffic patterns
Export captured data for offline analysis

🛠️ Features

📥 Live Packet Capture
🔍 Protocol Decoding (TCP, UDP, ICMP, HTTP, DNS)
🎯 Packet Filtering
📊 Traffic Statistics & Analysis
🚨 Suspicious Traffic Detection
💾 PCAP / CSV Export
🖥️ CLI-based Interface (Optional GUI extension)

🧠 How It Works

The analyzer listens to a selected network interface.
Incoming packets are captured using packet sniffing libraries.
Raw packet data is decoded into readable protocol information.
Filters are applied to display relevant packets.
Traffic statistics are generated and displayed.
Abnormal traffic patterns trigger alerts.
Data can be saved for later analysis.

🧰 Technologies Used

Programming Language: Python
Libraries & Tools:
Scapy
Libpcap / Npcap
Socket Programming
Protocols Analyzed:
TCP
UDP
ICMP
HTTP
DNS