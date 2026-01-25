📡 Network Packet Analyzer – Full‑Stack

This project is a full‑stack, educational **Network Packet Analyzer** with a
Python backend and a React dashboard frontend.

It is designed for learning and ethical monitoring only, focusing strictly on
packet **headers** (Ethernet/IP/TCP/UDP/ICMP) and simple anomaly detection.

---

## Architecture Overview

- **Backend** – Python 3, FastAPI, scapy
	- Captures live packets from a chosen network interface using scapy.
	- Decodes Ethernet, IPv4, TCP, UDP, ICMP headers.
	- Maintains in‑memory traffic statistics and anomaly detection:
		- Port‑scan–style behavior (many destination ports from one source).
		- Traffic spikes (many packets in a sliding time window).
	- Exposes:
		- REST API for health checks, interfaces, and stats.
		- WebSocket `/ws/packets` for real‑time packet + anomaly streaming.

- **Frontend** – React + Vite
	- Real‑time packet table (source/destination IP & ports, protocol, size, time).
	- Protocol filter buttons (TCP / UDP / ICMP / HTTP / ALL).
	- Live traffic chart (protocol distribution).
	- Alert panel for suspicious activity.
	- Clean, responsive dashboard layout.

Folder layout (top level):

```text
backend/           # FastAPI + scapy backend
frontend/          # React + Vite dashboard
python_analyzer/   # Optional standalone CLI analyzer (Python only)
README.md
```

---

## Backend – Python / FastAPI

### Tech Stack

- Python 3.9+
- FastAPI
- Uvicorn
- scapy

### Key Files

- `backend/app/main.py` – FastAPI app, REST endpoints, WebSocket `/ws/packets`.
- `backend/app/packet_capture.py` – scapy capture in a background thread.
- `backend/app/packet_analysis.py` – decodes headers into JSON‑friendly models.
- `backend/app/anomaly_detector.py` – tracks stats and detects basic anomalies.
- `backend/app/models.py` – Pydantic models used in the API/WebSocket.

### Running the Backend

1. Create and activate a virtual environment (recommended).
2. Install dependencies:

```bash
cd backend
pip install -r requirements.txt
```

3. (Optional) Choose capture interface via environment variables:

```bash
set CAPTURE_INTERFACE=Ethernet0   # Windows example
set CAPTURE_BPF_FILTER=tcp        # optional: only capture TCP
```

4. Start the API server:

```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

5. Open the interactive docs (FastAPI):

- http://localhost:8000/docs

Endpoints:

- `GET /api/health` – health check.
- `GET /api/interfaces` – list detected interfaces + default.
- `GET /api/stats` – total packets, protocol counts, anomalies.
- `WS /ws/packets` – WebSocket stream of packets and anomalies.

> On Windows, install **Npcap**; on Linux/macOS, libpcap is usually
> available out of the box. Capturing typically requires administrator/root
> privileges.

---

## Frontend – React Dashboard

### Tech Stack

- React 18
- Vite

### Running the Frontend

```bash
cd frontend
npm install
npm run dev
```

By default Vite runs on `http://localhost:5173` and connects to the backend at
`http://localhost:8000` and `ws://localhost:8000/ws/packets`.

You can override these with environment variables in `frontend/.env`:

```bash
VITE_API_BASE=http://localhost:8000
VITE_WS_URL=ws://localhost:8000/ws/packets
```

### UI Features

- **Real‑time packet table**
	- Time, source IP:port, destination IP:port, protocol, size.
- **Protocol filters**
	- Buttons for `ALL`, `TCP`, `UDP`, `ICMP`, `HTTP`.
- **Live traffic chart**
	- Simple bar chart of protocol‑wise packet counts.
- **Alert panel**
	- Shows anomaly events (potential port scans, spikes).

---

## Example End‑to‑End Workflow

1. Start backend (packet capture + API):

```bash
cd backend
uvicorn app.main:app --reload --port 8000
```

2. Start frontend dashboard:

```bash
cd ../frontend
npm install
npm run dev
```

3. Open the dashboard in your browser:

- http://localhost:5173

4. Generate some traffic (web browsing, `ping`, etc.).
5. Watch packets, protocol distribution, and alerts update in real time.

---

## Optional CLI Analyzer (python_analyzer/)

In addition to the full‑stack app, this repo includes a standalone,
terminal‑based packet analyzer in `python_analyzer/`.

### Quick Start (CLI)

```bash
cd python_analyzer
pip install scapy  # and ensure Npcap/libpcap is installed

python -m main --help
python -m main -i YOUR_INTERFACE_NAME -f tcp
```

The CLI tool:

- Captures live traffic from a chosen interface.
- Prints a live textual summary of packets.
- Logs detailed data under `python_analyzer/logs/` (packets + summary report).

For full details, see `python_analyzer/README.md`.

---

## Screenshots (add your own)

- Dashboard overview – packet table + charts.
- Example alert showing a port scan.

You can capture screenshots from your browser and include them here when
submitting this project.

---

## Ethics & Legal Disclaimer

- Use this tool **only** on networks and systems you own or are explicitly
	authorized to monitor.
- Do **not** use it to intercept, store, or inspect credentials, private
	messages, or other sensitive payloads.
- The analyzer is intentionally limited to **header metadata**; it does not
	decode or inspect application payload contents.
- The authors and maintainers are not responsible for misuse.

This repository is intended as a final‑year project / portfolio piece for
networking, cybersecurity, and full‑stack development.

---

*Ensure clean architecture, accurate protocol parsing, real‑time performance,
and beginner‑friendly explanations.*