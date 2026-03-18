📡 Network Packet Analyzer – Full‑Stack

This project is a full‑stack, educational **Network Packet Analyzer** with a
Python backend, a React dashboard frontend, and **MongoDB** for persistent
storage of captured packets and anomaly events.

It is designed for learning and ethical monitoring only, focusing strictly on
packet **headers** (Ethernet/IP/TCP/UDP/ICMP) and simple anomaly detection.

---

## Quick Start

1. Make sure **MongoDB** is running locally (default `mongodb://localhost:27017`).
   You can verify with **MongoDB Compass**.

2. Start the backend (API + packet capture):

```bash
cd backend
python -m venv .venv

# Activate the virtual environment
# Windows PowerShell:
.venv\Scripts\Activate.ps1
# Windows CMD:
.venv\Scripts\activate.bat
# Linux / macOS:
source .venv/bin/activate

pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

3. Start the frontend dashboard (in a new terminal):

```bash
cd frontend
npm install
npm run dev
```

4. Open the dashboard in your browser:

- http://localhost:5173

5. Open **MongoDB Compass** and connect to `mongodb://localhost:27017` to view
   the `network_packet_analyzer` database with `packets` and `anomalies`
   collections.

---

## Prerequisites

- **Python 3.9+** (recommended)
- **Node.js 18+** and npm
- **MongoDB 6.0+** – running locally on `localhost:27017`
  - Download: https://www.mongodb.com/try/download/community
  - GUI: **MongoDB Compass** (bundled with the installer or download
    separately)
- **Packet capture library:**
	- Windows: [Npcap](https://npcap.com/) (install with "WinPcap API
	  compatibility" checked)
	- Linux/macOS: libpcap (usually preinstalled)
- Sufficient privileges to capture packets on the selected interface
  (Administrator on Windows, root/sudo on Linux/macOS)

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        Browser  :5173                           │
│   React Dashboard (Vite)                                        │
│   ┌──────────┐ ┌──────────┐ ┌────────────┐ ┌──────────────┐    │
│   │PacketTable│ │TrafficChart│ │AlertPanel │ │ProtocolFilter│    │
│   └──────────┘ └──────────┘ └────────────┘ └──────────────┘    │
└────────────────────────┬────────────────────────────────────────┘
                         │  HTTP / WebSocket
┌────────────────────────▼────────────────────────────────────────┐
│                   FastAPI Backend  :8000                         │
│                                                                 │
│  ┌────────────┐  ┌──────────────┐  ┌─────────────────────────┐  │
│  │ REST API   │  │ WebSocket    │  │ Background Capture      │  │
│  │ /api/*     │  │ /ws/packets  │  │ (scapy in daemon thread)│  │
│  └────────────┘  └──────────────┘  └─────────────────────────┘  │
│                                                                 │
│  ┌──────────────────┐  ┌──────────────────────────────────────┐  │
│  │ Anomaly Detector │  │ Database Layer (Motor – async driver)│  │
│  │ (in‑memory)      │  │ Persists packets & anomalies         │  │
│  └──────────────────┘  └──────────────┬──────────────────────┘  │
└───────────────────────────────────────┼─────────────────────────┘
                                        │
                         ┌──────────────▼──────────────┐
                         │   MongoDB  :27017            │
                         │   DB: network_packet_analyzer│
                         │   ├── packets                │
                         │   └── anomalies              │
                         └─────────────────────────────┘
```

- **Backend** – Python 3, FastAPI, scapy, Motor (async MongoDB)
	- Captures live packets from a chosen network interface using scapy.
	- Decodes Ethernet, IPv4, TCP, UDP, ICMP headers.
	- Persists every captured packet and detected anomaly to **MongoDB**.
	- Maintains in‑memory traffic statistics and anomaly detection:
		- Port‑scan–style behavior (many destination ports from one source).
		- Traffic spikes (many packets in a sliding time window).
	- Exposes:
		- REST API for health checks, interfaces, stats, and database queries.
		- WebSocket `/ws/packets` for real‑time packet + anomaly streaming.

- **Frontend** – React + Vite
	- Real‑time packet table (source/destination IP & ports, protocol, size, time).
	- Protocol filter buttons (TCP / UDP / ICMP / HTTP / ALL).
	- Live traffic chart (protocol distribution).
	- Alert panel for suspicious activity.
	- Clean, responsive dashboard layout.

- **Database** – MongoDB
	- `packets` collection – every captured packet (timestamp, src/dst IP & port, protocol, length).
	- `anomalies` collection – detected anomaly events (timestamp, description).
	- Indexed on `timestamp`, `protocol`, and `src_ip` for fast queries.

Folder layout:

```text
backend/
  app/
    main.py              # FastAPI app, REST + WebSocket endpoints
    database.py          # MongoDB connection & data‑access helpers (Motor)
    packet_capture.py    # scapy capture in a background thread
    packet_analysis.py   # decodes headers into JSON‑friendly models
    anomaly_detector.py  # tracks stats and detects basic anomalies
    websocket_manager.py # WebSocket connection broadcasting
    models.py            # Pydantic models used in the API / WebSocket
  requirements.txt
frontend/
  src/
    App.jsx
    main.jsx
    styles.css
    components/
      PacketTable.jsx
      TrafficChart.jsx
      AlertPanel.jsx
      ProtocolFilterBar.jsx
  index.html
  package.json
  vite.config.js
README.md
```

---

## Backend – Python / FastAPI

### Tech Stack

| Package | Purpose |
|---------|---------|
| FastAPI | REST API framework |
| Uvicorn | ASGI server |
| scapy | Live packet capture & header decoding |
| Pydantic | Data validation & serialization |
| Motor | Async MongoDB driver (built on PyMongo) |
| PyMongo | MongoDB Python driver |

### Key Files

- `backend/app/main.py` – FastAPI app, REST endpoints, WebSocket `/ws/packets`, MongoDB startup/shutdown hooks.
- `backend/app/database.py` – Motor‑based async MongoDB connection, indexes, and CRUD helpers.
- `backend/app/packet_capture.py` – scapy capture in a background daemon thread.
- `backend/app/packet_analysis.py` – decodes raw packets into JSON‑friendly Pydantic models.
- `backend/app/anomaly_detector.py` – tracks stats and detects port scans / traffic spikes.
- `backend/app/websocket_manager.py` – manages WebSocket connections and broadcasting.
- `backend/app/models.py` – Pydantic models (`PacketModel`, `AnomalyEventModel`, `StatsModel`, `PacketMessage`).

### Running the Backend

1. Create and activate a virtual environment:

```bash
cd backend
python -m venv .venv

# Windows PowerShell:
.venv\Scripts\Activate.ps1
# Windows CMD:
.venv\Scripts\activate.bat
# Linux / macOS:
source .venv/bin/activate
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Make sure MongoDB is running on `localhost:27017` (default).
   Optionally override with environment variables:

```bash
# Windows PowerShell
$env:MONGO_URI = "mongodb://localhost:27017"
$env:MONGO_DB_NAME = "network_packet_analyzer"

# Linux / macOS
export MONGO_URI="mongodb://localhost:27017"
export MONGO_DB_NAME="network_packet_analyzer"
```

4. (Optional) Choose capture interface via environment variables:

```bash
# Windows PowerShell
$env:CAPTURE_INTERFACE = "Ethernet0"
$env:CAPTURE_BPF_FILTER = "tcp"       # optional: only capture TCP

# Linux / macOS
export CAPTURE_INTERFACE=eth0
export CAPTURE_BPF_FILTER=tcp
```

5. Start the API server:

```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

6. Open the interactive docs (FastAPI Swagger UI):

- http://localhost:8000/docs

### API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/health` | Health check |
| `GET` | `/api/interfaces` | List detected network interfaces + default |
| `GET` | `/api/stats` | In‑memory stats: total packets, protocol counts, anomalies |
| `GET` | `/api/packets?limit=100&protocol=TCP` | Query stored packets from MongoDB |
| `GET` | `/api/anomalies?limit=50` | Query stored anomalies from MongoDB |
| `GET` | `/api/db-stats` | Aggregate stats from MongoDB (total count, protocol breakdown) |
| `WS`  | `/ws/packets` | Real‑time WebSocket stream of packets and anomalies |

> On Windows, install **Npcap** (with WinPcap API compatibility); on
> Linux/macOS, libpcap is usually available out of the box.
> Capturing typically requires administrator / root privileges.

---

## MongoDB – Data Storage

### Connection

The backend connects to MongoDB on startup using **Motor** (async driver).
Default connection: `mongodb://localhost:27017`, database `network_packet_analyzer`.

### Collections

**`packets`** – one document per captured packet:

| Field | Type | Description |
|-------|------|-------------|
| `timestamp` | `datetime` | When the packet was captured |
| `src_ip` | `string` | Source IP address |
| `dst_ip` | `string` | Destination IP address |
| `src_port` | `int \| null` | Source port (TCP/UDP only) |
| `dst_port` | `int \| null` | Destination port (TCP/UDP only) |
| `protocol` | `string` | `TCP`, `UDP`, `ICMP`, `IP`, or `OTHER` |
| `length` | `int` | Packet size in bytes |

**`anomalies`** – one document per detected anomaly:

| Field | Type | Description |
|-------|------|-------------|
| `timestamp` | `datetime` | When the anomaly was detected |
| `description` | `string` | Human‑readable anomaly description |

### Indexes

- `packets.timestamp` – fast time‑range queries
- `packets.protocol` – fast protocol filtering
- `packets.src_ip` – fast source‑IP lookups
- `anomalies.timestamp` – fast anomaly listing

### Viewing Data in MongoDB Compass

1. Open **MongoDB Compass**.
2. Connect to `mongodb://localhost:27017`.
3. Select the `network_packet_analyzer` database.
4. Browse `packets` and `anomalies` collections to inspect captured data.

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

## Environment Variables Reference

| Variable | Default | Description |
|----------|---------|-------------|
| `MONGO_URI` | `mongodb://localhost:27017` | MongoDB connection string |
| `MONGO_DB_NAME` | `network_packet_analyzer` | MongoDB database name |
| `CAPTURE_INTERFACE` | Auto‑detected | Network interface for packet capture |
| `CAPTURE_BPF_FILTER` | *(none)* | BPF filter expression (e.g. `tcp`, `udp`) |
| `VITE_API_BASE` | `http://localhost:8000` | Backend API URL (frontend) |
| `VITE_WS_URL` | `ws://localhost:8000/ws/packets` | WebSocket URL (frontend) |

---

## Example End‑to‑End Workflow

1. Ensure MongoDB is running (`mongod` or MongoDB service).

2. Start backend (packet capture + API):

```bash
cd backend
.venv\Scripts\Activate.ps1   # or source .venv/bin/activate
uvicorn app.main:app --reload --port 8000
```

3. Start frontend dashboard (new terminal):

```bash
cd frontend
npm run dev
```

4. Open the dashboard in your browser:

- http://localhost:5173

5. Generate some traffic (web browsing, `ping`, `curl`, etc.).
6. Watch packets, protocol distribution, and alerts update in real time.
7. Open **MongoDB Compass** → `network_packet_analyzer` to inspect stored data.

---

## User Guide

Follow this guide to effectively use the application features:

### 1. Dashboard Controls
- **Protocol Filters:** Click the buttons (TCP, UDP, ICMP, HTTP) to isolate specific traffic types in the table.
- **Reset View:** Click **ALL** to see all traffic again.
- **Charts:** The bar chart updates every few seconds to show the distribution of protocols.

### 2. Reading the Packet Table
- **Source/Destination:** Shows IP addresses and ports (e.g., `192.168.1.15:443`).
- **Length:** The size of the packet header + payload in bytes.
- **Real-Time Updates:** New packets appear at the top of the list.

### 3. Understanding Alerts
The backend analyzes traffic patterns and pushes alerts to the frontend:
- **Port Scan Suspected:** Indicates a single IP is trying to connect to many different ports on a target.
- **High Traffic Volume:** Indicates a sudden spike in the number of packets per second.

### 4. Advanced Data Inspection
For forensic analysis, use **MongoDB Compass**:
- **Collection:** `packets`
- **Query Example:** `{ "src_ip": "192.168.1.10", "protocol": "TCP" }`
- **Sort:** `{ "timestamp": -1 }` (newest first)

---

## Screenshots (add your own)

- Dashboard overview – packet table + charts.
- Example alert showing a port scan.
- MongoDB Compass showing the `packets` collection.

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