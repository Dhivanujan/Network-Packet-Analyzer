"""FastAPI backend for the Network Packet Analyzer.

Responsibilities:

* Expose REST endpoints for health checks, interfaces and stats.
* Maintain an in‑memory anomaly detector.
* Run a background scapy capture thread.
* Stream packet and anomaly events to frontend clients via WebSockets.

Use this service only on networks you own or are explicitly allowed to
analyze. The backend only works with header metadata and does not
inspect application payloads.
"""

from __future__ import annotations

import asyncio
import os
from typing import Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .anomaly_detector import AnomalyDetector
from .database import connect as db_connect, disconnect as db_disconnect, insert_packet, insert_anomaly, get_recent_packets, get_anomalies, get_protocol_stats, get_total_packet_count
from .models import AnomalyEventModel, PacketMessage, PacketModel
from .packet_capture import list_interfaces, start_capture, default_interface
from .websocket_manager import WebSocketManager


app = FastAPI(title="Network Packet Analyzer API")

# Allow the React dev server to talk to the API in development.
origins = [
    "http://localhost:5173",  # Vite default
    "http://127.0.0.1:5173",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Shared runtime state -----------------------------------------------------

# Bounded queue prevents unbounded memory growth under heavy traffic. When
# the queue is full, new packets are simply dropped by the capture thread,
# which is acceptable for a monitoring dashboard.
packet_queue: "asyncio.Queue[PacketModel]" = asyncio.Queue(maxsize=1000)
anomaly_detector = AnomalyDetector()
ws_manager = WebSocketManager()


async def packet_broadcaster() -> None:
    """Background task that relays packets from the queue to WebSocket clients."""

    while True:
        pkt = await packet_queue.get()

        anomaly: Optional[AnomalyEventModel] = anomaly_detector.observe(pkt)

        # Persist packet to MongoDB
        try:
            await insert_packet(pkt)
        except Exception as exc:
            print(f"[analyzer] Failed to store packet: {exc}")

        # Broadcast packet
        await ws_manager.broadcast(
            PacketMessage(type="packet", data=pkt.dict())
        )

        # Broadcast anomaly if a new one was detected
        if anomaly is not None:
            # Persist anomaly to MongoDB
            try:
                await insert_anomaly(anomaly)
            except Exception as exc:
                print(f"[analyzer] Failed to store anomaly: {exc}")

            await ws_manager.broadcast(
                PacketMessage(type="anomaly", data=anomaly.dict())
            )


@app.on_event("startup")
async def on_startup() -> None:
    """Start capture and broadcaster on application startup."""

    # Connect to MongoDB
    try:
        db = await db_connect()
        print(f"[analyzer] Connected to MongoDB: {db.name}")
    except Exception as exc:
        print(f"[analyzer] MongoDB connection failed: {exc}")

    interface = os.getenv("CAPTURE_INTERFACE") or default_interface()
    bpf = os.getenv("CAPTURE_BPF_FILTER")  # e.g. "tcp", "udp", "icmp"

    if interface is None:
        # No interface available – the API will still run, but capture
        # will not start until the environment is fixed.
        print("[analyzer] No default interface found; capture disabled.")
    else:
        print(f"[analyzer] Starting capture on interface: {interface}")
        start_capture(packet_queue=packet_queue, interface=interface, bpf_filter=bpf)

    # Launch broadcaster task
    asyncio.create_task(packet_broadcaster())


@app.on_event("shutdown")
async def on_shutdown() -> None:
    """Disconnect from MongoDB on shutdown."""
    await db_disconnect()
    print("[analyzer] Disconnected from MongoDB.")


# REST endpoints -----------------------------------------------------------


@app.get("/api/health")
async def health() -> dict:
    return {"status": "ok"}


@app.get("/api/interfaces")
async def interfaces() -> dict:
    return {"interfaces": list_interfaces(), "default": default_interface()}


@app.get("/api/stats")
async def stats() -> JSONResponse:
    snapshot = anomaly_detector.snapshot()
    return JSONResponse(snapshot.dict())


@app.get("/api/packets")
async def packets(limit: int = 100, protocol: Optional[str] = None) -> JSONResponse:
    """Return recent packets from MongoDB."""
    try:
        data = await get_recent_packets(limit=limit, protocol=protocol)
        return JSONResponse(content={"packets": data}, status_code=200)
    except Exception as exc:
        return JSONResponse(content={"error": str(exc)}, status_code=500)


@app.get("/api/anomalies")
async def anomalies(limit: int = 50) -> JSONResponse:
    """Return recent anomalies from MongoDB."""
    try:
        data = await get_anomalies(limit=limit)
        return JSONResponse(content={"anomalies": data}, status_code=200)
    except Exception as exc:
        return JSONResponse(content={"error": str(exc)}, status_code=500)


@app.get("/api/db-stats")
async def db_stats() -> JSONResponse:
    """Return aggregate stats from MongoDB."""
    try:
        total = await get_total_packet_count()
        protocol_counts = await get_protocol_stats()
        return JSONResponse(content={
            "total_packets": total,
            "protocol_counts": protocol_counts,
        })
    except Exception as exc:
        return JSONResponse(content={"error": str(exc)}, status_code=500)


# WebSocket endpoint -------------------------------------------------------


@app.websocket("/ws/packets")
async def packets_ws(websocket: WebSocket) -> None:
    await ws_manager.connect(websocket)

    try:
        # This endpoint is write‑only from the server's perspective; we
        # simply keep the connection open until the client disconnects.
        while True:
            await websocket.receive_text()  # keep the connection alive if client sends pings
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception:
        ws_manager.disconnect(websocket)


# Convenience root endpoint -----------------------------------------------


@app.get("/")
async def root() -> dict:
    return {
        "message": "Network Packet Analyzer backend is running.",
        "docs": "/docs",
        "websocket": "/ws/packets",
    }
