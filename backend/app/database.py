"""MongoDB connection and data-access helpers using Motor (async driver).

The default connection string targets the local MongoDB instance that
MongoDB Compass connects to: ``mongodb://localhost:27017``.

Override with the ``MONGO_URI`` environment variable if needed.
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase

from .models import AnomalyEventModel, PacketModel

# ---------------------------------------------------------------------------
# Connection setup
# ---------------------------------------------------------------------------

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
DB_NAME = os.getenv("MONGO_DB_NAME", "network_packet_analyzer")

_client: Optional[AsyncIOMotorClient] = None
_db: Optional[AsyncIOMotorDatabase] = None


async def connect() -> AsyncIOMotorDatabase:
    """Open the Motor client and return the database handle."""
    global _client, _db
    _client = AsyncIOMotorClient(MONGO_URI)
    _db = _client[DB_NAME]

    # Create indexes for common query patterns
    await _db.packets.create_index("timestamp")
    await _db.packets.create_index("protocol")
    await _db.packets.create_index("src_ip")
    await _db.anomalies.create_index("timestamp")

    return _db


async def disconnect() -> None:
    """Close the Motor client gracefully."""
    global _client, _db
    if _client is not None:
        _client.close()
        _client = None
        _db = None


def get_db() -> AsyncIOMotorDatabase:
    """Return the current database handle (must call ``connect`` first)."""
    if _db is None:
        raise RuntimeError("Database not connected. Call connect() first.")
    return _db


# ---------------------------------------------------------------------------
# Data-access helpers
# ---------------------------------------------------------------------------


async def insert_packet(pkt: PacketModel) -> None:
    """Insert a single packet document."""
    db = get_db()
    doc = pkt.dict()
    doc["timestamp"] = pkt.timestamp  # keep as datetime
    await db.packets.insert_one(doc)


async def insert_anomaly(anomaly: AnomalyEventModel) -> None:
    """Insert a single anomaly document."""
    db = get_db()
    await db.anomalies.insert_one(anomaly.dict())


async def get_recent_packets(
    limit: int = 100,
    protocol: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Return the most recent packets, optionally filtered by protocol."""
    db = get_db()
    query: Dict[str, Any] = {}
    if protocol:
        query["protocol"] = protocol.upper()
    cursor = db.packets.find(query, {"_id": 0}).sort("timestamp", -1).limit(limit)
    return await cursor.to_list(length=limit)


async def get_anomalies(limit: int = 50) -> List[Dict[str, Any]]:
    """Return the most recent anomalies."""
    db = get_db()
    cursor = db.anomalies.find({}, {"_id": 0}).sort("timestamp", -1).limit(limit)
    return await cursor.to_list(length=limit)


async def get_protocol_stats() -> Dict[str, int]:
    """Aggregate packet counts by protocol from the database."""
    db = get_db()
    pipeline = [
        {"$group": {"_id": "$protocol", "count": {"$sum": 1}}},
    ]
    counts: Dict[str, int] = {}
    async for doc in db.packets.aggregate(pipeline):
        counts[doc["_id"]] = doc["count"]
    return counts


async def get_total_packet_count() -> int:
    """Return the total number of stored packets."""
    db = get_db()
    return await db.packets.count_documents({})
