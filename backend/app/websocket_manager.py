"""WebSocket connection management and broadcasting utilities."""

from __future__ import annotations

from typing import Any, Dict, List

from fastapi import WebSocket

from .models import PacketMessage


class WebSocketManager:
    def __init__(self) -> None:
        self._connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self._connections.append(websocket)

    def disconnect(self, websocket: WebSocket) -> None:
        if websocket in self._connections:
            self._connections.remove(websocket)

    async def broadcast(self, message: PacketMessage | Dict[str, Any]) -> None:
        if isinstance(message, PacketMessage):
            payload = message.dict()
        else:
            payload = message

        dead: List[WebSocket] = []
        for ws in self._connections:
            try:
                await ws.send_json(payload)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)
