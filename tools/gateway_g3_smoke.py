from __future__ import annotations

import asyncio
import json
from pathlib import Path
import sys

import aiohttp
from aiohttp import web


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from gateway.adapter import OpenAIResponsesAdapter
from gateway.attempts import SingleRouteAttemptRunner
from gateway.cancellation import CancellationToken
from gateway.commit import Committer
from gateway.models import BufferedResponse, CancelReason, CommitState, GatewayLimits
from gateway.request_snapshot import create_request_snapshot


class SmokeDownstream:
    def __init__(self) -> None:
        self.body = bytearray()

    async def prepare(self, _status: int, _content_type: str, _content_length: int) -> None:
        return

    async def write(self, chunk: bytes) -> None:
        self.body.extend(chunk)

    async def finish(self) -> None:
        return


def _event(event_type: str, payload: dict[str, object]) -> bytes:
    return (
        f"event: {event_type}\n"
        f"data: {json.dumps(payload, separators=(',', ':'))}\n\n"
    ).encode("utf-8")


def _success_sse() -> bytes:
    in_progress = {"id": "resp_g3_smoke", "object": "response", "status": "in_progress", "output": []}
    completed = {"id": "resp_g3_smoke", "object": "response", "status": "completed", "output": []}
    return b"".join(
        (
            _event("response.created", {"type": "response.created", "sequence_number": 0, "response": in_progress}),
            _event("response.completed", {"type": "response.completed", "sequence_number": 1, "response": completed}),
        )
    )


async def smoke() -> dict[str, object]:
    limits = GatewayLimits(
        max_request_bytes=1024,
        max_response_bytes=1024,
        read_chunk_bytes=4,
        connect_timeout_seconds=1,
        first_byte_timeout_seconds=1,
        idle_timeout_seconds=1,
        total_timeout_seconds=2,
    )
    partial_sent = asyncio.Event()

    async def responses(request: web.Request) -> web.StreamResponse:
        payload = await request.json()
        if payload.get("input") != "cancel":
            return web.Response(body=_success_sse(), content_type="text/event-stream")
        response = web.StreamResponse(headers={"Content-Type": "text/event-stream"})
        await response.prepare(request)
        in_progress = {"id": "resp_g3_cancel", "object": "response", "status": "in_progress", "output": []}
        await response.write(_event("response.created", {"type": "response.created", "response": in_progress}))
        partial_sent.set()
        try:
            await asyncio.sleep(30)
        except asyncio.CancelledError:
            pass
        return response

    app = web.Application()
    app.router.add_post("/v1/responses", responses)
    web_runner = web.AppRunner(app, shutdown_timeout=1)
    await web_runner.setup()
    site = web.TCPSite(web_runner, "127.0.0.1", 0)
    await site.start()
    sockets = site._server.sockets if site._server is not None else []
    if not sockets:
        raise RuntimeError("smoke_server_socket_missing")
    port = sockets[0].getsockname()[1]
    adapter = OpenAIResponsesAdapter(f"http://127.0.0.1:{port}/v1")

    success_request = json.dumps({"model": "g3-smoke", "input": "synthetic", "stream": True}).encode("utf-8")
    success_snapshot = create_request_snapshot(success_request, {"content-type": "application/json"}, limits)
    cancellation_request = json.dumps({"model": "g3-smoke", "input": "cancel", "stream": True}).encode("utf-8")
    cancellation_snapshot = create_request_snapshot(cancellation_request, {"content-type": "application/json"}, limits)
    body = b"G3_SMOKE_OK"
    buffered = BufferedResponse(
        status=200,
        content_type="application/octet-stream",
        body=body,
        body_sha256="fixture",
        terminal_status="completed",
        response_id="resp_g3_smoke",
        buffer_bytes=len(body),
    )
    downstream = SmokeDownstream()
    result = await Committer(chunk_bytes=4).commit(buffered, downstream, CancellationToken())
    try:
        async with aiohttp.ClientSession() as session:
            attempt_runner = SingleRouteAttemptRunner(session, adapter, limits)
            complete = await attempt_runner.run(success_snapshot, "fixture-only", CancellationToken())
            cancel_token = CancellationToken()
            cancel_task = asyncio.create_task(attempt_runner.run(cancellation_snapshot, "fixture-only", cancel_token))
            await asyncio.wait_for(partial_sent.wait(), timeout=2)
            cancel_token.cancel(CancelReason.CLIENT_DISCONNECTED)
            cancelled = await asyncio.wait_for(cancel_task, timeout=2)
        return {
            "ok": bool(
                complete.complete is not None
                and complete.complete.response_id == "resp_g3_smoke"
                and cancelled.cancelled is CancelReason.CLIENT_DISCONNECTED
                and result.state is CommitState.DELIVERED
                and bytes(downstream.body) == body
            ),
            "aiohttp": aiohttp.__version__,
            "complete_response_id": complete.complete.response_id if complete.complete else None,
            "cancelled": cancelled.cancelled.value if cancelled.cancelled else None,
            "commit_state": result.state.value,
        }
    finally:
        await web_runner.cleanup()


def main() -> int:
    result = asyncio.run(smoke())
    print(json.dumps(result, sort_keys=True))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
