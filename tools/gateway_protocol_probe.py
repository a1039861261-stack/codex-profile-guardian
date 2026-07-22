from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
from http.client import HTTPConnection
import json
import os
from pathlib import Path
import platform
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time
from typing import Any
from urllib.parse import urlparse
import uuid


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tests.gateway_probe_support import (  # noqa: E402
    ExperimentalFullBufferRelay,
    FAKE_BEARER,
    FIXTURE_MODEL,
    ProgrammableResponsesMock,
    ScenarioControl,
    ScriptedScenario,
    StateStore,
    fixture_request,
    http_post_json,
    http_post_response,
    raw_post_bytes,
    text_sse_frames,
    tool_sse_frames,
)


G2_SOURCE_FILES = (
    "docs/gateway-protocol-contract-v1.md",
    "gateway/protocols/responses.py",
    "tests/gateway_probe_support.py",
    "tests/test_gateway_protocol_probe.py",
    "tools/gateway_protocol_probe.py",
)
CODEX_01441_BODY_KEYS = {
    "client_metadata",
    "include",
    "input",
    "instructions",
    "model",
    "parallel_tool_calls",
    "prompt_cache_key",
    "reasoning",
    "store",
    "stream",
    "tool_choice",
    "tools",
}


def _codex_command(explicit: str | None) -> str:
    if explicit:
        return explicit
    candidates = ["codex.cmd", "codex"] if os.name == "nt" else ["codex"]
    for candidate in candidates:
        resolved = shutil.which(candidate)
        if resolved:
            return resolved
    raise RuntimeError("codex_cli_not_found")


def _codex_version(command: str) -> str:
    completed = subprocess.run(
        [command, "--version"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=10,
        check=False,
    )
    return completed.stdout.strip().splitlines()[-1] if completed.stdout.strip() else "unknown"


def _git_command(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=ROOT,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=5,
        check=False,
    )


def _git_head() -> str:
    completed = _git_command("rev-parse", "HEAD")
    return completed.stdout.strip() if completed.returncode == 0 else "uncommitted"


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest().upper()


def _source_binding() -> dict[str, Any]:
    status = _git_command(
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
        "--",
        *G2_SOURCE_FILES,
    )
    if status.returncode != 0:
        raise RuntimeError("git_status_failed")
    files = {}
    for relative in G2_SOURCE_FILES:
        path = ROOT / relative
        if not path.is_file():
            raise RuntimeError(f"g2_source_missing:{relative}")
        files[relative] = _sha256_file(path)
    porcelain = status.stdout.splitlines()
    return {
        "ok": True,
        "clean": not porcelain,
        "head": _git_head(),
        "git_status_porcelain": porcelain,
        "files_sha256": files,
    }


def _walk_dicts(value: Any):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from _walk_dicts(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_dicts(child)


def _request_contract(captured: Any) -> dict[str, Any]:
    body = captured.json_body if captured is not None else None
    media_type = captured.content_type.split(";", 1)[0].strip().lower() if captured and captured.content_type else None
    return {
        "ok": bool(
            captured is not None
            and captured.method == "POST"
            and captured.path == "/v1/responses"
            and captured.authorization_scheme == "Bearer"
            and captured.authorization_valid
            and media_type == "application/json"
            and isinstance(body, dict)
            and body.get("model") == FIXTURE_MODEL
            and body.get("stream") is True
            and isinstance(body.get("input"), list)
        ),
        "method": captured.method if captured else None,
        "path": captured.path if captured else None,
        "authorization_scheme": captured.authorization_scheme if captured else None,
        "authorization_valid": captured.authorization_valid if captured else False,
        "content_type": captured.content_type if captured else None,
        "model": body.get("model") if isinstance(body, dict) else None,
        "stream": body.get("stream") if isinstance(body, dict) else None,
        "input_is_array": isinstance(body.get("input"), list) if isinstance(body, dict) else False,
        "body_keys": sorted(body) if isinstance(body, dict) else [],
    }


def run_zero_header_probe(gate_seconds: float) -> dict[str, Any]:
    control = ScenarioControl()
    frames = text_sse_frames("G2_SOCKET_OK")
    scenario = ScriptedScenario(
        name="socket_gate",
        chunks=frames,
        wait_before_chunk=len(frames) - 1,
        control=control,
    )
    with ProgrammableResponsesMock(lambda _request: scenario) as primary:
        with ExperimentalFullBufferRelay(primary.base_url) as relay:
            host, port, request = raw_post_bytes(relay.base_url, fixture_request())
            with socket.create_connection((host, port), timeout=5) as downstream:
                downstream.sendall(request)
                if not control.partial_sent.wait(5):
                    raise RuntimeError("upstream_partial_not_observed")
                started = time.monotonic()
                downstream.settimeout(gate_seconds)
                zero_bytes = False
                try:
                    zero_bytes = downstream.recv(1) == b""
                except socket.timeout:
                    zero_bytes = True
                waited = time.monotonic() - started
                records_before_terminal = len(relay.records)
                control.release_terminal.set()
                downstream.settimeout(5)
                response = bytearray()
                while True:
                    chunk = downstream.recv(65536)
                    if not chunk:
                        break
                    response.extend(chunk)
            if not relay.wait_for_records(1, timeout=5):
                raise RuntimeError("relay_record_missing")
            record = relay.records[0]
    return {
        "ok": bool(
            zero_bytes
            and records_before_terminal == 0
            and bytes(response).startswith(b"HTTP/1.1 200")
            and b"response.completed" in response
            and record.outcome == "delivered"
        ),
        "zero_response_bytes_before_terminal": zero_bytes,
        "records_before_terminal": records_before_terminal,
        "wait_without_headers_seconds": round(waited, 3),
        "terminal_precedes_commit": bool(
            control.terminal_sent_at is not None
            and record.commit_started_at is not None
            and record.commit_started_at >= control.terminal_sent_at
        ),
        "upstream_requests": primary.request_count,
    }


def run_state_fixture() -> dict[str, Any]:
    shared_store = StateStore()
    with ProgrammableResponsesMock(route_name="P1", state_store=shared_store, stateful=True) as p1:
        with ProgrammableResponsesMock(route_name="P2", state_store=shared_store, stateful=True) as p2:
            status, created_p1 = http_post_json(p1.base_url, {"model": FIXTURE_MODEL, "input": "fixture-p1"})
            p1_to_p2_status, created_p2 = http_post_json(
                p2.base_url,
                {
                    "model": FIXTURE_MODEL,
                    "input": "fixture-p2",
                    "previous_response_id": created_p1.get("id"),
                },
            )
            p2_to_p1_status, _continued = http_post_json(
                p1.base_url,
                {
                    "model": FIXTURE_MODEL,
                    "input": "fixture-p1-return",
                    "previous_response_id": created_p2.get("id"),
                },
            )
    with ProgrammableResponsesMock(route_name="P1", stateful=True) as isolated_p1:
        with ProgrammableResponsesMock(route_name="P2", stateful=True) as isolated_p2:
            _, isolated_created = http_post_json(
                isolated_p1.base_url,
                {"model": FIXTURE_MODEL, "input": "fixture-isolated-p1"},
            )
            incompatible_status, incompatible_payload = http_post_json(
                isolated_p2.base_url,
                {
                    "model": FIXTURE_MODEL,
                    "input": "fixture-isolated-p2",
                    "previous_response_id": isolated_created.get("id"),
                },
            )
    return {
        "ok": bool(
            status == 200
            and p1_to_p2_status == 200
            and p2_to_p1_status == 200
            and incompatible_status == 404
        ),
        "shared_bidirectional": p1_to_p2_status == 200 and p2_to_p1_status == 200,
        "isolated_is_rejected": incompatible_status == 404,
        "isolated_error_code": incompatible_payload.get("error", {}).get("code"),
        "real_route_capability": "unknown",
        "safe_default": "block_stateful_before_upstream",
    }


def _codex_args(command: str, base_url: str, request_marker: str, *, prompt: str | None = None) -> list[str]:
    return [
        command,
        "exec",
        "--ephemeral",
        "--ignore-user-config",
        "--ignore-rules",
        "--disable",
        "apps",
        "--disable",
        "plugins",
        "--disable",
        "remote_plugin",
        "--skip-git-repo-check",
        "-s",
        "read-only",
        "-C",
        str(ROOT),
        "-c",
        f'model="{FIXTURE_MODEL}"',
        "-c",
        'model_provider="guardian_probe"',
        "-c",
        'model_providers.guardian_probe.name="Guardian G2 Probe"',
        "-c",
        f'model_providers.guardian_probe.base_url="{base_url}"',
        "-c",
        'model_providers.guardian_probe.env_key="GUARDIAN_G2_PROBE_KEY"',
        "-c",
        'model_providers.guardian_probe.wire_api="responses"',
        "-c",
        "model_providers.guardian_probe.request_max_retries=0",
        "-c",
        "model_providers.guardian_probe.stream_max_retries=0",
        "-c",
        "model_providers.guardian_probe.requires_openai_auth=false",
        prompt or f"This is a local protocol probe request identified by {request_marker}.",
    ]


def _remove_probe_tree(path: Path) -> None:
    def make_writable_and_retry(function, target, _error_info) -> None:
        os.chmod(target, stat.S_IWRITE)
        function(target)

    if path.exists():
        shutil.rmtree(path, onerror=make_writable_and_retry)
    if path.exists():
        raise RuntimeError("isolated_codex_home_cleanup_failed")


def _new_probe_environment(prefix: str) -> tuple[Path, dict[str, str]]:
    probe_root = ROOT / "_tmp"
    probe_root.mkdir(parents=True, exist_ok=True)
    codex_home = Path(tempfile.mkdtemp(prefix=prefix, dir=probe_root))
    environment = os.environ.copy()
    environment["CODEX_HOME"] = str(codex_home)
    environment["GUARDIAN_G2_PROBE_KEY"] = FAKE_BEARER
    return codex_home, environment


def _run_codex_process(
    command: str,
    base_url: str,
    request_marker: str,
    environment: dict[str, str],
    *,
    prompt: str | None = None,
    timeout: float = 45,
) -> tuple[int, str]:
    completed = subprocess.run(
        _codex_args(command, base_url, request_marker, prompt=prompt),
        cwd=ROOT,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
    )
    return completed.returncode, completed.stdout


def run_codex_probe(command: str, gate_seconds: float) -> dict[str, Any]:
    request_marker = f"G2_REQUEST_ONLY_{uuid.uuid4().hex}"
    response_marker = f"G2_UPSTREAM_ONLY_{uuid.uuid4().hex}"
    control = ScenarioControl()
    frames = text_sse_frames(response_marker)
    scenario = ScriptedScenario(
        name="codex_gate",
        chunks=frames,
        wait_before_chunk=len(frames) - 1,
        control=control,
    )
    codex_home, environment = _new_probe_environment("g2-codex-home-")
    result: dict[str, Any] | None = None
    try:
        with ProgrammableResponsesMock(lambda _request: scenario, route_name="P1") as primary:
            with ExperimentalFullBufferRelay(primary.base_url) as relay:
                process = subprocess.Popen(
                    _codex_args(command, relay.base_url, request_marker),
                    cwd=ROOT,
                    env=environment,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                )
                try:
                    if not control.partial_sent.wait(10):
                        raise RuntimeError("codex_request_not_observed")
                    time.sleep(gate_seconds)
                    waiting_without_headers = process.poll() is None and len(relay.records) == 0
                    control.release_terminal.set()
                    output, _ = process.communicate(timeout=30)
                except Exception:
                    control.release_terminal.set()
                    process.kill()
                    process.communicate(timeout=10)
                    raise
                if not relay.wait_for_records(1, timeout=5):
                    raise RuntimeError("codex_relay_record_missing")
                record = relay.records[0]
                captured = relay.ingress_requests[0] if relay.ingress_requests else None
        body = captured.json_body if captured is not None else None
        contract = _request_contract(captured)
        body_keys_exact = isinstance(body, dict) and set(body) == CODEX_01441_BODY_KEYS
        request_body_text = json.dumps(body, ensure_ascii=False, sort_keys=True) if body else ""
        tool_descriptors = [
            {
                "type": tool.get("type"),
                "name": tool.get("name"),
                "required": (tool.get("parameters") or {}).get("required", []),
            }
            for tool in (body.get("tools", []) if body else [])
            if isinstance(tool, dict)
        ]
        result = {
            "ok": bool(
                process.returncode == 0
                and waiting_without_headers
                and response_marker in output
                and response_marker not in request_body_text
                and request_marker in request_body_text
                and primary.request_count == 1
                and record.outcome == "delivered"
                and contract["ok"]
                and body_keys_exact
                and body is not None
            ),
            "exit_code": process.returncode,
            "waited_without_headers": waiting_without_headers,
            "gate_seconds": gate_seconds,
            "request_count": primary.request_count,
            "request_contract": contract,
            "path": contract["path"],
            "method": contract["method"],
            "authorization_scheme": contract["authorization_scheme"],
            "content_type": contract["content_type"],
            "stream": contract["stream"],
            "model": contract["model"],
            "body_keys": sorted(body.keys()) if body else [],
            "body_keys_exact_for_codex_0_144_1": body_keys_exact,
            "tool_descriptors": tool_descriptors,
            "distinct_response_nonce_received": response_marker in output,
            "response_nonce_absent_from_request": response_marker not in request_body_text,
            "request_nonce_present_in_request": request_marker in request_body_text,
            "request_max_retries": 0,
            "stream_max_retries": 0,
        }
    finally:
        _remove_probe_tree(codex_home)
    if result is None:
        raise RuntimeError("codex_probe_result_missing")
    result["isolated_codex_home_removed"] = not codex_home.exists()
    return result


def run_models_probe() -> dict[str, Any]:
    with ProgrammableResponsesMock(route_name="P1") as primary:
        with ExperimentalFullBufferRelay(primary.base_url) as relay:
            parsed = urlparse(relay.base_url)
            path = parsed.path.rstrip("/") + "/models"
            connection = HTTPConnection(parsed.hostname, parsed.port, timeout=5)
            try:
                connection.request("GET", path)
                response = connection.getresponse()
                status = response.status
                content_type = response.getheader("Content-Type", "")
                body = response.read()
            finally:
                connection.close()
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        payload = None
    models = payload.get("data") if isinstance(payload, dict) else None
    fixture_models = [item for item in models or [] if isinstance(item, dict) and item.get("id") == FIXTURE_MODEL]
    return {
        "ok": bool(
            status == 200
            and content_type.split(";", 1)[0].strip().lower() == "application/json"
            and isinstance(payload, dict)
            and payload.get("object") == "list"
            and len(fixture_models) == 1
            and primary.request_count == 0
        ),
        "method": "GET",
        "path": path,
        "status": status,
        "content_type": content_type,
        "model_ids": [item.get("id") for item in models or [] if isinstance(item, dict)],
        "upstream_response_requests": primary.request_count,
    }


def _service_unavailable_scenario(_request: Any) -> ScriptedScenario:
    body = json.dumps(
        {
            "error": {
                "type": "synthetic_upstream_error",
                "code": "synthetic_service_unavailable",
                "message": "Synthetic G2 fixture only.",
            }
        },
        separators=(",", ":"),
    ).encode("utf-8")
    return ScriptedScenario(
        name="service_unavailable",
        status=503,
        content_type="application/json; charset=utf-8",
        chunks=(body,),
    )


def run_service_unavailable_probe(command: str) -> dict[str, Any]:
    with ProgrammableResponsesMock(_service_unavailable_scenario, route_name="P1") as wire_primary:
        with ExperimentalFullBufferRelay(wire_primary.base_url) as wire_relay:
            wire_status, wire_content_type, wire_body = http_post_response(
                wire_relay.base_url,
                json.loads(fixture_request().decode("utf-8")),
            )
        wire_record = wire_relay.records[0] if len(wire_relay.records) == 1 else None
    try:
        wire_payload = json.loads(wire_body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        wire_payload = None
    wire_code = wire_payload.get("error", {}).get("code") if isinstance(wire_payload, dict) else None
    wire_ok = bool(
        wire_status == 502
        and wire_content_type.split(";", 1)[0].strip().lower() == "application/json"
        and wire_code == "guardian_all_routes_failed"
        and wire_primary.request_count == 1
        and wire_record is not None
        and wire_record.outcome == "all_routes_failed"
        and len(wire_record.attempts) == 1
        and wire_record.attempts[0].get("code") == "http_503"
    )

    request_marker = f"G2_ERROR_REQUEST_{uuid.uuid4().hex}"
    codex_home, environment = _new_probe_environment("g2-codex-error-home-")
    result: dict[str, Any] | None = None
    try:
        with ProgrammableResponsesMock(_service_unavailable_scenario, route_name="P1") as primary:
            with ExperimentalFullBufferRelay(primary.base_url) as relay:
                exit_code, output = _run_codex_process(
                    command,
                    relay.base_url,
                    request_marker,
                    environment,
                    prompt=f"Local G2 structured error probe {request_marker}.",
                )
                if not relay.wait_for_records(1, timeout=5):
                    raise RuntimeError("codex_error_relay_record_missing")
                records = list(relay.records)
                captured = relay.ingress_requests[0] if relay.ingress_requests else None
        contract = _request_contract(captured)
        record = records[0] if len(records) == 1 else None
        attempt = record.attempts[0] if record is not None and len(record.attempts) == 1 else None
        result = {
            "ok": bool(
                wire_ok
                and exit_code != 0
                and primary.request_count == 1
                and len(records) == 1
                and record is not None
                and record.outcome == "all_routes_failed"
                and attempt is not None
                and attempt.get("source") == "primary"
                and attempt.get("code") == "http_503"
                and contract["ok"]
            ),
            "wire_status": wire_status,
            "wire_content_type": wire_content_type,
            "wire_error_code": wire_code,
            "wire_upstream_requests": wire_primary.request_count,
            "codex_exit_code": exit_code,
            "codex_request_contract": contract,
            "codex_upstream_requests": primary.request_count,
            "codex_relay_records": len(records),
            "codex_attempts": len(record.attempts) if record is not None else None,
            "codex_outcome": record.outcome if record is not None else None,
            "console_mentions_http_502": "502 Bad Gateway" in output,
            "retry_proof": "actual upstream and relay counts, not console line count",
            "request_max_retries": 0,
            "stream_max_retries": 0,
        }
    finally:
        _remove_probe_tree(codex_home)
    if result is None:
        raise RuntimeError("codex_error_probe_result_missing")
    result["isolated_codex_home_removed"] = not codex_home.exists()
    return result


def run_shell_tool_roundtrip_probe(command: str) -> dict[str, Any]:
    request_marker = f"G2_TOOL_REQUEST_{uuid.uuid4().hex}"
    response_marker = f"G2_TOOL_FINAL_{uuid.uuid4().hex}"
    execution_marker = "G2_TOOL_EXECUTED"
    call_id = f"call_g2_shell_{uuid.uuid4().hex}"
    item_id = f"fc_g2_shell_{uuid.uuid4().hex}"
    arguments = json.dumps({"command": f"Write-Output {execution_marker}"}, separators=(",", ":"))

    def scenario_for(captured: Any) -> ScriptedScenario:
        body = captured.json_body if captured is not None else None
        outputs = [
            node
            for node in _walk_dicts(body)
            if node.get("type") == "function_call_output"
        ]
        if outputs:
            matching = [
                node
                for node in outputs
                if node.get("call_id") == call_id
                and execution_marker in json.dumps(node.get("output"), ensure_ascii=False, sort_keys=True)
            ]
            if len(matching) == 1:
                return ScriptedScenario(
                    name="tool_final",
                    chunks=text_sse_frames(response_marker, response_id=f"resp_g2_tool_final_{uuid.uuid4().hex}"),
                )
            return ScriptedScenario(
                name="tool_output_mismatch",
                status=422,
                content_type="application/json",
                chunks=(b'{"error":{"type":"synthetic_tool_output_mismatch"}}',),
            )
        return ScriptedScenario(
            name="shell_tool_call",
            chunks=tool_sse_frames(
                response_id=f"resp_g2_shell_{uuid.uuid4().hex}",
                item_id=item_id,
                call_id=call_id,
                name="shell_command",
                arguments=arguments,
            ),
        )

    codex_home, environment = _new_probe_environment("g2-codex-tool-home-")
    result: dict[str, Any] | None = None
    try:
        with ProgrammableResponsesMock(scenario_for, route_name="P1") as primary:
            with ExperimentalFullBufferRelay(primary.base_url) as relay:
                exit_code, output = _run_codex_process(
                    command,
                    relay.base_url,
                    request_marker,
                    environment,
                    prompt=f"Local G2 shell tool round-trip probe {request_marker}.",
                    timeout=60,
                )
                if not relay.wait_for_records(2, timeout=5):
                    raise RuntimeError("codex_tool_roundtrip_records_missing")
                records = list(relay.records)
                captured_requests = list(relay.ingress_requests)
        first = captured_requests[0] if len(captured_requests) >= 1 else None
        second = captured_requests[1] if len(captured_requests) >= 2 else None
        first_body = first.json_body if first is not None else None
        second_body = second.json_body if second is not None else None
        shell_tools = [
            tool
            for tool in (first_body.get("tools", []) if isinstance(first_body, dict) else [])
            if isinstance(tool, dict) and tool.get("type") == "function" and tool.get("name") == "shell_command"
        ]
        function_outputs = [
            node
            for node in _walk_dicts(second_body)
            if node.get("type") == "function_call_output" and node.get("call_id") == call_id
        ]
        matching_outputs = [
            node
            for node in function_outputs
            if execution_marker in json.dumps(node.get("output"), ensure_ascii=False, sort_keys=True)
        ]
        request_bodies_text = json.dumps(
            [request.json_body for request in captured_requests],
            ensure_ascii=False,
            sort_keys=True,
        )
        result = {
            "ok": bool(
                exit_code == 0
                and response_marker in output
                and response_marker not in request_bodies_text
                and request_marker in request_bodies_text
                and primary.request_count == 2
                and len(captured_requests) == 2
                and len(records) == 2
                and all(record.outcome == "delivered" for record in records)
                and all(len(record.attempts) == 1 for record in records)
                and _request_contract(first)["ok"]
                and _request_contract(second)["ok"]
                and len(shell_tools) == 1
                and "command" in ((shell_tools[0].get("parameters") or {}).get("required") or [])
                and len(matching_outputs) == 1
            ),
            "exit_code": exit_code,
            "upstream_requests": primary.request_count,
            "relay_records": len(records),
            "relay_outcomes": [record.outcome for record in records],
            "first_request_contract": _request_contract(first),
            "second_request_contract": _request_contract(second),
            "shell_command_descriptor_count": len(shell_tools),
            "matching_function_call_outputs": len(matching_outputs),
            "call_id_roundtrip_matched": len(matching_outputs) == 1,
            "execution_output_seen_in_second_request": len(matching_outputs) == 1,
            "distinct_final_nonce_received": response_marker in output,
            "final_nonce_absent_from_requests": response_marker not in request_bodies_text,
            "request_max_retries": 0,
            "stream_max_retries": 0,
        }
    finally:
        _remove_probe_tree(codex_home)
    if result is None:
        raise RuntimeError("codex_tool_probe_result_missing")
    result["isolated_codex_home_removed"] = not codex_home.exists()
    return result


def build_report(args: argparse.Namespace) -> dict[str, Any]:
    command = _codex_command(args.codex)
    codex_version = _codex_version(command)
    source_binding = _source_binding()
    report: dict[str, Any] = {
        "schema_version": 2,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_head": source_binding["head"],
        "source_binding": source_binding,
        "environment": {
            "os": platform.platform(),
            "python": platform.python_version(),
            "codex": codex_version,
            "codex_supported": codex_version == "codex-cli 0.144.1",
        },
    }
    report["zero_header_probe"] = run_zero_header_probe(args.gate_seconds)
    report["state_fixture"] = run_state_fixture()
    report["models_probe"] = run_models_probe()
    report["codex_probe"] = run_codex_probe(command, args.gate_seconds)
    report["service_unavailable_probe"] = run_service_unavailable_probe(command)
    report["shell_tool_roundtrip"] = run_shell_tool_roundtrip_probe(command)
    source_binding_after = _source_binding()
    report["source_binding_after"] = source_binding_after
    source_stable = source_binding_after == source_binding
    report["ok"] = bool(
        report["environment"]["codex_supported"]
        and source_binding["ok"]
        and source_binding["clean"]
        and source_stable
        and all(
        section.get("ok") is True
        for section in (
            report["zero_header_probe"],
            report["state_fixture"],
            report["models_probe"],
            report["codex_probe"],
            report["service_unavailable_probe"],
            report["shell_tool_roundtrip"],
        )
        )
    )
    return report


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Offline Guardian Responses protocol probe")
    parser.add_argument("--codex", help="Path to codex/codex.cmd")
    parser.add_argument("--gate-seconds", type=float, default=1.0)
    parser.add_argument("--report", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.gate_seconds < 0.2 or args.gate_seconds > 30:
        raise SystemExit("--gate-seconds must be between 0.2 and 30")
    try:
        report = build_report(args)
    except Exception as exc:
        report = {
            "schema_version": 1,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "ok": False,
            "probe_error_type": type(exc).__name__,
        }
    rendered = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True)
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0 if report.get("ok") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
