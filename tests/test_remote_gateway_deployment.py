from __future__ import annotations

import json
import ast
import base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path, PurePosixPath
import socket
import tempfile
import threading
import unittest
from unittest.mock import patch

from backend.remote_gateway import BoundedProcessResult
from backend.remote_gateway import NasCompatibilityDecision
from backend.remote_gateway_deployment import (
    DEPLOYMENT_PROTOCOL,
    DEPLOYMENT_REMOTE_COMMAND,
    NasDeploymentEnvelope,
    NasDeploymentTransportError,
    NasSshDeploymentTransport,
    deployment_plan_from_decision,
    parse_deployment_receipt,
    render_deployment_stdin,
)
from gateway.platforms.linux import LinuxGatewayLayout
from gateway.platforms.linux_deployment import (
    LinuxDeploymentBundle,
    LinuxDeploymentPlan,
    LinuxVersionedReleaseStore,
)
from tests.test_gateway_g5_lifecycle import _config_document


def _receipt(*, ok: bool = True, recovered: bool = True) -> bytes:
    document = {
        "protocol": DEPLOYMENT_PROTOCOL,
        "ok": ok,
        "error_code": None if ok else "nas_deployment_transaction_failed",
        "recovered": recovered,
        "active_version": "v1.7.0" if ok else None,
        "manifest_sha256": "a" * 64 if ok else None,
        "config_sha256": "b" * 64 if ok else None,
    }
    return json.dumps(document, separators=(",", ":")).encode()


class RecordingRunner:
    def __init__(self, result: BoundedProcessResult) -> None:
        self.result = result
        self.calls = []

    def __call__(self, command, stdin, timeout, max_stdout, max_stderr):
        self.calls.append((list(command), stdin, timeout, max_stdout, max_stderr))
        return self.result


class _WorkerGatewayHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):
        return

    def _send(self, document):
        payload = json.dumps(document, separators=(",", ":")).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        if self.path == "/health":
            self._send(self.server.health)
        elif self.path == "/v1/models":
            self._send({"object": "list", "data": [{"id": item} for item in self.server.models]})
        elif self.path == "/control/v1/status":
            self._send(self.server.status)
        else:
            self.send_error(404)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = json.loads(self.rfile.read(length) or b"{}")
        self.server.requests.append((self.path, body))
        if self.path == "/control/v1/drain":
            self._send({"ok": True, "phase": "draining", "active_requests": 0})
        else:
            self.send_error(404)


def _worker_helpers(rendered: bytes) -> dict[str, object]:
    tree = ast.parse(rendered.decode("utf-8"))
    selected = []
    names = {
        "cron_without_managed",
        "cron_content",
        "service",
        "validate_config",
        "require_ports_available",
        "request_json",
        "drain_gateway",
        "verify_gateway",
    }
    for node in tree.body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            selected.append(node)
        elif isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id in {"CRON_BEGIN", "CRON_END"}
            for target in node.targets
        ):
            selected.append(node)
        elif isinstance(node, ast.FunctionDef) and node.name in names:
            selected.append(node)
    namespace: dict[str, object] = {}
    exec(compile(ast.Module(body=selected, type_ignores=[]), "<nas-worker>", "exec"), namespace)
    return namespace


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


class RemoteGatewayDeploymentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        source = self.root / "source"
        (source / "bin").mkdir(parents=True)
        (source / "bin" / "guardian-gateway").write_text("fixture", encoding="utf-8")
        (source / "bin" / "guardian-gateway-supervisor").write_text(
            "fixture-supervisor",
            encoding="utf-8",
        )
        layout = LinuxGatewayLayout(self.root / "home")
        store = LinuxVersionedReleaseStore(
            layout,
            transaction_id_factory=lambda: "fixturetx0001",
        )
        release = store.install("v1.7.0", source, architecture="x86_64")
        config = _config_document(
            primary_url="https://primary.fixture.invalid/v1",
            backup_url="https://backup.fixture.invalid/v1",
            data_port=43117,
            control_port=43118,
            revision=1,
        )
        config["gateway_version"] = "v1.7.0"
        config["active_group"]["primary"]["profile_id"] = "primary"
        config["active_group"]["primary"]["secret_ref"] = "profile:primary:r1"
        config["active_group"]["backup"]["profile_id"] = "backup"
        config["active_group"]["backup"]["secret_ref"] = "profile:backup:r1"
        bundle = LinuxDeploymentBundle(
            config=config,
            secrets={
                "primary.r1": "fixture-secret-never-output",
                "backup.r1": "fixture-secret-never-output-backup",
            },
        )
        plan = LinuxDeploymentPlan("x86_64", "locked_venv", "systemd_user")
        self.envelope = NasDeploymentEnvelope.from_release(release, bundle, plan)
        self.host = {"target": "fixture-nas", "port": 22}

    def test_fixed_command_and_all_sensitive_material_stays_in_stdin(self) -> None:
        runner = RecordingRunner(BoundedProcessResult(0, _receipt(), b""))
        result = NasSshDeploymentTransport(runner=runner).deploy(self.host, self.envelope)
        self.assertTrue(result["ok"])
        command, stdin, _timeout, _max_stdout, _max_stderr = runner.calls[0]
        self.assertEqual(command[-1], DEPLOYMENT_REMOTE_COMMAND)
        command_text = "\0".join(command).lower()
        self.assertNotIn("fixture-secret", command_text)
        self.assertNotIn("authorization", command_text)
        self.assertNotIn(".codex", command_text)
        self.assertNotIn(b"fixture-secret-never-output", stdin)
        payload_line = next(
            line for line in stdin.decode("utf-8").splitlines() if line.startswith("payload_b64 = ")
        )
        encoded = ast.literal_eval(payload_line.split("=", 1)[1].strip())
        decoded = base64.b64decode(encoded, validate=True)
        self.assertIn(b"fixture-secret-never-output", decoded)
        self.assertIn(b"systemctl", stdin)
        self.assertNotIn(b"fixture-secret-never-output", _receipt())

    def test_cron_supervisor_is_the_only_secondary_executable(self) -> None:
        modes = {str(item["path"]): item["mode"] for item in self.envelope.files}
        self.assertEqual(modes["bin/guardian-gateway"], 0o700)
        self.assertEqual(modes["bin/guardian-gateway-supervisor"], 0o700)

    def test_release_change_is_rejected_before_runner(self) -> None:
        file = self.envelope.files[0]
        changed = dict(file)
        changed["data_b64"] = "AAAA"
        files = list(self.envelope.files)
        files[0] = changed
        invalid = NasDeploymentEnvelope(
            version=self.envelope.version,
            architecture=self.envelope.architecture,
            package_mode=self.envelope.package_mode,
            supervisor=self.envelope.supervisor,
            entrypoint=self.envelope.entrypoint,
            manifest_sha256=self.envelope.manifest_sha256,
            manifest_b64=self.envelope.manifest_b64,
            files=tuple(files),
            config=self.envelope.config,
            secrets=self.envelope.secrets,
        )
        with self.assertRaisesRegex(NasDeploymentTransportError, "nas_deployment_release_changed"):
            render_deployment_stdin(invalid)

    def test_receipt_is_strict_and_never_accepts_extra_or_hostile_fields(self) -> None:
        self.assertTrue(parse_deployment_receipt(_receipt())["ok"])
        invalid = json.loads(_receipt())
        invalid["secret"] = "leak"
        with self.assertRaisesRegex(NasDeploymentTransportError, "nas_deployment_output_invalid"):
            parse_deployment_receipt(json.dumps(invalid).encode())
        invalid = json.loads(_receipt(ok=False))
        invalid["error_code"] = "hostile\nBearer secret"
        with self.assertRaisesRegex(NasDeploymentTransportError, "nas_deployment_output_invalid"):
            parse_deployment_receipt(json.dumps(invalid).encode())

    def test_timeout_nonzero_and_hostile_stderr_return_stable_codes(self) -> None:
        scenarios = (
            (
                BoundedProcessResult(-9, b"", b"Bearer fixture-secret", timed_out=True),
                "nas_deployment_timeout",
            ),
            (
                BoundedProcessResult(255, b"", b"Authorization: secret"),
                "nas_deployment_ssh_failed",
            ),
            (
                BoundedProcessResult(0, b"x", b"", stdout_truncated=True),
                "nas_deployment_output_too_large",
            ),
        )
        for completed, code in scenarios:
            with self.subTest(code=code):
                runner = RecordingRunner(completed)
                with self.assertRaisesRegex(NasDeploymentTransportError, code):
                    NasSshDeploymentTransport(runner=runner).deploy(self.host, self.envelope)

    def test_failed_remote_receipt_preserves_recovered_state(self) -> None:
        runner = RecordingRunner(BoundedProcessResult(0, _receipt(ok=False, recovered=False), b""))
        result = NasSshDeploymentTransport(runner=runner).deploy(self.host, self.envelope)
        self.assertFalse(result["ok"])
        self.assertFalse(result["recovered"])
        self.assertEqual(result["error_code"], "nas_deployment_transaction_failed")

    def test_deployment_plan_requires_verified_compatible_decision(self) -> None:
        decision = NasCompatibilityDecision(
            compatible=True,
            package_mode="locked_venv",
            supervisor="systemd_user",
            blockers=(),
        )
        plan = deployment_plan_from_decision(decision, architecture="x86_64")
        self.assertEqual(plan.architecture, "x86_64")
        cron = NasCompatibilityDecision(
            compatible=True,
            package_mode="locked_venv",
            supervisor="cron_user",
            blockers=(),
        )
        cron_plan = deployment_plan_from_decision(cron, architecture="x86_64")
        self.assertEqual(cron_plan.supervisor, "cron_user")
        incompatible = NasCompatibilityDecision(
            compatible=False,
            package_mode=None,
            supervisor=None,
            blockers=("nas_python_unavailable",),
        )
        with self.assertRaisesRegex(
            NasDeploymentTransportError,
            "nas_deployment_environment_incompatible",
        ):
            deployment_plan_from_decision(incompatible, architecture="x86_64")

    def test_remote_worker_rechecks_manifest_environment_and_ports(self) -> None:
        stdin = render_deployment_stdin(self.envelope)
        self.assertIn(b"validate_manifest(document)", stdin)
        self.assertIn(b"require_environment(document)", stdin)
        self.assertIn(b"probe.bind", stdin)
        self.assertIn(b"systemctl", stdin)
        self.assertIn(b"crontab", stdin)
        self.assertIn(b"/control/v1/drain", stdin)
        self.assertIn(b"control.token", stdin)
        self.assertNotIn(b".codex", stdin)

    def test_remote_worker_helpers_use_old_drain_and_verify_all_new_endpoints(self) -> None:
        helpers = _worker_helpers(render_deployment_stdin(self.envelope))
        old_port = _free_port()
        data_port = _free_port()
        control_port = _free_port()
        while control_port in {old_port, data_port}:
            control_port = _free_port()
        old_server = ThreadingHTTPServer(("127.0.0.1", old_port), _WorkerGatewayHandler)
        data_server = ThreadingHTTPServer(("127.0.0.1", data_port), _WorkerGatewayHandler)
        control_server = ThreadingHTTPServer(("127.0.0.1", control_port), _WorkerGatewayHandler)
        instance = "fixture-nas-instance"
        revision = 7
        process = "fixture-process"
        data_server.health = {
            "ok": True,
            "version": "v1.7.0",
            "instance_id": instance,
            "config_revision": revision,
            "process_instance_id": process,
            "accepting": True,
        }
        data_server.models = ["fixture-model"]
        control_server.status = {
            "ok": True,
            "phase": "running",
            "version": "v1.7.0",
            "instance_id": instance,
            "config_revision": revision,
            "process_instance_id": process,
            "data_port": data_port,
            "control_port": control_port,
        }
        for server in (old_server, data_server, control_server):
            server.requests = []
            server.health = getattr(server, "health", {})
            server.models = getattr(server, "models", [])
            server.status = getattr(server, "status", {})
        threads = [threading.Thread(target=server.serve_forever, daemon=True) for server in (old_server, data_server, control_server)]
        for thread in threads:
            thread.start()
        helpers["read_token"] = lambda _path: "fixture-token"
        old_config = {
            "listen": {"host": "127.0.0.1", "data_port": _free_port(), "control_port": old_port},
            "lifecycle": {"drain_timeout_seconds": 1},
        }
        new_config = {
            "gateway_version": "v1.7.0",
            "instance_id": instance,
            "listen": {"host": "127.0.0.1", "data_port": data_port, "control_port": control_port},
            "active_group": {"revision": revision, "allowed_models": ["fixture-model"]},
        }
        try:
            helpers["drain_gateway"](self.root, old_config)
            helpers["verify_gateway"](self.root, new_config)
        finally:
            for server in (old_server, data_server, control_server):
                server.shutdown()
                server.server_close()
        self.assertEqual(old_server.requests, [("/control/v1/drain", {"timeout_seconds": 1})])

    def test_gateway_verification_retries_token_creation_during_async_start(self) -> None:
        helpers = _worker_helpers(render_deployment_stdin(self.envelope))
        attempts = 0

        def read_token(_path):
            nonlocal attempts
            attempts += 1
            if attempts < 3:
                raise RuntimeError("nas_deployment_token_invalid")
            return "fixture-token"

        helpers["read_token"] = read_token
        helpers["request_json"] = lambda _port, _method, path, _token, **_kwargs: (
            {
                "ok": True,
                "version": "v1.7.0",
                "instance_id": "fixture-instance",
                "config_revision": 1,
                "process_instance_id": "fixture-process",
                "accepting": True,
            }
            if path == "/health"
            else {"data": [{"id": "fixture-model"}]}
            if path == "/v1/models"
            else {
                "ok": True,
                "phase": "running",
                "version": "v1.7.0",
                "instance_id": "fixture-instance",
                "config_revision": 1,
                "process_instance_id": "fixture-process",
                "data_port": 43117,
                "control_port": 43118,
            }
        )
        helpers["verify_gateway"](
            self.root,
            {
                "gateway_version": "v1.7.0",
                "instance_id": "fixture-instance",
                "listen": {"host": "127.0.0.1", "data_port": 43117, "control_port": 43118},
                "active_group": {"revision": 1, "allowed_models": ["fixture-model"]},
            },
        )
        self.assertEqual(attempts, 4)

    def test_remote_worker_service_invocation_is_fixed_and_silent(self) -> None:
        helpers = _worker_helpers(render_deployment_stdin(self.envelope))
        with patch("subprocess.run") as run:
            helpers["service"]("restart", "codex-profile-guardian-gateway.service")
        command = run.call_args.args[0]
        self.assertEqual(command, ["systemctl", "--user", "restart", "codex-profile-guardian-gateway.service"])
        self.assertNotIn("fixture-secret", "\0".join(command))

    def test_cron_block_preserves_user_entries_and_quotes_fixed_paths(self) -> None:
        helpers = _worker_helpers(render_deployment_stdin(self.envelope))
        previous = b"MAILTO=user@example.test\n15 4 * * * /usr/bin/fixture\n"
        content = helpers["cron_content"](
            previous,
            PurePosixPath("/home/fixture user/release/bin/guardian-gateway-supervisor"),
            PurePosixPath("/home/fixture user/share"),
            PurePosixPath("/home/fixture user/config"),
            PurePosixPath("/home/fixture user"),
        ).decode("utf-8")
        self.assertIn("MAILTO=user@example.test", content)
        self.assertIn("15 4 * * * /usr/bin/fixture", content)
        self.assertEqual(content.count("# BEGIN CODEX PROFILE GUARDIAN GATEWAY"), 1)
        self.assertIn("'/home/fixture user/release/bin/guardian-gateway-supervisor'", content)
        self.assertEqual(
            helpers["cron_without_managed"](content.encode("utf-8")),
            previous.decode("utf-8").rstrip(),
        )

    def test_cron_block_rejects_partial_or_duplicate_managed_sections(self) -> None:
        helpers = _worker_helpers(render_deployment_stdin(self.envelope))
        invalid = (
            b"# BEGIN CODEX PROFILE GUARDIAN GATEWAY\n",
            b"# END CODEX PROFILE GUARDIAN GATEWAY\n",
            b"# BEGIN CODEX PROFILE GUARDIAN GATEWAY\n"
            b"# END CODEX PROFILE GUARDIAN GATEWAY\n"
            b"# BEGIN CODEX PROFILE GUARDIAN GATEWAY\n"
            b"# END CODEX PROFILE GUARDIAN GATEWAY\n",
        )
        for content in invalid:
            with self.subTest(content=content):
                with self.assertRaisesRegex(RuntimeError, "nas_deployment_crontab_invalid"):
                    helpers["cron_without_managed"](content)


if __name__ == "__main__":
    unittest.main()
