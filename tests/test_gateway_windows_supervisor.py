from __future__ import annotations

from http.client import HTTPConnection
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time
import unittest
import uuid
import xml.etree.ElementTree as ElementTree
from unittest.mock import patch

from gateway.dpapi import protect_current_user, unprotect_current_user
from gateway.platforms.windows import (
    CurrentUserScheduledTask,
    ReleaseError,
    SingleInstanceError,
    VersionedReleaseStore,
    WindowsGatewayLayout,
    WindowsSingleInstanceMutex,
)
from gateway.supervisor import (
    BoundedRestartSupervisor,
    ChildExitKind,
    CONFIGURATION_ERROR_EXIT_CODE,
    GatewaySupervisorRunner,
    RestartPolicy,
    SUPERVISOR_SAFE_STOP_EXIT_CODE,
    SupervisorAction,
    classify_child_exit,
)
from gateway.runtime_files import RuntimeDescriptor, RuntimeDescriptorStore
from tests.gateway_probe_support import (
    FAKE_BEARER,
    FIXTURE_MODEL,
    ProgrammableResponsesMock,
    fixture_request,
    text_scenario,
)


GATEWAY_VERSION = "v1.7.0"


def _free_port(*, excluding: set[int] | None = None) -> int:
    blocked = excluding or set()
    while True:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(("127.0.0.1", 0))
            port = int(probe.getsockname()[1])
        if port >= 1024 and port not in blocked:
            return port


def _gateway_config(
    *,
    primary_url: str,
    backup_url: str,
    data_port: int,
    control_port: int,
) -> dict[str, object]:
    route_common = {
        "adapter_name": "openai-responses-v1",
        "enabled": True,
    }
    return {
        "schema_version": 1,
        "instance_id": "g5-supervisor-fixture",
        "gateway_version": GATEWAY_VERSION,
        "listen": {
            "host": "127.0.0.1",
            "data_port": data_port,
            "control_port": control_port,
        },
        "limits": {
            "max_request_bytes": 1024 * 1024,
            "max_response_bytes": 1024 * 1024,
            "read_chunk_bytes": 4096,
            "max_concurrent_requests": 4,
            "connect_timeout_seconds": 1,
            "first_byte_timeout_seconds": 1,
            "idle_timeout_seconds": 2,
            "total_timeout_seconds": 5,
        },
        "lifecycle": {
            "minimum_free_bytes": 1024 * 1024,
            "drain_timeout_seconds": 2,
        },
        "active_group": {
            "revision": 1,
            "group_id": "g5-supervisor-fixture-group",
            "primary": {
                **route_common,
                "profile_id": "g5-supervisor-primary",
                "base_url": primary_url,
                "secret_ref": "profile:g5-supervisor-primary",
                "secret_suffix": "P1",
            },
            "backup": {
                **route_common,
                "profile_id": "g5-supervisor-backup",
                "base_url": backup_url,
                "secret_ref": "profile:g5-supervisor-backup",
                "secret_suffix": "P2",
            },
            "allowed_models": [FIXTURE_MODEL],
            "breaker_policy": {
                "failure_threshold": 1,
                "protocol_failure_threshold": 1,
                "error_rate_threshold": None,
                "minimum_samples": 1,
                "window_size": 8,
                "recovery_success_threshold": 1,
                "base_cooldown_seconds": 30,
                "max_cooldown_seconds": 300,
                "jitter_ratio": 0,
            },
            "probe_policy": {
                "enabled": False,
                "mode": "models",
                "interval_seconds": 30,
                "timeout_seconds": 1,
                "allow_billable": False,
                "allow_action_required_auto_retest": False,
            },
            "state_compatibility": {},
        },
    }


def _process_is_running(pid: int) -> bool:
    if os.name != "nt" or pid <= 0:
        return False
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.GetExitCodeProcess.argtypes = (wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD))
    kernel32.GetExitCodeProcess.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel32.CloseHandle.restype = wintypes.BOOL
    handle = kernel32.OpenProcess(0x1000, False, pid)
    if not handle:
        return False
    try:
        exit_code = wintypes.DWORD()
        return bool(kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code))) and exit_code.value == 259
    finally:
        kernel32.CloseHandle(handle)


def _process_parent_pid(pid: int) -> int | None:
    if os.name != "nt" or pid <= 0:
        return None
    import ctypes
    from ctypes import wintypes

    class ProcessBasicInformation(ctypes.Structure):
        _fields_ = (
            ("reserved1", ctypes.c_void_p),
            ("peb_base_address", ctypes.c_void_p),
            ("reserved2", ctypes.c_void_p * 2),
            ("unique_process_id", ctypes.c_size_t),
            ("inherited_from_unique_process_id", ctypes.c_size_t),
        )

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    ntdll = ctypes.WinDLL("ntdll")
    kernel32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel32.CloseHandle.restype = wintypes.BOOL
    ntdll.NtQueryInformationProcess.argtypes = (
        wintypes.HANDLE,
        wintypes.ULONG,
        ctypes.c_void_p,
        wintypes.ULONG,
        ctypes.POINTER(wintypes.ULONG),
    )
    ntdll.NtQueryInformationProcess.restype = wintypes.LONG
    handle = kernel32.OpenProcess(0x0400, False, pid)
    if not handle:
        return None
    try:
        information = ProcessBasicInformation()
        returned = wintypes.ULONG()
        status = ntdll.NtQueryInformationProcess(
            handle,
            0,
            ctypes.byref(information),
            ctypes.sizeof(information),
            ctypes.byref(returned),
        )
        if status != 0:
            return None
        return int(information.inherited_from_unique_process_id)
    finally:
        kernel32.CloseHandle(handle)


def _terminate_process(pid: int) -> None:
    if os.name != "nt" or pid <= 0 or pid == os.getpid():
        return
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.TerminateProcess.argtypes = (wintypes.HANDLE, wintypes.UINT)
    kernel32.TerminateProcess.restype = wintypes.BOOL
    kernel32.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
    kernel32.WaitForSingleObject.restype = wintypes.DWORD
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel32.CloseHandle.restype = wintypes.BOOL
    handle = kernel32.OpenProcess(0x0001 | 0x00100000, False, pid)
    if not handle:
        return
    try:
        kernel32.TerminateProcess(handle, 137)
        kernel32.WaitForSingleObject(handle, 5000)
    finally:
        kernel32.CloseHandle(handle)


def _wait_for_descriptor(
    store: RuntimeDescriptorStore,
    *,
    different_from: RuntimeDescriptor | None = None,
    timeout: float = 15,
) -> RuntimeDescriptor:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            descriptor = store.read()
        except (FileNotFoundError, RuntimeError):
            time.sleep(0.05)
            continue
        if different_from is not None and (
            descriptor.pid == different_from.pid
            or descriptor.process_instance_id == different_from.process_instance_id
        ):
            time.sleep(0.05)
            continue
        if _process_is_running(descriptor.pid):
            return descriptor
        time.sleep(0.05)
    raise AssertionError("gateway_runtime_descriptor_timeout")


def _http(
    port: int,
    method: str,
    path: str,
    token: str,
    body: bytes | None = None,
) -> tuple[int, bytes]:
    connection = HTTPConnection("127.0.0.1", port, timeout=5)
    headers = {"Authorization": f"Bearer {token}"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    try:
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()


def _wait_for_process_exit(pid: int, timeout: float = 10) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not _process_is_running(pid):
            return True
        time.sleep(0.05)
    return not _process_is_running(pid)


class BoundedRestartSupervisorTests(unittest.TestCase):
    def test_crashes_restart_with_bounded_backoff_then_latch_safe_stop(self) -> None:
        supervisor = BoundedRestartSupervisor(
            RestartPolicy(
                max_restarts=3,
                window_seconds=60,
                base_delay_seconds=2,
                max_delay_seconds=5,
                stable_run_reset_seconds=300,
            )
        )
        decisions = [
            supervisor.observe_exit(
                ChildExitKind.CRASH,
                exited_at=float(index),
                run_duration_seconds=1,
            )
            for index in range(4)
        ]
        self.assertEqual(
            [decision.action for decision in decisions],
            [
                SupervisorAction.RESTART,
                SupervisorAction.RESTART,
                SupervisorAction.RESTART,
                SupervisorAction.SAFE_STOP,
            ],
        )
        self.assertEqual([decision.delay_seconds for decision in decisions[:3]], [2, 4, 5])
        self.assertEqual(decisions[-1].reason, "crash_loop")
        self.assertTrue(supervisor.safe_stopped)
        still_stopped = supervisor.observe_exit(
            ChildExitKind.CRASH,
            exited_at=5,
            run_duration_seconds=1,
        )
        self.assertEqual(still_stopped.action, SupervisorAction.SAFE_STOP)
        supervisor.reset_after_operator_action()
        self.assertFalse(supervisor.safe_stopped)
        self.assertTrue(
            supervisor.observe_exit(
                ChildExitKind.CRASH,
                exited_at=1,
                run_duration_seconds=1,
            ).should_restart
        )

    def test_configuration_error_never_restarts(self) -> None:
        supervisor = BoundedRestartSupervisor()
        decision = supervisor.observe_exit(
            ChildExitKind.CONFIGURATION_ERROR,
            exited_at=1,
            run_duration_seconds=0.01,
        )
        self.assertEqual(decision.action, SupervisorAction.SAFE_STOP)
        self.assertEqual(decision.reason, "configuration_error")
        self.assertEqual(
            classify_child_exit(CONFIGURATION_ERROR_EXIT_CODE),
            ChildExitKind.CONFIGURATION_ERROR,
        )

    def test_clean_and_requested_stops_do_not_restart(self) -> None:
        for kind in (ChildExitKind.CLEAN, ChildExitKind.REQUESTED_STOP):
            with self.subTest(kind=kind):
                supervisor = BoundedRestartSupervisor()
                decision = supervisor.observe_exit(kind, exited_at=1, run_duration_seconds=10)
                self.assertEqual(decision.action, SupervisorAction.STOP)
                self.assertFalse(decision.should_restart)
        self.assertEqual(classify_child_exit(0), ChildExitKind.CLEAN)
        self.assertEqual(classify_child_exit(123), ChildExitKind.CRASH)
        self.assertEqual(classify_child_exit(123, stop_requested=True), ChildExitKind.REQUESTED_STOP)

    def test_stable_run_and_window_expiry_reset_crash_budget(self) -> None:
        policy = RestartPolicy(
            max_restarts=1,
            window_seconds=10,
            base_delay_seconds=1,
            max_delay_seconds=2,
            stable_run_reset_seconds=20,
        )
        supervisor = BoundedRestartSupervisor(policy)
        first = supervisor.observe_exit(ChildExitKind.CRASH, exited_at=1, run_duration_seconds=1)
        expired = supervisor.observe_exit(ChildExitKind.CRASH, exited_at=12, run_duration_seconds=1)
        stable = supervisor.observe_exit(ChildExitKind.CRASH, exited_at=13, run_duration_seconds=20)
        self.assertTrue(first.should_restart)
        self.assertTrue(expired.should_restart)
        self.assertTrue(stable.should_restart)
        self.assertEqual(stable.crashes_in_window, 1)

    def test_snapshot_restores_crash_loop_latch_without_sensitive_fields(self) -> None:
        policy = RestartPolicy(max_restarts=0)
        source = BoundedRestartSupervisor(policy)
        source.observe_exit(ChildExitKind.CRASH, exited_at=7, run_duration_seconds=1)
        snapshot = source.snapshot()
        serialized = json.dumps(snapshot, sort_keys=True)
        for forbidden in ("authorization", "cookie", "prompt", "secret", "token"):
            self.assertNotIn(forbidden, serialized.lower())
        restored = BoundedRestartSupervisor.restore(policy, snapshot)
        self.assertTrue(restored.safe_stopped)
        self.assertEqual(restored.safe_stop_reason, "crash_loop")


class GatewaySupervisorRunnerTests(unittest.TestCase):
    @staticmethod
    def install_release(root: Path) -> tuple[WindowsGatewayLayout, Path]:
        layout = WindowsGatewayLayout(root / "fixture-install")
        source = root / "release-source"
        source.mkdir()
        (source / "GuardianGateway.exe").write_text("fixture-executable", encoding="utf-8")
        store = VersionedReleaseStore(layout, transaction_id_factory=lambda: "fixturetx0001")
        store.install("v1.7.0", source)
        store.activate("v1.7.0")
        config = layout.config / "active.json"
        config.parent.mkdir(parents=True)
        config.write_text("{}", encoding="utf-8")
        return layout, config

    def test_runner_bounds_real_process_restarts_and_persists_safe_stop(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            layout, config = self.install_release(Path(directory))
            commands: list[tuple[str, ...]] = []
            exit_codes = iter((1, 1, 1))

            class Process:
                def __init__(self, code: int) -> None:
                    self.code = code

                def wait(self) -> int:
                    return self.code

            def process_factory(command, **kwargs):
                commands.append(tuple(command))
                self.assertEqual(kwargs["stdin"], -3)
                self.assertEqual(kwargs["stdout"], -3)
                self.assertEqual(kwargs["stderr"], -3)
                return Process(next(exit_codes))

            monotonic_values = iter((0.0, 0.1, 1.0, 1.1, 2.0, 2.1))
            wall_values = iter((100.0, 101.0, 102.0))
            delays: list[float] = []
            runner = GatewaySupervisorRunner(
                layout,
                config,
                policy=RestartPolicy(
                    max_restarts=2,
                    window_seconds=60,
                    base_delay_seconds=1,
                    max_delay_seconds=2,
                    stable_run_reset_seconds=300,
                ),
                process_factory=process_factory,
                monotonic_clock=lambda: next(monotonic_values),
                wall_clock=lambda: next(wall_values),
                sleep=delays.append,
            )
            self.assertEqual(runner.run(), SUPERVISOR_SAFE_STOP_EXIT_CODE)
            self.assertEqual(len(commands), 3)
            self.assertEqual(delays, [1, 2])
            serialized = " ".join(part for command in commands for part in command).lower()
            for forbidden in ("authorization", "bearer ", "api-sk-", "password", "token"):
                self.assertNotIn(forbidden, serialized)

            no_process_calls: list[tuple[str, ...]] = []
            restarted = GatewaySupervisorRunner(
                layout,
                config,
                process_factory=lambda command, **_kwargs: no_process_calls.append(tuple(command)),
            )
            self.assertEqual(restarted.run(), SUPERVISOR_SAFE_STOP_EXIT_CODE)
            self.assertEqual(no_process_calls, [])

    def test_configuration_error_child_stops_without_restart(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            layout, config = self.install_release(Path(directory))
            calls = 0

            class Process:
                @staticmethod
                def wait() -> int:
                    return CONFIGURATION_ERROR_EXIT_CODE

            def process_factory(_command, **_kwargs):
                nonlocal calls
                calls += 1
                return Process()

            monotonic_values = iter((0.0, 0.1))
            runner = GatewaySupervisorRunner(
                layout,
                config,
                process_factory=process_factory,
                monotonic_clock=lambda: next(monotonic_values),
                wall_clock=lambda: 100.0,
                sleep=lambda _seconds: self.fail("configuration errors must not restart"),
            )
            self.assertEqual(runner.run(), CONFIGURATION_ERROR_EXIT_CODE)
            self.assertEqual(calls, 1)


@unittest.skipUnless(os.name == "nt", "Windows process supervision integration")
class GatewaySupervisorProcessIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.project_root = Path(__file__).resolve().parents[1]
        cls.venv_root = cls.project_root / ".venv"
        cls.python = cls.venv_root / "Scripts" / "python.exe"
        if not cls.python.is_file():
            raise unittest.SkipTest("project virtual environment unavailable")
        try:
            __import__("aiohttp")
        except ImportError as exc:
            raise unittest.SkipTest("gateway dependencies unavailable") from exc
        cls.bundle_temporary = tempfile.TemporaryDirectory()
        bundle_root = Path(cls.bundle_temporary.name)
        entrypoint = bundle_root / "gateway-fixture-entry.py"
        entrypoint.write_text(
            "from gateway.app import main\n"
            "raise SystemExit(main())\n",
            encoding="utf-8",
        )
        supervisor_entrypoint = bundle_root / "supervisor-fixture-entry.py"
        supervisor_entrypoint.write_text(
            "from gateway.supervisor import main\n"
            "raise SystemExit(main())\n",
            encoding="utf-8",
        )
        common_arguments = [
            str(cls.python),
            "-B",
            "-m",
            "PyInstaller",
            "--clean",
            "--noconfirm",
            "--onedir",
            "--console",
            "--paths",
            str(cls.project_root),
            "--distpath",
            str(bundle_root / "dist"),
            "--workpath",
            str(bundle_root / "build"),
            "--specpath",
            str(bundle_root),
        ]
        gateway_result = subprocess.run(
            [
                *common_arguments,
                "--name",
                "GuardianGateway",
                str(entrypoint),
            ],
            cwd=str(cls.project_root),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=120,
            check=False,
        )
        supervisor_result = subprocess.run(
            [
                *common_arguments,
                "--name",
                "GuardianGatewaySupervisor",
                str(supervisor_entrypoint),
            ],
            cwd=str(cls.project_root),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=120,
            check=False,
        )
        if gateway_result.returncode != 0 or supervisor_result.returncode != 0:
            cls.bundle_temporary.cleanup()
            raise RuntimeError("gateway_process_fixture_build_failed")
        cls.gateway_bundle = bundle_root / "dist" / "GuardianGateway"
        cls.gateway_executable = cls.gateway_bundle / "GuardianGateway.exe"
        cls.supervisor_executable = (
            bundle_root
            / "dist"
            / "GuardianGatewaySupervisor"
            / "GuardianGatewaySupervisor.exe"
        )
        if not cls.gateway_executable.is_file() or not cls.supervisor_executable.is_file():
            cls.bundle_temporary.cleanup()
            raise RuntimeError("gateway_process_fixture_executable_missing")

    @classmethod
    def tearDownClass(cls) -> None:
        cls.bundle_temporary.cleanup()

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.primary = ProgrammableResponsesMock(
            lambda _request: text_scenario(text="G5_SUPERVISOR_PRIMARY_OK"),
            route_name="P1",
        ).start()
        self.backup = ProgrammableResponsesMock(
            lambda _request: text_scenario(text="G5_SUPERVISOR_BACKUP_UNUSED"),
            route_name="P2",
        ).start()
        self.layout = WindowsGatewayLayout(self.root / "fixture-install")
        self.data_port = _free_port()
        self.control_port = _free_port(excluding={self.data_port})
        self.config = self._install_release()
        self.descriptor_store = RuntimeDescriptorStore(
            self.layout.gateway_root / "runtime" / "runtime.json"
        )
        self.control_token = self._read_token("control")
        self.ingress_token = self._read_token("ingress")
        self.supervisor_pid: int | None = None

    def tearDown(self) -> None:
        try:
            try:
                descriptor = self.descriptor_store.read()
            except (FileNotFoundError, RuntimeError):
                descriptor = None
            if descriptor is not None:
                try:
                    _http(
                        descriptor.control_port,
                        "POST",
                        "/control/v1/stop",
                        self.control_token,
                        b'{"timeout_seconds":1}',
                    )
                except OSError:
                    pass
                _wait_for_process_exit(descriptor.pid, timeout=5)
            if self.supervisor_pid is not None and _process_is_running(self.supervisor_pid):
                _terminate_process(self.supervisor_pid)
            try:
                descriptor = self.descriptor_store.read()
            except (FileNotFoundError, RuntimeError):
                descriptor = None
            if descriptor is not None and _process_is_running(descriptor.pid):
                _terminate_process(descriptor.pid)
        finally:
            self.primary.close()
            self.backup.close()
            self.temporary.cleanup()

    def _install_release(self) -> Path:
        source = self.root / "release-source"
        shutil.copytree(self.gateway_bundle, source)
        store = VersionedReleaseStore(
            self.layout,
            transaction_id_factory=lambda: "fixturetx0001",
        )
        store.install(GATEWAY_VERSION, source)
        store.activate(GATEWAY_VERSION)
        config = self.layout.config / "active.json"
        config.parent.mkdir(parents=True)
        config.write_text(
            json.dumps(
                _gateway_config(
                    primary_url=self.primary.base_url,
                    backup_url=self.backup.base_url,
                    data_port=self.data_port,
                    control_port=self.control_port,
                ),
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        profiles = self.layout.gateway_root / "secrets" / "profiles"
        profiles.mkdir(parents=True)
        for profile_id in ("g5-supervisor-primary", "g5-supervisor-backup"):
            (profiles / f"{profile_id}.dpapi").write_bytes(
                protect_current_user(FAKE_BEARER.encode("ascii"))
            )
        token_root = self.layout.gateway_root / "secrets" / "tokens"
        token_root.mkdir(parents=True)
        for purpose, token in (
            ("ingress", "A" * 64),
            ("control", "B" * 64),
        ):
            (token_root / f"{purpose}.token.dpapi").write_bytes(
                protect_current_user(token.encode("ascii"))
            )
        return config

    def _read_token(self, purpose: str) -> str:
        encrypted = (
            self.layout.gateway_root / "secrets" / "tokens" / f"{purpose}.token.dpapi"
        ).read_bytes()
        return unprotect_current_user(encrypted).decode("ascii")

    def _launch_and_discard_ui_parent(self) -> tuple[int, int]:
        supervisor_pid_file = self.root / "supervisor.pid"
        ui_launcher = self.root / "fixture-ui-launcher.py"
        ui_launcher.write_text(
            "from pathlib import Path\n"
            "import os\n"
            "import subprocess\n"
            "process = subprocess.Popen(\n"
            f"    [{str(self.supervisor_executable)!r}, "
            f"'--layout-root', {str(self.layout.root)!r}, "
            f"'--config-file', {str(self.config)!r}],\n"
            f"    cwd={str(self.supervisor_executable.parent)!r},\n"
            "    stdin=subprocess.DEVNULL,\n"
            "    stdout=subprocess.DEVNULL,\n"
            "    stderr=subprocess.DEVNULL,\n"
            "    creationflags=0x00000008 | 0x00000200 | 0x08000000,\n"
            ")\n"
            f"Path({str(supervisor_pid_file)!r}).write_text("
            "f'{os.getpid()}:{process.pid}', encoding='ascii')\n",
            encoding="utf-8",
        )
        launcher = subprocess.run(
            [str(self.python), "-B", str(ui_launcher)],
            cwd=str(self.project_root),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
            check=False,
        )
        self.assertEqual(launcher.returncode, 0)
        launcher_pid_text, supervisor_pid_text = supervisor_pid_file.read_text(
            encoding="ascii"
        ).split(":", 1)
        launcher_pid = int(launcher_pid_text)
        supervisor_pid = int(supervisor_pid_text)
        self.supervisor_pid = supervisor_pid
        return launcher_pid, supervisor_pid

    def test_ui_exit_gateway_survives_and_crash_is_restarted_on_fixed_ports(self) -> None:
        launcher_pid, supervisor_pid = self._launch_and_discard_ui_parent()
        first = _wait_for_descriptor(self.descriptor_store)

        self.assertFalse(_process_is_running(launcher_pid))
        self.assertTrue(_process_is_running(supervisor_pid))
        self.assertTrue(_process_is_running(first.pid))
        self.assertNotEqual(supervisor_pid, first.pid)
        self.assertNotEqual(_process_parent_pid(supervisor_pid), os.getpid())
        self.assertEqual(_process_parent_pid(first.pid), supervisor_pid)
        self.assertEqual((first.data_port, first.control_port), (self.data_port, self.control_port))

        status, body = _http(
            first.control_port,
            "GET",
            "/control/v1/status",
            self.control_token,
        )
        self.assertEqual(status, 200)
        status_document = json.loads(body)
        self.assertEqual(status_document["pid"], first.pid)
        self.assertEqual(status_document["process_instance_id"], first.process_instance_id)
        status, body = _http(
            first.data_port,
            "POST",
            "/v1/responses",
            self.ingress_token,
            fixture_request(),
        )
        self.assertEqual(status, 200)
        self.assertIn(b"response.completed", body)
        self.assertEqual((self.primary.request_count, self.backup.request_count), (1, 0))

        crashed_at = time.monotonic()
        _terminate_process(first.pid)
        self.assertTrue(_wait_for_process_exit(first.pid, timeout=5))
        second = _wait_for_descriptor(
            self.descriptor_store,
            different_from=first,
            timeout=15,
        )
        restarted_in = time.monotonic() - crashed_at

        self.assertLess(restarted_in, 15)
        self.assertTrue(_process_is_running(supervisor_pid))
        self.assertTrue(_process_is_running(second.pid))
        self.assertNotEqual(second.pid, first.pid)
        self.assertNotEqual(second.process_instance_id, first.process_instance_id)
        self.assertEqual(_process_parent_pid(second.pid), supervisor_pid)
        self.assertEqual((second.data_port, second.control_port), (self.data_port, self.control_port))
        status, body = _http(
            second.control_port,
            "GET",
            "/control/v1/status",
            self.control_token,
        )
        self.assertEqual(status, 200)
        status_document = json.loads(body)
        self.assertEqual(status_document["pid"], second.pid)
        self.assertEqual(status_document["process_instance_id"], second.process_instance_id)
        status, body = _http(
            second.data_port,
            "POST",
            "/v1/responses",
            self.ingress_token,
            fixture_request(),
        )
        self.assertEqual(status, 200)
        self.assertIn(b"response.completed", body)
        self.assertEqual((self.primary.request_count, self.backup.request_count), (2, 0))

        status, body = _http(
            second.control_port,
            "POST",
            "/control/v1/stop",
            self.control_token,
            b'{"timeout_seconds":1}',
        )
        self.assertEqual(status, 202)
        self.assertEqual(json.loads(body)["phase"], "stopping")
        self.assertTrue(_wait_for_process_exit(second.pid, timeout=10))
        self.assertTrue(_wait_for_process_exit(supervisor_pid, timeout=10))
        self.assertFalse(self.descriptor_store.path.exists())


class WindowsScheduledTaskTests(unittest.TestCase):
    def task(self, root: Path) -> CurrentUserScheduledTask:
        layout = WindowsGatewayLayout(root)
        return CurrentUserScheduledTask(
            task_name="CodexProfileGuardianGatewayFixture",
            user_id="FIXTURE\\guardian-user",
            supervisor_executable=root / "gateway" / "supervisor" / "GuardianGatewaySupervisor.exe",
            layout=layout,
            config_file=layout.config / "gateway-config.json",
        )

    def test_task_xml_is_current_user_least_privilege_hidden_and_single_instance(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            task = self.task(Path(directory))
            document = ElementTree.fromstring(task.render_xml())
            namespace = {"task": "http://schemas.microsoft.com/windows/2004/02/mit/task"}

            def text(path: str) -> str | None:
                node = document.find(path, namespace)
                return None if node is None else node.text

            self.assertEqual(text("task:Principals/task:Principal/task:UserId"), "FIXTURE\\guardian-user")
            self.assertEqual(text("task:Principals/task:Principal/task:LogonType"), "InteractiveToken")
            self.assertEqual(text("task:Principals/task:Principal/task:RunLevel"), "LeastPrivilege")
            self.assertEqual(text("task:Settings/task:MultipleInstancesPolicy"), "IgnoreNew")
            self.assertEqual(text("task:Settings/task:Hidden"), "true")
            self.assertEqual(text("task:Settings/task:StartWhenAvailable"), "true")
            self.assertIsNone(document.find("task:Settings/task:RestartOnFailure", namespace))
            self.assertEqual(
                text("task:Actions/task:Exec/task:Command"),
                str(task.supervisor_executable),
            )
            arguments = text("task:Actions/task:Exec/task:Arguments") or ""
            self.assertIn("--layout-root", arguments)
            self.assertIn("--config-file", arguments)
            self.assertNotIn("key", arguments.lower())
            self.assertNotIn("secret", arguments.lower())
            self.assertNotIn("token", arguments.lower())

    def test_schtasks_commands_are_data_only_and_contain_no_credentials(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            task = self.task(root)
            definition = root / "task-definitions" / "gateway.xml"
            commands = (
                task.registration_command(definition),
                task.query_command(),
                task.removal_command(),
            )
            self.assertEqual(commands[0][0].lower(), "schtasks.exe")
            self.assertIn("/Create", commands[0])
            self.assertIn("/Query", commands[1])
            self.assertIn("/Delete", commands[2])
            serialized = " ".join(part for command in commands for part in command).lower()
            for forbidden in ("api-sk-", "authorization", "bearer ", "password", "secret", "token"):
                self.assertNotIn(forbidden, serialized)

    def test_fixture_registration_and_uninstall_only_touch_definition(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            task = self.task(root)
            definitions = root / "fixture-task-scheduler"
            task.layout.config.mkdir(parents=True)
            task.layout.state.mkdir(parents=True)
            config = task.layout.config / "gateway-config.json"
            state = task.layout.state / "breaker.json"
            codex_data = root / "unrelated-codex-data" / "sessions" / "fixture.jsonl"
            config.write_text("fixture-config", encoding="utf-8")
            state.write_text("fixture-state", encoding="utf-8")
            codex_data.parent.mkdir(parents=True)
            codex_data.write_text("fixture-chat", encoding="utf-8")
            definition = task.write_fixture_definition(definitions)
            self.assertTrue(definition.is_file())
            self.assertTrue(task.remove_fixture_definition(definitions))
            self.assertFalse(definition.exists())
            self.assertEqual(config.read_text(encoding="utf-8"), "fixture-config")
            self.assertEqual(state.read_text(encoding="utf-8"), "fixture-state")
            self.assertEqual(codex_data.read_text(encoding="utf-8"), "fixture-chat")
            self.assertFalse(task.remove_fixture_definition(definitions))

    def test_task_paths_must_stay_inside_injected_layout(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            layout = WindowsGatewayLayout(root)
            with self.assertRaisesRegex(ValueError, "outside_layout"):
                CurrentUserScheduledTask(
                    task_name="FixtureGateway",
                    user_id="FIXTURE\\user",
                    supervisor_executable=root.parent / "outside.exe",
                    layout=layout,
                    config_file=layout.config / "gateway-config.json",
                )
            task = self.task(root)
            with self.assertRaisesRegex(ValueError, "definitions_outside_layout"):
                task.write_fixture_definition(root.parent / "outside-definitions")


class VersionedReleaseStoreTests(unittest.TestCase):
    @staticmethod
    def make_source(root: Path, name: str, content: str) -> Path:
        source = root / name
        source.mkdir()
        (source / "GuardianGateway.exe").write_text(content, encoding="utf-8")
        (source / "resources").mkdir()
        (source / "resources" / "fixture.txt").write_text(f"resource-{content}", encoding="utf-8")
        return source

    def test_atomic_activation_and_rollback_retain_both_versions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            layout = WindowsGatewayLayout(root / "fixture-install")
            store = VersionedReleaseStore(layout, transaction_id_factory=lambda: "fixturetx0001")
            first_source = self.make_source(root, "source-1", "v1")
            second_source = self.make_source(root, "source-2", "v2")
            first = store.install("v1.7.0", first_source)
            self.assertEqual(store.activate("v1.7.0").previous_version, None)
            store = VersionedReleaseStore(layout, transaction_id_factory=lambda: "fixturetx0002")
            second = store.install("v1.8.0", second_source)
            activated = store.activate("v1.8.0")
            self.assertEqual(activated.active_version, "v1.8.0")
            self.assertEqual(activated.previous_version, "v1.7.0")
            rolled_back = store.rollback()
            self.assertEqual(rolled_back.active_version, "v1.7.0")
            self.assertEqual(rolled_back.previous_version, "v1.8.0")
            self.assertTrue(first.path.is_dir())
            self.assertTrue(second.path.is_dir())
            self.assertEqual((first.path / "GuardianGateway.exe").read_text(encoding="utf-8"), "v1")
            self.assertEqual((second.path / "GuardianGateway.exe").read_text(encoding="utf-8"), "v2")

    def test_failed_pointer_replace_keeps_previous_active_version(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            layout = WindowsGatewayLayout(root / "fixture-install")
            source_one = self.make_source(root, "source-1", "v1")
            source_two = self.make_source(root, "source-2", "v2")
            first = VersionedReleaseStore(layout, transaction_id_factory=lambda: "fixturetx0001")
            first.install("v1.7.0", source_one)
            first.activate("v1.7.0")
            second = VersionedReleaseStore(layout, transaction_id_factory=lambda: "fixturetx0002")
            second.install("v1.8.0", source_two)
            original_replace = os.replace

            def fail_pointer_only(source: str | os.PathLike[str], target: str | os.PathLike[str]) -> None:
                if Path(target) == layout.current_pointer:
                    raise OSError("fixture_pointer_failure")
                original_replace(source, target)

            with patch("gateway.platforms.windows.os.replace", side_effect=fail_pointer_only):
                with self.assertRaisesRegex(ReleaseError, "commit_uncertain"):
                    second.activate("v1.8.0")
            self.assertEqual(second.load_pointer().active_version, "v1.7.0")
            self.assertTrue(layout.release_path("v1.8.0").is_dir())

    def test_install_refuses_overwrite_and_activation_detects_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            layout = WindowsGatewayLayout(root / "fixture-install")
            source = self.make_source(root, "source", "v1")
            store = VersionedReleaseStore(layout, transaction_id_factory=lambda: "fixturetx0001")
            installed = store.install("v1.7.0", source)
            with self.assertRaisesRegex(ReleaseError, "already_installed"):
                store.install("v1.7.0", source)
            (installed.path / "GuardianGateway.exe").write_text("tampered", encoding="utf-8")
            with self.assertRaisesRegex(ReleaseError, "content_hash_mismatch"):
                store.activate("v1.7.0")

    def test_release_source_cannot_overlap_version_store(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            layout = WindowsGatewayLayout(root / "fixture-install")
            source = layout.versions / "staging"
            source.mkdir(parents=True)
            (source / "GuardianGateway.exe").write_text("fixture", encoding="utf-8")
            store = VersionedReleaseStore(layout, transaction_id_factory=lambda: "fixturetx0001")
            with self.assertRaisesRegex(ReleaseError, "source_overlaps_versions"):
                store.install("v1.7.0", source)

    def test_preexisting_transaction_directory_is_never_deleted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            layout = WindowsGatewayLayout(root / "fixture-install")
            source = self.make_source(root, "source", "v1")
            transaction = layout.versions / ".v1.7.0.fixturetx0001.tmp"
            transaction.mkdir(parents=True)
            canary = transaction / "owner-canary.txt"
            canary.write_text("preserve", encoding="utf-8")
            store = VersionedReleaseStore(layout, transaction_id_factory=lambda: "fixturetx0001")
            with self.assertRaisesRegex(ReleaseError, "transaction_exists"):
                store.install("v1.7.0", source)
            self.assertEqual(canary.read_text(encoding="utf-8"), "preserve")


@unittest.skipUnless(os.name == "nt", "Windows named mutex")
class WindowsSingleInstanceMutexTests(unittest.TestCase):
    def test_named_mutex_allows_exactly_one_live_instance(self) -> None:
        name = f"fixture-{uuid.uuid4().hex}"
        first = WindowsSingleInstanceMutex(name)
        second = WindowsSingleInstanceMutex(name)
        first.acquire()
        self.assertTrue(first.acquired)
        try:
            with self.assertRaisesRegex(SingleInstanceError, "already_running"):
                second.acquire()
        finally:
            first.release()
        replacement = WindowsSingleInstanceMutex(name)
        with replacement:
            self.assertTrue(replacement.acquired)
        self.assertFalse(replacement.acquired)


if __name__ == "__main__":
    unittest.main()
