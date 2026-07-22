from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from enum import StrEnum
import argparse
import json
import math
import os
from pathlib import Path
import stat
import subprocess
import sys
import time
from typing import Callable
from typing import Mapping
import uuid

from .platforms.windows import ReleaseError, VersionedReleaseStore, WindowsGatewayLayout
from .singleton import SingleInstanceLock


CONFIGURATION_ERROR_EXIT_CODE = 78
SUPERVISOR_SAFE_STOP_EXIT_CODE = 75


class ChildExitKind(StrEnum):
    CLEAN = "clean"
    REQUESTED_STOP = "requested_stop"
    CRASH = "crash"
    CONFIGURATION_ERROR = "configuration_error"


class SupervisorAction(StrEnum):
    RESTART = "restart"
    STOP = "stop"
    SAFE_STOP = "safe_stop"


@dataclass(frozen=True, slots=True)
class RestartPolicy:
    max_restarts: int = 3
    window_seconds: float = 60.0
    base_delay_seconds: float = 1.0
    max_delay_seconds: float = 30.0
    stable_run_reset_seconds: float = 300.0

    def __post_init__(self) -> None:
        if type(self.max_restarts) is not int or not 0 <= self.max_restarts <= 100:
            raise ValueError("supervisor_max_restarts_invalid")
        for value, error in (
            (self.window_seconds, "supervisor_window_invalid"),
            (self.base_delay_seconds, "supervisor_base_delay_invalid"),
            (self.max_delay_seconds, "supervisor_max_delay_invalid"),
            (self.stable_run_reset_seconds, "supervisor_stable_run_invalid"),
        ):
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValueError(error)
            if not math.isfinite(value) or value <= 0:
                raise ValueError(error)
        if self.base_delay_seconds > self.max_delay_seconds:
            raise ValueError("supervisor_delay_range_invalid")


@dataclass(frozen=True, slots=True)
class SupervisorDecision:
    action: SupervisorAction
    reason: str
    delay_seconds: float = 0.0
    crashes_in_window: int = 0

    @property
    def should_restart(self) -> bool:
        return self.action is SupervisorAction.RESTART


def classify_child_exit(exit_code: int, *, stop_requested: bool = False) -> ChildExitKind:
    if isinstance(exit_code, bool) or not isinstance(exit_code, int):
        raise ValueError("supervisor_exit_code_invalid")
    if stop_requested:
        return ChildExitKind.REQUESTED_STOP
    if exit_code == 0:
        return ChildExitKind.CLEAN
    if exit_code == CONFIGURATION_ERROR_EXIT_CODE:
        return ChildExitKind.CONFIGURATION_ERROR
    return ChildExitKind.CRASH


class BoundedRestartSupervisor:
    def __init__(self, policy: RestartPolicy = RestartPolicy()) -> None:
        self.policy = policy
        self._crashes: deque[float] = deque()
        self._last_observed_at: float | None = None
        self._safe_stop_reason: str | None = None

    @property
    def safe_stopped(self) -> bool:
        return self._safe_stop_reason is not None

    @property
    def safe_stop_reason(self) -> str | None:
        return self._safe_stop_reason

    def observe_exit(
        self,
        kind: ChildExitKind,
        *,
        exited_at: float,
        run_duration_seconds: float,
    ) -> SupervisorDecision:
        if not isinstance(kind, ChildExitKind):
            raise ValueError("supervisor_exit_kind_invalid")
        if isinstance(exited_at, bool) or not isinstance(exited_at, (int, float)):
            raise ValueError("supervisor_exit_time_invalid")
        if not math.isfinite(exited_at) or exited_at < 0:
            raise ValueError("supervisor_exit_time_invalid")
        if isinstance(run_duration_seconds, bool) or not isinstance(run_duration_seconds, (int, float)):
            raise ValueError("supervisor_run_duration_invalid")
        if not math.isfinite(run_duration_seconds) or run_duration_seconds < 0:
            raise ValueError("supervisor_run_duration_invalid")
        if self._last_observed_at is not None and exited_at < self._last_observed_at:
            raise ValueError("supervisor_clock_moved_backwards")
        self._last_observed_at = exited_at

        if self._safe_stop_reason is not None:
            return SupervisorDecision(
                SupervisorAction.SAFE_STOP,
                self._safe_stop_reason,
                crashes_in_window=len(self._crashes),
            )
        if kind is ChildExitKind.CONFIGURATION_ERROR:
            return self._latch_safe_stop("configuration_error")
        if kind is ChildExitKind.REQUESTED_STOP:
            self._crashes.clear()
            return SupervisorDecision(SupervisorAction.STOP, "requested_stop")
        if kind is ChildExitKind.CLEAN:
            self._crashes.clear()
            return SupervisorDecision(SupervisorAction.STOP, "clean_exit")

        if run_duration_seconds >= self.policy.stable_run_reset_seconds:
            self._crashes.clear()
        cutoff = exited_at - self.policy.window_seconds
        while self._crashes and self._crashes[0] <= cutoff:
            self._crashes.popleft()
        self._crashes.append(exited_at)
        crash_count = len(self._crashes)
        if crash_count > self.policy.max_restarts:
            return self._latch_safe_stop("crash_loop")
        delay = min(
            self.policy.max_delay_seconds,
            self.policy.base_delay_seconds * (2 ** max(0, crash_count - 1)),
        )
        return SupervisorDecision(
            SupervisorAction.RESTART,
            "transient_crash",
            delay_seconds=delay,
            crashes_in_window=crash_count,
        )

    def reset_after_operator_action(self) -> None:
        self._crashes.clear()
        self._last_observed_at = None
        self._safe_stop_reason = None

    def snapshot(self) -> Mapping[str, object]:
        return {
            "schema_version": 1,
            "crash_times": list(self._crashes),
            "last_observed_at": self._last_observed_at,
            "safe_stop_reason": self._safe_stop_reason,
        }

    @classmethod
    def restore(
        cls,
        policy: RestartPolicy,
        snapshot: Mapping[str, object],
    ) -> BoundedRestartSupervisor:
        if type(snapshot.get("schema_version")) is not int or snapshot.get("schema_version") != 1:
            raise ValueError("supervisor_snapshot_schema_invalid")
        expected_fields = {
            "schema_version",
            "crash_times",
            "last_observed_at",
            "safe_stop_reason",
        }
        if set(snapshot) != expected_fields:
            raise ValueError("supervisor_snapshot_fields_invalid")
        crash_times = snapshot.get("crash_times")
        last_observed_at = snapshot.get("last_observed_at")
        safe_stop_reason = snapshot.get("safe_stop_reason")
        if not isinstance(crash_times, list):
            raise ValueError("supervisor_snapshot_crashes_invalid")
        parsed_times: list[float] = []
        for value in crash_times:
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValueError("supervisor_snapshot_crashes_invalid")
            parsed = float(value)
            if not math.isfinite(parsed) or parsed < 0:
                raise ValueError("supervisor_snapshot_crashes_invalid")
            parsed_times.append(parsed)
        if parsed_times != sorted(parsed_times):
            raise ValueError("supervisor_snapshot_crashes_invalid")
        if last_observed_at is not None:
            if isinstance(last_observed_at, bool) or not isinstance(last_observed_at, (int, float)):
                raise ValueError("supervisor_snapshot_time_invalid")
            last_observed_at = float(last_observed_at)
            if not math.isfinite(last_observed_at) or last_observed_at < 0:
                raise ValueError("supervisor_snapshot_time_invalid")
            if parsed_times and parsed_times[-1] > last_observed_at:
                raise ValueError("supervisor_snapshot_time_invalid")
        if safe_stop_reason not in (None, "configuration_error", "crash_loop"):
            raise ValueError("supervisor_snapshot_reason_invalid")
        restored = cls(policy)
        restored._crashes.extend(parsed_times)
        restored._last_observed_at = last_observed_at
        restored._safe_stop_reason = safe_stop_reason
        return restored

    def _latch_safe_stop(self, reason: str) -> SupervisorDecision:
        self._safe_stop_reason = reason
        return SupervisorDecision(
            SupervisorAction.SAFE_STOP,
            reason,
            crashes_in_window=len(self._crashes),
        )


class SupervisorStateError(RuntimeError):
    pass


class SupervisorStateStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def load(self, policy: RestartPolicy) -> BoundedRestartSupervisor:
        try:
            payload = self.path.read_bytes()
        except FileNotFoundError:
            return BoundedRestartSupervisor(policy)
        except OSError as exc:
            raise SupervisorStateError("supervisor_state_read_failed") from exc
        if len(payload) > 64 * 1024:
            raise SupervisorStateError("supervisor_state_too_large")
        try:
            document = json.loads(payload.decode("utf-8"))
            if not isinstance(document, Mapping):
                raise TypeError
            return BoundedRestartSupervisor.restore(policy, document)
        except Exception as exc:
            raise SupervisorStateError("supervisor_state_invalid") from exc

    def save(self, supervisor: BoundedRestartSupervisor) -> None:
        try:
            payload = (
                json.dumps(
                    supervisor.snapshot(),
                    ensure_ascii=True,
                    allow_nan=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise SupervisorStateError("supervisor_state_serialize_failed") from exc
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.path.parent, stat.S_IRWXU)
        except OSError:
            pass
        temporary = self.path.parent / f".{self.path.name}.{uuid.uuid4().hex}.tmp"
        descriptor: int | None = None
        try:
            descriptor = os.open(
                temporary,
                os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                stat.S_IRUSR | stat.S_IWUSR,
            )
            with os.fdopen(descriptor, "wb") as stream:
                descriptor = None
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
            os.chmod(self.path, stat.S_IRUSR | stat.S_IWUSR)
        except OSError as exc:
            raise SupervisorStateError("supervisor_state_write_failed") from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
            except OSError:
                pass


ProcessFactory = Callable[..., object]


class GatewaySupervisorRunner:
    def __init__(
        self,
        layout: WindowsGatewayLayout,
        config_path: str | Path,
        *,
        policy: RestartPolicy = RestartPolicy(),
        process_factory: ProcessFactory = subprocess.Popen,
        monotonic_clock: Callable[[], float] = time.monotonic,
        wall_clock: Callable[[], float] = time.time,
        sleep: Callable[[float], None] = time.sleep,
        executable_name: str = "GuardianGateway.exe",
    ) -> None:
        self.layout = layout
        self.config_path = Path(config_path).resolve()
        if self.layout.config.resolve() not in self.config_path.parents:
            raise ValueError("supervisor_config_outside_layout")
        if not executable_name or Path(executable_name).name != executable_name:
            raise ValueError("supervisor_executable_name_invalid")
        self.policy = policy
        self._process_factory = process_factory
        self._monotonic_clock = monotonic_clock
        self._wall_clock = wall_clock
        self._sleep = sleep
        self._executable_name = executable_name
        self._release_store = VersionedReleaseStore(layout)
        self._state_store = SupervisorStateStore(layout.state / "supervisor.json")

    def run(self) -> int:
        try:
            supervisor = self._state_store.load(self.policy)
        except SupervisorStateError:
            return CONFIGURATION_ERROR_EXIT_CODE
        if supervisor.safe_stopped:
            return SUPERVISOR_SAFE_STOP_EXIT_CODE
        while True:
            try:
                pointer = self._release_store.load_pointer()
                if pointer is None:
                    raise ReleaseError("gateway_release_pointer_missing")
                release = self._release_store.inspect(pointer.version)
                executable = (release.path / self._executable_name).resolve()
                if executable.parent != release.path.resolve() or not executable.is_file():
                    raise ReleaseError("gateway_release_executable_missing")
            except (OSError, ReleaseError, ValueError):
                decision = supervisor.observe_exit(
                    ChildExitKind.CONFIGURATION_ERROR,
                    exited_at=self._wall_clock(),
                    run_duration_seconds=0,
                )
                self._state_store.save(supervisor)
                return (
                    CONFIGURATION_ERROR_EXIT_CODE
                    if decision.reason == "configuration_error"
                    else SUPERVISOR_SAFE_STOP_EXIT_CODE
                )
            command = (
                str(executable),
                "--install-root",
                str(self.layout.root),
                "--config",
                str(self.config_path),
            )
            started = self._monotonic_clock()
            try:
                process = self._process_factory(
                    command,
                    cwd=str(release.path),
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    creationflags=(0x08000000 if os.name == "nt" else 0),
                )
                exit_code = int(process.wait())
            except OSError:
                exit_code = 1
            duration = max(0.0, self._monotonic_clock() - started)
            decision = supervisor.observe_exit(
                classify_child_exit(exit_code),
                exited_at=self._wall_clock(),
                run_duration_seconds=duration,
            )
            self._state_store.save(supervisor)
            if decision.action is SupervisorAction.RESTART:
                self._sleep(decision.delay_seconds)
                continue
            if decision.action is SupervisorAction.SAFE_STOP:
                return (
                    CONFIGURATION_ERROR_EXIT_CODE
                    if decision.reason == "configuration_error"
                    else SUPERVISOR_SAFE_STOP_EXIT_CODE
                )
            return 0

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Codex Profile Guardian Gateway Supervisor")
    parser.add_argument("--layout-root", required=True)
    parser.add_argument("--config-file", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    layout = WindowsGatewayLayout(Path(args.layout_root).resolve())
    lock = SingleInstanceLock(layout.gateway_root / "runtime" / "supervisor.lock")
    try:
        lock.acquire()
    except Exception:
        return SUPERVISOR_SAFE_STOP_EXIT_CODE
    try:
        return GatewaySupervisorRunner(layout, args.config_file).run()
    except (SupervisorStateError, ValueError):
        return CONFIGURATION_ERROR_EXIT_CODE
    finally:
        lock.release()


if __name__ == "__main__":
    raise SystemExit(main())
