from __future__ import annotations

from dataclasses import dataclass
import os
import re
import subprocess
import threading
from typing import Any, Callable, Mapping, Sequence


INSPECTION_PROTOCOL = "guardian-nas-inspection-v1"
INSPECTION_REMOTE_COMMAND = "sh -s -- guardian-nas-inspection-v1"
MAX_INSPECTION_STDOUT = 32 * 1024
MAX_INSPECTION_STDERR = 8 * 1024
_HOST_TARGET = re.compile(r"[A-Za-z0-9_.:@][A-Za-z0-9_.:@-]{0,254}")
_SAFE_VALUE = re.compile(r"[A-Za-z0-9 ._/:+@(),=-]{1,256}")
_RESULT_KEYS = (
    "protocol",
    "architecture",
    "kernel_name",
    "kernel_release",
    "os_id",
    "os_version",
    "python_command",
    "python_version",
    "glibc_version",
    "openssl_version",
    "supervisor",
    "current_user",
    "home",
    "data_port_state",
    "control_port_state",
    "disk_total_kib",
    "disk_available_kib",
    "memory_total_kib",
    "memory_available_kib",
    "stdin_mode",
)
_TEXT_KEYS = set(_RESULT_KEYS) - {
    "disk_total_kib",
    "disk_available_kib",
    "memory_total_kib",
    "memory_available_kib",
}
_PORT_STATES = {"not_listening", "listening", "unknown"}
_SUPERVISORS = {
    "systemd_user",
    "systemd_system",
    "cron_user",
    "synology",
    "qnap",
    "unknown",
}
_SUPPORTED_ARCHITECTURES = {"x86_64", "aarch64"}
_PYTHON_VERSION = re.compile(r"Python (0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:\.(0|[1-9][0-9]*))?.*")


class NasInspectionError(RuntimeError):
    pass


def _public_text(value: object, *, fallback: str, limit: int) -> str:
    text = " ".join(
        "".join(
            character if ord(character) >= 0x20 and ord(character) != 0x7F else " "
            for character in str(value or "")
        ).split()
    )
    return (text or fallback)[:limit]


@dataclass(frozen=True, slots=True)
class NasInspectionRequest:
    data_port: int
    control_port: int

    def __post_init__(self) -> None:
        for value in (self.data_port, self.control_port):
            if type(value) is not int or not 1024 <= value <= 65535:
                raise ValueError("nas_inspection_port_invalid")
        if self.data_port == self.control_port:
            raise ValueError("nas_inspection_ports_must_differ")


@dataclass(frozen=True, slots=True)
class NasCompatibilityPolicy:
    minimum_python: tuple[int, int] = (3, 11)
    minimum_disk_available_kib: int = 512 * 1024
    minimum_memory_available_kib: int = 256 * 1024

    def __post_init__(self) -> None:
        major, minor = self.minimum_python
        if major < 3 or minor < 0:
            raise ValueError("nas_compatibility_python_policy_invalid")
        if self.minimum_disk_available_kib < 1 or self.minimum_memory_available_kib < 1:
            raise ValueError("nas_compatibility_resource_policy_invalid")


@dataclass(frozen=True, slots=True)
class NasCompatibilityDecision:
    compatible: bool
    package_mode: str | None
    supervisor: str | None
    blockers: tuple[str, ...]

    def as_public_document(self) -> dict[str, object]:
        return {
            "compatible": self.compatible,
            "package_mode": self.package_mode,
            "supervisor": self.supervisor,
            "blockers": list(self.blockers),
        }


class NasCompatibilityEvaluator:
    def __init__(self, policy: NasCompatibilityPolicy | None = None) -> None:
        self.policy = policy or NasCompatibilityPolicy()

    def evaluate(self, environment: Mapping[str, object]) -> NasCompatibilityDecision:
        blockers: list[str] = []
        if environment.get("protocol") != INSPECTION_PROTOCOL:
            blockers.append("nas_protocol_unverified")
        if environment.get("kernel_name") != "Linux":
            blockers.append("nas_kernel_unsupported")
        if environment.get("architecture") not in _SUPPORTED_ARCHITECTURES:
            blockers.append("nas_architecture_unsupported")

        python_command = environment.get("python_command")
        python_match = _PYTHON_VERSION.fullmatch(str(environment.get("python_version") or ""))
        if python_command not in {"python3", "python"} or python_match is None:
            blockers.append("nas_python_unavailable")
        elif (int(python_match.group(1)), int(python_match.group(2))) < self.policy.minimum_python:
            blockers.append("nas_python_unsupported")

        if environment.get("glibc_version") in {None, "", "unknown"}:
            blockers.append("nas_glibc_unverified")
        if environment.get("openssl_version") in {None, "", "unknown"}:
            blockers.append("nas_openssl_unverified")

        supervisor = environment.get("supervisor")
        selected_supervisor = supervisor if supervisor in {"systemd_user", "cron_user"} else None
        if selected_supervisor is None:
            blockers.append("nas_supervisor_unsupported")

        for key, code in (
            ("data_port_state", "nas_data_port_unavailable"),
            ("control_port_state", "nas_control_port_unavailable"),
        ):
            if environment.get(key) != "not_listening":
                blockers.append(code)

        home = environment.get("home")
        if not isinstance(home, str) or not home.startswith("/") or home == "/":
            blockers.append("nas_home_invalid")
        if environment.get("current_user") in {None, "", "unknown", "root"}:
            blockers.append("nas_service_user_unsupported")

        self._resource_blocker(
            environment.get("disk_available_kib"),
            self.policy.minimum_disk_available_kib,
            "nas_disk_insufficient",
            blockers,
        )
        self._resource_blocker(
            environment.get("memory_available_kib"),
            self.policy.minimum_memory_available_kib,
            "nas_memory_insufficient",
            blockers,
        )
        unique_blockers = tuple(dict.fromkeys(blockers))
        return NasCompatibilityDecision(
            compatible=not unique_blockers,
            package_mode="locked_venv" if not unique_blockers else None,
            supervisor=selected_supervisor if not unique_blockers else None,
            blockers=unique_blockers,
        )

    @staticmethod
    def _resource_blocker(
        value: object,
        minimum: int,
        code: str,
        blockers: list[str],
    ) -> None:
        if type(value) is not int or value < minimum:
            blockers.append(code)


@dataclass(frozen=True, slots=True)
class BoundedProcessResult:
    returncode: int
    stdout: bytes
    stderr: bytes
    timed_out: bool = False
    stdout_truncated: bool = False
    stderr_truncated: bool = False


ProcessRunner = Callable[
    [Sequence[str], bytes, float, int, int],
    BoundedProcessResult,
]


def ssh_inspection_command(host: Mapping[str, Any]) -> list[str]:
    target = host.get("target")
    port = host.get("port", 22)
    if not isinstance(target, str) or _HOST_TARGET.fullmatch(target) is None:
        raise NasInspectionError("nas_inspection_host_invalid")
    if type(port) is not int or not 1 <= port <= 65535:
        raise NasInspectionError("nas_inspection_host_invalid")
    return [
        "ssh",
        "-T",
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=8",
        "-o",
        "ClearAllForwardings=yes",
        "-p",
        str(port),
        target,
        INSPECTION_REMOTE_COMMAND,
    ]


def render_inspection_script(request: NasInspectionRequest) -> bytes:
    script = r'''#!/bin/sh
set -f
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH LC_ALL=C LANG=C
[ "${1:-}" = "guardian-nas-inspection-v1" ] || exit 64

clean() {
    cleaned="$(printf '%s' "$1" | tr '\r\n\t' '   ' | tr -cd 'A-Za-z0-9 ._/:+@(),=-' | cut -c1-256)"
    if [ -n "$cleaned" ]; then
        printf '%s' "$cleaned"
    else
        printf 'unknown'
    fi
}

first_line() {
    "$@" 2>/dev/null | sed -n '1p'
}

os_field() {
    key="$1"
    if [ ! -r /etc/os-release ]; then
        printf 'unknown'
        return
    fi
    sed -n "s/^${key}=//p" /etc/os-release | sed -n '1p' | sed 's/^"//;s/"$//'
}

port_state() {
    port="$1"
    if command -v ss >/dev/null 2>&1; then
        if ss -lnt 2>/dev/null | awk 'NR > 1 {print $4}' | grep -Eq "[:.]${port}$"; then
            printf 'listening'
        else
            printf 'not_listening'
        fi
        return
    fi
    if command -v netstat >/dev/null 2>&1; then
        if netstat -lnt 2>/dev/null | awk 'NR > 2 {print $4}' | grep -Eq "[:.]${port}$"; then
            printf 'listening'
        else
            printf 'not_listening'
        fi
        return
    fi
    printf 'unknown'
}

python_command=unknown
python_version=unknown
if command -v python3 >/dev/null 2>&1; then
    python_command=python3
    python_version="$(first_line python3 --version)"
elif command -v python >/dev/null 2>&1; then
    python_command=python
    python_version="$(first_line python --version)"
fi

glibc_version="$(getconf GNU_LIBC_VERSION 2>/dev/null || true)"
if [ -z "$glibc_version" ] && command -v ldd >/dev/null 2>&1; then
    glibc_version="$(first_line ldd --version)"
fi
[ -n "$glibc_version" ] || glibc_version=unknown

openssl_version=unknown
if command -v openssl >/dev/null 2>&1; then
    openssl_version="$(first_line openssl version)"
fi

supervisor=unknown
if command -v systemctl >/dev/null 2>&1; then
    user_runtime="${XDG_RUNTIME_DIR:-}"
    if [ -z "$user_runtime" ]; then
        user_runtime="/run/user/$(id -u 2>/dev/null || printf unknown)"
    fi
    if [ -d "$user_runtime" ] && [ -S "$user_runtime/bus" ]; then
        XDG_RUNTIME_DIR="$user_runtime"
        DBUS_SESSION_BUS_ADDRESS="unix:path=$user_runtime/bus"
        export XDG_RUNTIME_DIR DBUS_SESSION_BUS_ADDRESS
    fi
    if systemctl --user show-environment >/dev/null 2>&1; then
        supervisor=systemd_user
    elif command -v crontab >/dev/null 2>&1 && systemctl is-active --quiet cron.service >/dev/null 2>&1; then
        supervisor=cron_user
    else
        supervisor=systemd_system
    fi
elif [ -x /usr/syno/bin/synosystemctl ] || [ -d /usr/syno ]; then
    supervisor=synology
elif [ -x /sbin/getcfg ] || [ -d /share ]; then
    supervisor=qnap
fi

disk_total_kib=0
disk_available_kib=0
disk_line="$(df -Pk "${HOME:-/}" 2>/dev/null | awk 'NR == 2 {print $2 " " $4}')"
case "$disk_line" in
    *[!0-9\ ]*) disk_line="" ;;
esac
if [ -n "$disk_line" ]; then
    disk_total_kib="${disk_line%% *}"
    disk_available_kib="${disk_line##* }"
fi

memory_total_kib=0
memory_available_kib=0
if [ -r /proc/meminfo ]; then
    memory_total_kib="$(awk '/^MemTotal:/ {print $2; exit}' /proc/meminfo)"
    memory_available_kib="$(awk '/^MemAvailable:/ {print $2; exit}' /proc/meminfo)"
fi
case "$memory_total_kib" in *[!0-9]*|'') memory_total_kib=0 ;; esac
case "$memory_available_kib" in *[!0-9]*|'') memory_available_kib=0 ;; esac

printf '%s\n' 'GUARDIAN_NAS_INSPECTION_BEGIN'
printf 'protocol=%s\n' 'guardian-nas-inspection-v1'
printf 'architecture=%s\n' "$(clean "$(uname -m 2>/dev/null || printf unknown)")"
printf 'kernel_name=%s\n' "$(clean "$(uname -s 2>/dev/null || printf unknown)")"
printf 'kernel_release=%s\n' "$(clean "$(uname -r 2>/dev/null || printf unknown)")"
printf 'os_id=%s\n' "$(clean "$(os_field ID)")"
printf 'os_version=%s\n' "$(clean "$(os_field VERSION_ID)")"
printf 'python_command=%s\n' "$(clean "$python_command")"
printf 'python_version=%s\n' "$(clean "$python_version")"
printf 'glibc_version=%s\n' "$(clean "$glibc_version")"
printf 'openssl_version=%s\n' "$(clean "$openssl_version")"
printf 'supervisor=%s\n' "$(clean "$supervisor")"
printf 'current_user=%s\n' "$(clean "$(id -un 2>/dev/null || printf unknown)")"
printf 'home=%s\n' "$(clean "${HOME:-unknown}")"
printf 'data_port_state=%s\n' "$(port_state __DATA_PORT__)"
printf 'control_port_state=%s\n' "$(port_state __CONTROL_PORT__)"
printf 'disk_total_kib=%s\n' "$disk_total_kib"
printf 'disk_available_kib=%s\n' "$disk_available_kib"
printf 'memory_total_kib=%s\n' "$memory_total_kib"
printf 'memory_available_kib=%s\n' "$memory_available_kib"
printf 'stdin_mode=%s\n' 'script_ok'
printf '%s\n' 'GUARDIAN_NAS_INSPECTION_END'
'''
    return (
        script.replace("__DATA_PORT__", str(request.data_port))
        .replace("__CONTROL_PORT__", str(request.control_port))
        .encode("utf-8")
    )


def parse_inspection_output(payload: bytes) -> dict[str, object]:
    if len(payload) > MAX_INSPECTION_STDOUT:
        raise NasInspectionError("nas_inspection_output_too_large")
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise NasInspectionError("nas_inspection_output_invalid") from exc
    lines = text.splitlines()
    if (
        len(lines) != len(_RESULT_KEYS) + 2
        or lines[0] != "GUARDIAN_NAS_INSPECTION_BEGIN"
        or lines[-1] != "GUARDIAN_NAS_INSPECTION_END"
    ):
        raise NasInspectionError("nas_inspection_output_invalid")
    result: dict[str, object] = {}
    for expected_key, line in zip(_RESULT_KEYS, lines[1:-1], strict=True):
        key, separator, value = line.partition("=")
        if not separator or key != expected_key:
            raise NasInspectionError("nas_inspection_output_invalid")
        if key in _TEXT_KEYS:
            if _SAFE_VALUE.fullmatch(value) is None:
                raise NasInspectionError("nas_inspection_output_invalid")
            result[key] = value
        else:
            if not value.isascii() or not value.isdecimal():
                raise NasInspectionError("nas_inspection_output_invalid")
            number = int(value)
            if number < 0 or number > 2**63 - 1:
                raise NasInspectionError("nas_inspection_output_invalid")
            result[key] = number
    if result["protocol"] != INSPECTION_PROTOCOL:
        raise NasInspectionError("nas_inspection_protocol_mismatch")
    if result["stdin_mode"] != "script_ok":
        raise NasInspectionError("nas_inspection_stdin_unverified")
    if result["supervisor"] not in _SUPERVISORS:
        raise NasInspectionError("nas_inspection_output_invalid")
    for key in ("data_port_state", "control_port_state"):
        if result[key] not in _PORT_STATES:
            raise NasInspectionError("nas_inspection_output_invalid")
    return result


class NasEnvironmentInspector:
    def __init__(
        self,
        *,
        runner: ProcessRunner | None = None,
        timeout: float = 20.0,
    ) -> None:
        if timeout <= 0 or timeout > 120:
            raise ValueError("nas_inspection_timeout_invalid")
        self._runner = runner or run_bounded_process
        self._timeout = timeout

    def inspect(
        self,
        host: Mapping[str, Any],
        request: NasInspectionRequest,
    ) -> dict[str, object]:
        public_host = {
            "display_name": _public_text(
                host.get("display_name"), fallback="NAS", limit=80
            ),
            "host_id": _public_text(host.get("host_id"), fallback="", limit=200),
        }
        try:
            command = ssh_inspection_command(host)
            script = render_inspection_script(request)
            completed = self._runner(
                command,
                script,
                self._timeout,
                MAX_INSPECTION_STDOUT,
                MAX_INSPECTION_STDERR,
            )
            if completed.timed_out:
                raise NasInspectionError("nas_inspection_timeout")
            if completed.stdout_truncated or completed.stderr_truncated:
                raise NasInspectionError("nas_inspection_output_too_large")
            if completed.returncode != 0:
                raise NasInspectionError("nas_inspection_ssh_failed")
            environment = parse_inspection_output(completed.stdout)
            return {
                **public_host,
                "ok": True,
                "read_only": True,
                "environment": environment,
            }
        except NasInspectionError as exc:
            return {
                **public_host,
                "ok": False,
                "read_only": True,
                "error_code": str(exc),
            }
        except (OSError, subprocess.SubprocessError):
            return {
                **public_host,
                "ok": False,
                "read_only": True,
                "error_code": "nas_inspection_process_failed",
            }


def run_bounded_process(
    command: Sequence[str],
    input_payload: bytes,
    timeout: float,
    max_stdout: int,
    max_stderr: int,
) -> BoundedProcessResult:
    creationflags = 0x08000000 if os.name == "nt" else 0
    process = subprocess.Popen(
        list(command),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        creationflags=creationflags,
    )
    stdout = bytearray()
    stderr = bytearray()
    truncated = {"stdout": False, "stderr": False}

    def read_stream(stream: Any, output: bytearray, limit: int, name: str) -> None:
        while True:
            chunk = stream.read(4096)
            if not chunk:
                break
            remaining = limit + 1 - len(output)
            if remaining > 0:
                output.extend(chunk[:remaining])
            if len(output) > limit or len(chunk) > remaining:
                truncated[name] = True

    def write_input() -> None:
        try:
            if process.stdin is not None:
                process.stdin.write(input_payload)
                process.stdin.flush()
        except (BrokenPipeError, OSError):
            pass
        finally:
            if process.stdin is not None:
                process.stdin.close()

    assert process.stdout is not None and process.stderr is not None
    threads = [
        threading.Thread(target=write_input, daemon=True),
        threading.Thread(
            target=read_stream,
            args=(process.stdout, stdout, max_stdout, "stdout"),
            daemon=True,
        ),
        threading.Thread(
            target=read_stream,
            args=(process.stderr, stderr, max_stderr, "stderr"),
            daemon=True,
        ),
    ]
    for thread in threads:
        thread.start()
    timed_out = False
    try:
        returncode = process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        process.kill()
        returncode = process.wait(timeout=5)
    finally:
        for thread in threads:
            thread.join(timeout=5)
        process.stdout.close()
        process.stderr.close()
    return BoundedProcessResult(
        returncode=returncode,
        stdout=bytes(stdout[:max_stdout]),
        stderr=bytes(stderr[:max_stderr]),
        timed_out=timed_out,
        stdout_truncated=truncated["stdout"],
        stderr_truncated=truncated["stderr"],
    )


__all__ = [
    "BoundedProcessResult",
    "INSPECTION_PROTOCOL",
    "INSPECTION_REMOTE_COMMAND",
    "MAX_INSPECTION_STDERR",
    "MAX_INSPECTION_STDOUT",
    "NasEnvironmentInspector",
    "NasCompatibilityDecision",
    "NasCompatibilityEvaluator",
    "NasCompatibilityPolicy",
    "NasInspectionError",
    "NasInspectionRequest",
    "parse_inspection_output",
    "render_inspection_script",
    "run_bounded_process",
    "ssh_inspection_command",
]
