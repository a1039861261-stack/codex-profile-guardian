from __future__ import annotations

import argparse
from collections import deque
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time
import uuid


CONFIGURATION_ERROR_EXIT_CODE = 78
SUPERVISOR_SAFE_STOP_EXIT_CODE = 75


def _atomic_json(path: Path, document: dict[str, object]) -> None:
    payload = (
        json.dumps(document, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    temporary = path.parent / f".{path.name}.{uuid.uuid4().hex}.tmp"
    descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)


def _config_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load_state(path: Path, config_sha256: str) -> tuple[deque[float], str | None]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return deque(), None
    except Exception:
        return deque(), "state_invalid"
    if (
        not isinstance(document, dict)
        or set(document) != {"schema_version", "config_sha256", "crash_times", "safe_stop_reason"}
        or document.get("schema_version") != 1
        or document.get("config_sha256") != config_sha256
    ):
        return deque(), None
    raw_times = document.get("crash_times")
    reason = document.get("safe_stop_reason")
    if not isinstance(raw_times, list) or reason not in {None, "configuration_error", "crash_loop"}:
        return deque(), "state_invalid"
    times: deque[float] = deque()
    for value in raw_times:
        if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
            return deque(), "state_invalid"
        times.append(float(value))
    return times, reason


def _save_state(
    path: Path,
    config_sha256: str,
    crash_times: deque[float],
    reason: str | None,
) -> None:
    _atomic_json(
        path,
        {
            "schema_version": 1,
            "config_sha256": config_sha256,
            "crash_times": list(crash_times),
            "safe_stop_reason": reason,
        },
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--install-root", required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--platform", choices=("linux",), required=True)
    parser.add_argument("--home", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    home = Path(args.home).expanduser().resolve()
    install_root = Path(args.install_root).expanduser().resolve()
    config = Path(args.config).expanduser().resolve()
    release_root = Path(os.environ.get("GUARDIAN_RELEASE_ROOT", "")).resolve()
    expected_install = home / ".local" / "share" / "codex-profile-guardian-gateway"
    expected_config = home / ".config" / "codex-profile-guardian-gateway" / "active.json"
    if install_root != expected_install or config != expected_config or not release_root.is_dir():
        return CONFIGURATION_ERROR_EXIT_CODE
    gateway = release_root / "bin" / "guardian-gateway"
    if not gateway.is_file() or gateway.is_symlink():
        return CONFIGURATION_ERROR_EXIT_CODE
    state_root = home / ".local" / "state" / "codex-profile-guardian-gateway"
    state_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(state_root, 0o700)
    lock_path = state_root / "cron-supervisor.lock"
    lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return 0
        config_sha256 = _config_sha256(config)
        state_path = state_root / "cron-supervisor.json"
        crashes, safe_stop = _load_state(state_path, config_sha256)
        if safe_stop is not None:
            return SUPERVISOR_SAFE_STOP_EXIT_CODE
        while True:
            started = time.monotonic()
            try:
                completed = subprocess.run(
                    [
                        str(gateway),
                        "--install-root",
                        str(install_root),
                        "--config",
                        str(config),
                        "--platform",
                        "linux",
                        "--home",
                        str(home),
                    ],
                    cwd=release_root,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                )
                exit_code = int(completed.returncode)
            except OSError:
                exit_code = 1
            if exit_code == 0:
                crashes.clear()
                _save_state(state_path, config_sha256, crashes, None)
                return 0
            if exit_code == CONFIGURATION_ERROR_EXIT_CODE:
                _save_state(state_path, config_sha256, crashes, "configuration_error")
                return CONFIGURATION_ERROR_EXIT_CODE
            now = time.time()
            if time.monotonic() - started >= 300:
                crashes.clear()
            cutoff = now - 300
            while crashes and crashes[0] <= cutoff:
                crashes.popleft()
            crashes.append(now)
            if len(crashes) > 3:
                _save_state(state_path, config_sha256, crashes, "crash_loop")
                return SUPERVISOR_SAFE_STOP_EXIT_CODE
            _save_state(state_path, config_sha256, crashes, None)
            time.sleep(min(30.0, 2 ** (len(crashes) - 1)))
    except Exception:
        return CONFIGURATION_ERROR_EXIT_CODE
    finally:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        except OSError:
            pass
        os.close(lock_fd)


if __name__ == "__main__":
    raise SystemExit(main())
