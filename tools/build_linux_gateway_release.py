from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import zipfile


PROJECT_ROOT = Path(__file__).resolve().parents[1]
RELEASE_VERSION = "v" + (PROJECT_ROOT / "VERSION").read_text(encoding="utf-8").strip()
MAX_RELEASE_BYTES = 64 * 1024 * 1024
MAX_RELEASE_FILES = 512

GATEWAY_WRAPPER = b'''#!/bin/sh
set -eu
RELEASE_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
export PYTHONNOUSERSITE=1
export PYTHONSAFEPATH=1
export PYTHONPATH="$RELEASE_ROOT/app:$RELEASE_ROOT/lib"
exec /usr/bin/python3 -B "$RELEASE_ROOT/app/guardian_gateway.py" "$@"
'''

SUPERVISOR_WRAPPER = b'''#!/bin/sh
set -eu
RELEASE_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
export GUARDIAN_RELEASE_ROOT="$RELEASE_ROOT"
export PYTHONNOUSERSITE=1
export PYTHONSAFEPATH=1
export PYTHONPATH="$RELEASE_ROOT/app:$RELEASE_ROOT/lib"
exec /usr/bin/python3 -B "$RELEASE_ROOT/app/guardian_gateway_cron_supervisor.py" "$@"
'''


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)


def _download_wheels(destination: Path) -> None:
    command = [
        sys.executable,
        "-m",
        "pip",
        "download",
        "--requirement",
        str(PROJECT_ROOT / "requirements-gateway.txt"),
        "--dest",
        str(destination),
        "--only-binary=:all:",
        "--platform",
        "manylinux_2_17_x86_64",
        "--implementation",
        "cp",
        "--python-version",
        "311",
        "--abi",
        "cp311",
        "--no-deps",
        "--disable-pip-version-check",
    ]
    subprocess.run(command, cwd=PROJECT_ROOT, check=True)


def _extract_wheels(wheel_root: Path, destination: Path) -> list[dict[str, object]]:
    wheels = sorted(wheel_root.glob("*.whl"), key=lambda path: path.name.lower())
    if not wheels:
        raise RuntimeError("linux_gateway_wheels_missing")
    records: list[dict[str, object]] = []
    for wheel in wheels:
        with zipfile.ZipFile(wheel) as archive:
            for member in archive.infolist():
                relative = Path(member.filename)
                if (
                    relative.is_absolute()
                    or ".." in relative.parts
                    or member.is_dir()
                    or relative.parts[0].endswith(".data")
                ):
                    if member.is_dir():
                        continue
                    raise RuntimeError("linux_gateway_wheel_invalid")
                target = destination.joinpath(*relative.parts)
                target.parent.mkdir(parents=True, exist_ok=True)
                if target.exists():
                    raise RuntimeError("linux_gateway_wheel_collision")
                with archive.open(member) as source, target.open("wb") as output:
                    shutil.copyfileobj(source, output)
        records.append(
            {
                "filename": wheel.name,
                "size": wheel.stat().st_size,
                "sha256": _sha256(wheel),
            }
        )
    return records


def _inventory(root: Path) -> list[dict[str, object]]:
    entries: list[dict[str, object]] = []
    total = 0
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        if path.is_dir():
            continue
        if path.is_symlink() or not path.is_file():
            raise RuntimeError("linux_gateway_release_invalid")
        relative = path.relative_to(root).as_posix()
        total += path.stat().st_size
        entries.append(
            {
                "path": relative,
                "size": path.stat().st_size,
                "sha256": _sha256(path),
            }
        )
    if len(entries) > MAX_RELEASE_FILES or total > MAX_RELEASE_BYTES:
        raise RuntimeError("linux_gateway_release_too_large")
    return entries


def build(destination: Path, *, wheels: Path | None = None) -> dict[str, object]:
    destination = destination.resolve()
    if destination.exists():
        raise RuntimeError("linux_gateway_destination_exists")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=destination.parent) as temporary_name:
        temporary = Path(temporary_name)
        wheel_root = wheels.resolve() if wheels is not None else temporary / "wheels"
        if wheels is None:
            wheel_root.mkdir()
            _download_wheels(wheel_root)
        stage = temporary / "release"
        (stage / "app").mkdir(parents=True)
        shutil.copytree(PROJECT_ROOT / "gateway", stage / "app" / "gateway")
        for cache in (stage / "app").rglob("__pycache__"):
            shutil.rmtree(cache)
        _write(stage / "app" / "guardian_gateway.py", b"from gateway.app import main\n\nraise SystemExit(main())\n")
        _write(
            stage / "app" / "guardian_gateway_cron_supervisor.py",
            b"from gateway.cron_supervisor import main\n\nraise SystemExit(main())\n",
        )
        _write(stage / "bin" / "guardian-gateway", GATEWAY_WRAPPER)
        _write(stage / "bin" / "guardian-gateway-supervisor", SUPERVISOR_WRAPPER)
        wheel_records = _extract_wheels(wheel_root, stage / "lib")
        inventory = _inventory(stage)
        metadata = {
            "schema_version": 1,
            "version": RELEASE_VERSION,
            "architecture": "x86_64",
            "python": "CPython 3.11",
            "package_mode": "locked_venv",
            "wheels": wheel_records,
            "content_sha256": hashlib.sha256(
                json.dumps(inventory, sort_keys=True, separators=(",", ":")).encode("ascii")
            ).hexdigest(),
        }
        _write(
            stage / "BUILD-METADATA.json",
            (json.dumps(metadata, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii"),
        )
        inventory = _inventory(stage)
        shutil.copytree(stage, destination)
    return {
        "ok": True,
        "destination": str(destination),
        "files": len(inventory),
        "bytes": sum(int(item["size"]) for item in inventory),
        "content_sha256": metadata["content_sha256"],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    parser.add_argument("--wheels")
    args = parser.parse_args()
    result = build(
        Path(args.output),
        wheels=Path(args.wheels) if args.wheels else None,
    )
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
