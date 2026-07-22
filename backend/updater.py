from __future__ import annotations

from dataclasses import dataclass
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import threading
from typing import Callable, Mapping
from urllib import error as urlerror
from urllib import request as urlrequest
from urllib.parse import urlparse
import uuid


REPOSITORY = "a1039861261-stack/codex-profile-guardian"
RELEASES_API = f"https://api.github.com/repos/{REPOSITORY}/releases/latest"
MAX_RELEASE_BYTES = 1024 * 1024
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_INSTALLER_BYTES = 256 * 1024 * 1024
ALLOWED_DOWNLOAD_HOSTS = frozenset({
    "github.com",
    "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
})
_VERSION = re.compile(r"^(?:v)?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")


class UpdateError(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def parse_version(value: str) -> tuple[int, int, int]:
    match = _VERSION.fullmatch(str(value).strip())
    if not match:
        raise UpdateError("update_version_invalid")
    return tuple(int(part) for part in match.groups())


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_url(value: object, *, api: bool = False) -> str:
    parsed = urlparse(str(value or ""))
    allowed_hosts = {"api.github.com"} if api else ALLOWED_DOWNLOAD_HOSTS
    if parsed.scheme != "https" or parsed.hostname not in allowed_hosts:
        raise UpdateError("update_url_rejected")
    if parsed.username or parsed.password or parsed.fragment:
        raise UpdateError("update_url_rejected")
    return parsed.geturl()


def _default_fetch(url: str, headers: Mapping[str, str], limit: int) -> tuple[bytes, Mapping[str, str]]:
    request = urlrequest.Request(url, headers=dict(headers), method="GET")
    try:
        with urlrequest.urlopen(request, timeout=20) as response:
            final_url = response.geturl()
            _safe_url(final_url, api=urlparse(url).hostname == "api.github.com")
            length = response.headers.get("Content-Length")
            if length and int(length) > limit:
                raise UpdateError("update_response_too_large")
            payload = response.read(limit + 1)
            if len(payload) > limit:
                raise UpdateError("update_response_too_large")
            return payload, dict(response.headers.items())
    except urlerror.HTTPError as exc:
        if exc.code == 304:
            raise UpdateError("update_not_modified") from exc
        if exc.code == 404:
            raise UpdateError("update_repository_unavailable") from exc
        if exc.code in (403, 429):
            raise UpdateError("update_rate_limited") from exc
        raise UpdateError("update_http_failed") from exc
    except (OSError, ValueError) as exc:
        if isinstance(exc, UpdateError):
            raise
        raise UpdateError("update_network_failed") from exc


Fetch = Callable[[str, Mapping[str, str], int], tuple[bytes, Mapping[str, str]]]
Launcher = Callable[[Path], None]


def _default_launcher(path: Path) -> None:
    if os.name != "nt":
        raise UpdateError("update_install_windows_only")
    subprocess.Popen(
        [str(path)],
        cwd=str(path.parent),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=0x08000000,
        close_fds=True,
    )


@dataclass(frozen=True, slots=True)
class ReleaseCandidate:
    version: str
    release_url: str
    installer_name: str
    installer_url: str
    installer_bytes: int
    installer_sha256: str
    manifest_name: str
    manifest_url: str


class GitHubReleaseUpdater:
    def __init__(
        self,
        current_version: str,
        data_dir: str | Path,
        *,
        fetch: Fetch = _default_fetch,
        launcher: Launcher = _default_launcher,
    ) -> None:
        parse_version(current_version)
        self.current_version = current_version.lstrip("v")
        self.root = Path(data_dir).resolve() / "updates"
        self.state_path = self.root / "state.json"
        self._fetch = fetch
        self._launcher = launcher
        self._lock = threading.Lock()

    def status(self) -> dict[str, object]:
        state = self._read_state()
        public = {
            "state": state.get("state", "idle"),
            "current_version": self.current_version,
            "latest_version": state.get("latest_version"),
            "checked_at": state.get("checked_at"),
            "release_url": state.get("release_url"),
            "downloaded": bool(state.get("downloaded")),
            "error_code": state.get("error_code"),
            "repository": REPOSITORY,
        }
        return public

    def check(self) -> dict[str, object]:
        with self._lock:
            try:
                previous = self._read_state()
                request_headers = {
                    "Accept": "application/vnd.github+json",
                    "User-Agent": "Codex-Profile-Guardian-Updater",
                    "X-GitHub-Api-Version": "2022-11-28",
                }
                if previous.get("etag"):
                    request_headers["If-None-Match"] = str(previous["etag"])
                payload, headers = self._fetch(
                    _safe_url(RELEASES_API, api=True),
                    request_headers,
                    MAX_RELEASE_BYTES,
                )
                release = self._release_document(payload)
                candidate = self._candidate(release)
                state = self._candidate_state(candidate)
                state["etag"] = headers.get("ETag") or headers.get("etag")
                self._write_state(state)
            except UpdateError as exc:
                state = self._read_state()
                if exc.code == "update_not_modified" and state.get("latest_version"):
                    state["checked_at"] = utc_now()
                    state["error_code"] = None
                    self._write_state(state)
                    return self.status()
                state.update({
                    "state": "error",
                    "checked_at": utc_now(),
                    "error_code": exc.code,
                    "downloaded": False,
                })
                self._write_state(state)
            return self.status()

    def download(self) -> dict[str, object]:
        with self._lock:
            state = self._read_state()
            candidate = self._candidate_from_state(state)
            if parse_version(candidate.version) <= parse_version(self.current_version):
                raise UpdateError("update_not_available")
            payload, _ = self._fetch(candidate.installer_url, {
                "Accept": "application/octet-stream",
                "User-Agent": "Codex-Profile-Guardian-Updater",
            }, min(MAX_INSTALLER_BYTES, candidate.installer_bytes))
            if len(payload) != candidate.installer_bytes:
                raise UpdateError("update_installer_size_mismatch")
            digest = hashlib.sha256(payload).hexdigest()
            if digest.lower() != candidate.installer_sha256.lower():
                raise UpdateError("update_installer_hash_mismatch")
            version_root = (self.root / f"v{candidate.version}").resolve()
            if self.root.resolve() not in version_root.parents:
                raise UpdateError("update_path_rejected")
            version_root.mkdir(parents=True, exist_ok=True)
            target = version_root / candidate.installer_name
            temporary = version_root / f".{candidate.installer_name}.{uuid.uuid4().hex}.part"
            temporary.write_bytes(payload)
            os.replace(temporary, target)
            state.update({"state": "downloaded", "downloaded": True, "installer_file": target.name})
            self._write_state(state)
            return self.status()

    def install(self, *, confirmed: bool) -> dict[str, object]:
        if confirmed is not True:
            raise UpdateError("update_install_confirmation_required")
        with self._lock:
            state = self._read_state()
            candidate = self._candidate_from_state(state)
            if not state.get("downloaded"):
                raise UpdateError("update_not_downloaded")
            target = (self.root / f"v{candidate.version}" / candidate.installer_name).resolve()
            if self.root.resolve() not in target.parents or not target.is_file():
                raise UpdateError("update_installer_missing")
            if target.stat().st_size != candidate.installer_bytes:
                raise UpdateError("update_installer_size_mismatch")
            if _sha256_file(target).lower() != candidate.installer_sha256.lower():
                raise UpdateError("update_installer_hash_mismatch")
            self._launcher(target)
            state.update({"state": "installing", "install_started_at": utc_now()})
            self._write_state(state)
            return self.status()

    def check_and_download(self) -> dict[str, object]:
        result = self.check()
        if result["state"] == "available":
            return self.download()
        return result

    def _candidate_state(self, candidate: ReleaseCandidate) -> dict[str, object]:
        available = parse_version(candidate.version) > parse_version(self.current_version)
        return {
            "schema_version": 1,
            "state": "available" if available else "up_to_date",
            "current_version": self.current_version,
            "latest_version": candidate.version,
            "checked_at": utc_now(),
            "release_url": candidate.release_url,
            "downloaded": False,
            "error_code": None,
            "installer_name": candidate.installer_name,
            "installer_url": candidate.installer_url,
            "installer_bytes": candidate.installer_bytes,
            "installer_sha256": candidate.installer_sha256,
            "manifest_name": candidate.manifest_name,
            "manifest_url": candidate.manifest_url,
        }

    def _candidate(self, release: Mapping[str, object]) -> ReleaseCandidate:
        if release.get("draft") is not False or release.get("prerelease") is not False:
            raise UpdateError("update_release_not_stable")
        version = str(release.get("tag_name") or "").removeprefix("v")
        parse_version(version)
        assets = release.get("assets")
        if not isinstance(assets, list):
            raise UpdateError("update_assets_invalid")
        expected_installer = f"CodexProfileGuardianSetup-v{version}.exe"
        expected_manifest = f"Codex-Profile-Guardian-v{version}-manifest.json"
        by_name = {str(item.get("name")): item for item in assets if isinstance(item, Mapping)}
        installer = by_name.get(expected_installer)
        manifest = by_name.get(expected_manifest)
        if not isinstance(installer, Mapping) or not isinstance(manifest, Mapping):
            raise UpdateError("update_assets_missing")
        manifest_url = _safe_url(manifest.get("browser_download_url"))
        manifest_payload, _ = self._fetch(manifest_url, {
            "Accept": "application/octet-stream",
            "User-Agent": "Codex-Profile-Guardian-Updater",
        }, MAX_MANIFEST_BYTES)
        try:
            manifest_document = json.loads(manifest_payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise UpdateError("update_manifest_invalid") from exc
        if not isinstance(manifest_document, Mapping):
            raise UpdateError("update_manifest_invalid")
        if manifest_document.get("product") != "Codex Profile Guardian" or str(manifest_document.get("version")) != version:
            raise UpdateError("update_manifest_identity_mismatch")
        artifacts = manifest_document.get("artifacts")
        if not isinstance(artifacts, list):
            raise UpdateError("update_manifest_invalid")
        entries = [item for item in artifacts if isinstance(item, Mapping) and item.get("name") == expected_installer]
        if len(entries) != 1:
            raise UpdateError("update_manifest_installer_missing")
        entry = entries[0]
        size = entry.get("bytes")
        digest = str(entry.get("sha256") or "")
        if type(size) is not int or not 1 <= size <= MAX_INSTALLER_BYTES or not _SHA256.fullmatch(digest):
            raise UpdateError("update_manifest_installer_invalid")
        api_size = installer.get("size")
        if type(api_size) is int and api_size != size:
            raise UpdateError("update_manifest_installer_invalid")
        return ReleaseCandidate(
            version=version,
            release_url=_safe_url(release.get("html_url")),
            installer_name=expected_installer,
            installer_url=_safe_url(installer.get("browser_download_url")),
            installer_bytes=size,
            installer_sha256=digest.lower(),
            manifest_name=expected_manifest,
            manifest_url=manifest_url,
        )

    @staticmethod
    def _release_document(payload: bytes) -> Mapping[str, object]:
        try:
            document = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise UpdateError("update_release_invalid") from exc
        if not isinstance(document, Mapping):
            raise UpdateError("update_release_invalid")
        return document

    def _candidate_from_state(self, state: Mapping[str, object]) -> ReleaseCandidate:
        try:
            candidate = ReleaseCandidate(
                version=str(state["latest_version"]),
                release_url=_safe_url(state["release_url"]),
                installer_name=str(state["installer_name"]),
                installer_url=_safe_url(state["installer_url"]),
                installer_bytes=int(state["installer_bytes"]),
                installer_sha256=str(state["installer_sha256"]),
                manifest_name=str(state["manifest_name"]),
                manifest_url=_safe_url(state["manifest_url"]),
            )
        except (KeyError, TypeError, ValueError, UpdateError) as exc:
            raise UpdateError("update_candidate_missing") from exc
        expected = f"CodexProfileGuardianSetup-v{candidate.version}.exe"
        if candidate.installer_name != expected or not _SHA256.fullmatch(candidate.installer_sha256):
            raise UpdateError("update_candidate_invalid")
        return candidate

    def _read_state(self) -> dict[str, object]:
        try:
            document = json.loads(self.state_path.read_text(encoding="utf-8"))
            if isinstance(document, dict) and document.get("schema_version") == 1:
                return document
        except (FileNotFoundError, OSError, UnicodeDecodeError, json.JSONDecodeError):
            pass
        return {"schema_version": 1, "state": "idle", "current_version": self.current_version}

    def _write_state(self, state: Mapping[str, object]) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        payload = (json.dumps(dict(state), ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        temporary = self.root / f".state.{uuid.uuid4().hex}.tmp"
        temporary.write_bytes(payload)
        os.replace(temporary, self.state_path)
