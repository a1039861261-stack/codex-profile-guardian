from __future__ import annotations

import argparse
import json
import re
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from typing import Iterable, Sequence


MAX_TEXT_BYTES = 4 * 1024 * 1024
PUBLIC_BINARY_SIGNATURES = {
    ".ico": (b"\x00\x00\x01\x00",),
    ".jpeg": (b"\xff\xd8\xff",),
    ".jpg": (b"\xff\xd8\xff",),
    ".png": (b"\x89PNG\r\n\x1a\n",),
}
REQUIRED_PUBLIC_FILES = ("README.md", "SECURITY.md", "docs/PUBLIC-RELEASE-CHECKLIST.md")
LICENSE_CANDIDATES = ("LICENSE", "LICENSE.md", "LICENSE.txt")
FORBIDDEN_BASENAMES = {
    "auth.json",
    "profiles.json",
    "session_index.jsonl",
    "state_5.sqlite",
}
FORBIDDEN_SUFFIXES = (
    ".dpapi",
    ".key",
    ".pem",
    ".pfx",
    ".p12",
    ".sqlite",
    ".sqlite-wal",
    ".sqlite-shm",
    ".dmp",
)
SAFE_SECRET_MARKERS = ("fixture", "example", "invalid", "dummy", "test", "local-ingress")
TEXT_RULES = (
    (
        "windows_user_path",
        re.compile(r"(?i)[a-z]:\\users\\[^\\\r\n]+\\"),
    ),
    (
        "private_key_material",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    ),
    (
        "openai_style_secret",
        re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    ),
    (
        "long_bearer_token",
        re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~-]{32,}\b"),
    ),
)


@dataclass(frozen=True)
class Finding:
    code: str
    path: str
    line: int | None = None


def _is_safe_fixture_match(value: str) -> bool:
    lowered = value.lower()
    return any(marker in lowered for marker in SAFE_SECRET_MARKERS)


def _normalise_relative_path(value: str) -> str:
    return PurePosixPath(value.replace("\\", "/")).as_posix()


def audit_paths(
    root: Path,
    relative_paths: Iterable[str],
    *,
    require_license: bool = True,
) -> list[Finding]:
    findings: list[Finding] = []
    normalised_paths = sorted({_normalise_relative_path(path) for path in relative_paths if path})
    path_set = set(normalised_paths)

    for required in REQUIRED_PUBLIC_FILES:
        if required not in path_set:
            findings.append(Finding("required_public_file_missing", required))

    if require_license and not any(candidate in path_set for candidate in LICENSE_CANDIDATES):
        findings.append(Finding("license_missing", "LICENSE"))

    for relative in normalised_paths:
        pure = PurePosixPath(relative)
        basename = pure.name.lower()
        if basename in FORBIDDEN_BASENAMES or basename.startswith("state_5.sqlite"):
            findings.append(Finding("private_runtime_file", relative))
            continue
        if basename.endswith(FORBIDDEN_SUFFIXES):
            findings.append(Finding("private_or_binary_secret_file", relative))
            continue

        path = root / Path(*pure.parts)
        try:
            size = path.stat().st_size
        except OSError:
            findings.append(Finding("candidate_file_unreadable", relative))
            continue
        if size > MAX_TEXT_BYTES:
            findings.append(Finding("candidate_file_too_large", relative))
            continue
        signatures = PUBLIC_BINARY_SIGNATURES.get(pure.suffix.lower())
        if signatures is not None:
            try:
                header = path.read_bytes()[: max(len(signature) for signature in signatures)]
            except OSError:
                findings.append(Finding("candidate_file_unreadable", relative))
                continue
            if not any(header.startswith(signature) for signature in signatures):
                findings.append(Finding("binary_asset_signature_invalid", relative))
            continue
        try:
            content = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            findings.append(Finding("binary_or_non_utf8_candidate", relative))
            continue
        except OSError:
            findings.append(Finding("candidate_file_unreadable", relative))
            continue

        for line_number, line in enumerate(content.splitlines(), start=1):
            for code, pattern in TEXT_RULES:
                for match in pattern.finditer(line):
                    if code in {"openai_style_secret", "long_bearer_token"} and _is_safe_fixture_match(
                        match.group(0)
                    ):
                        continue
                    findings.append(Finding(code, relative, line_number))

    return sorted(findings, key=lambda item: (item.code, item.path, item.line or 0))


def git_candidate_paths(root: Path) -> list[str]:
    result = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=root,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return [item.decode("utf-8") for item in result.stdout.split(b"\0") if item]


def build_report(root: Path, *, require_license: bool) -> dict[str, object]:
    paths = git_candidate_paths(root)
    findings = audit_paths(root, paths, require_license=require_license)
    return {
        "schema_version": 1,
        "ok": not findings,
        "candidate_files": len(paths),
        "require_license": require_license,
        "findings": [asdict(item) for item in findings],
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Audit Git candidate files before a public release.")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument(
        "--allow-no-license",
        action="store_true",
        help="Allow repository preparation to pass before the owner selects a license.",
    )
    args = parser.parse_args(argv)
    root = args.root.resolve()
    report = build_report(root, require_license=not args.allow_no_license)
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
