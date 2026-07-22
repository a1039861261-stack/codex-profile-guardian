from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import shutil
import struct
import sys
import uuid


RT_ICON = 3
RT_GROUP_ICON = 14
LANG_EN_US = 0x0409


def parse_ico(path: Path) -> tuple[bytes, list[tuple[int, bytes]]]:
    data = path.read_bytes()
    if len(data) < 6 or data[:4] != b"\x00\x00\x01\x00":
        raise ValueError("invalid ICO signature")
    count = struct.unpack_from("<H", data, 4)[0]
    if count < 1 or len(data) < 6 + count * 16:
        raise ValueError("invalid ICO directory")
    group = bytearray(struct.pack("<HHH", 0, 1, count))
    images: list[tuple[int, bytes]] = []
    for index in range(count):
        offset = 6 + index * 16
        width, height, colors, reserved, planes, bits, size, image_offset = struct.unpack_from(
            "<BBBBHHII", data, offset
        )
        if size < 1 or image_offset + size > len(data):
            raise ValueError("ICO image entry is out of bounds")
        resource_id = index + 1
        group.extend(
            struct.pack(
                "<BBBBHHIH",
                width,
                height,
                colors,
                reserved,
                planes,
                bits,
                size,
                resource_id,
            )
        )
        images.append((resource_id, data[image_offset : image_offset + size]))
    return bytes(group), images


def _resource_id(value: int) -> wintypes.LPWSTR:
    return ctypes.cast(ctypes.c_void_p(value), wintypes.LPWSTR)


def update_icon_resources(executable: Path, icon: Path) -> None:
    if os.name != "nt":
        raise RuntimeError("PE icon stamping is supported only on Windows")
    group, images = parse_ico(icon)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    begin = kernel32.BeginUpdateResourceW
    begin.argtypes = [wintypes.LPCWSTR, wintypes.BOOL]
    begin.restype = wintypes.HANDLE
    update = kernel32.UpdateResourceW
    update.argtypes = [
        wintypes.HANDLE,
        wintypes.LPWSTR,
        wintypes.LPWSTR,
        wintypes.WORD,
        wintypes.LPVOID,
        wintypes.DWORD,
    ]
    update.restype = wintypes.BOOL
    end = kernel32.EndUpdateResourceW
    end.argtypes = [wintypes.HANDLE, wintypes.BOOL]
    end.restype = wintypes.BOOL
    handle = begin(str(executable), False)
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    committed = False
    buffers: list[ctypes.Array] = []
    try:
        for resource_id, payload in images:
            buffer = ctypes.create_string_buffer(payload)
            buffers.append(buffer)
            if not update(
                handle,
                _resource_id(RT_ICON),
                _resource_id(resource_id),
                LANG_EN_US,
                buffer,
                len(payload),
            ):
                raise ctypes.WinError(ctypes.get_last_error())
        group_buffer = ctypes.create_string_buffer(group)
        buffers.append(group_buffer)
        if not update(
            handle,
            _resource_id(RT_GROUP_ICON),
            _resource_id(1),
            LANG_EN_US,
            group_buffer,
            len(group),
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        if not end(handle, False):
            raise ctypes.WinError(ctypes.get_last_error())
        committed = True
    finally:
        if not committed:
            end(handle, True)


def has_group_icon(executable: Path) -> bool:
    import pefile

    pe = pefile.PE(str(executable), fast_load=False)
    try:
        directory = getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None)
        return bool(
            directory
            and any(entry.id == RT_GROUP_ICON for entry in directory.entries)
        )
    finally:
        pe.close()


def stamp_executable_icon(executable: Path, icon: Path) -> None:
    executable = executable.resolve(strict=True)
    icon = icon.resolve(strict=True)
    temporary = executable.with_name(f".{executable.stem}.{uuid.uuid4().hex}.icon.tmp.exe")
    try:
        shutil.copy2(executable, temporary)
        update_icon_resources(temporary, icon)
        if not has_group_icon(temporary):
            raise RuntimeError("stamped executable has no RT_GROUP_ICON resource")
        os.replace(temporary, executable)
    finally:
        temporary.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("executable", type=Path)
    parser.add_argument("icon", type=Path)
    args = parser.parse_args()
    stamp_executable_icon(args.executable, args.icon)
    print(json.dumps({"ok": True, "executable": str(args.executable.resolve())}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
