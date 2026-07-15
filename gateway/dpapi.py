from __future__ import annotations

import ctypes
from ctypes import wintypes
import os
from typing import Any


class DpapiError(RuntimeError):
    pass


class DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]


def _blob(data: bytes) -> tuple[DATA_BLOB, Any]:
    buffer = ctypes.create_string_buffer(data)
    return DATA_BLOB(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_byte))), buffer


def protect_current_user(data: bytes) -> bytes:
    if os.name != "nt":
        raise DpapiError("gateway_dpapi_requires_windows")
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    input_blob, keepalive = _blob(data)
    output_blob = DATA_BLOB()
    if not crypt32.CryptProtectData(
        ctypes.byref(input_blob),
        "Codex Profile Guardian Gateway",
        None,
        None,
        None,
        0x01,
        ctypes.byref(output_blob),
    ):
        raise DpapiError("gateway_dpapi_protect_failed")
    try:
        return ctypes.string_at(output_blob.pbData, output_blob.cbData)
    finally:
        kernel32.LocalFree(output_blob.pbData)
        del keepalive


def unprotect_current_user(data: bytes) -> bytes:
    if os.name != "nt":
        raise DpapiError("gateway_dpapi_requires_windows")
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    input_blob, keepalive = _blob(data)
    output_blob = DATA_BLOB()
    if not crypt32.CryptUnprotectData(
        ctypes.byref(input_blob),
        None,
        None,
        None,
        None,
        0x01,
        ctypes.byref(output_blob),
    ):
        raise DpapiError("gateway_dpapi_unprotect_failed")
    try:
        return ctypes.string_at(output_blob.pbData, output_blob.cbData)
    finally:
        kernel32.LocalFree(output_blob.pbData)
        del keepalive
