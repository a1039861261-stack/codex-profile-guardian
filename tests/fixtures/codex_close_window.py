"""Disposable off-screen Win32 windows for graceful-close integration tests."""
import ctypes
from ctypes import wintypes
import json
import os
import sys


def main():
    mode, delay, count = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
    user = ctypes.WinDLL("user32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    callback_type = ctypes.WINFUNCTYPE(ctypes.c_ssize_t, wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM)

    class WindowClass(ctypes.Structure):
        _fields_ = [
            ("style", wintypes.UINT), ("callback", callback_type),
            ("cls_extra", ctypes.c_int), ("wnd_extra", ctypes.c_int),
            ("instance", wintypes.HINSTANCE), ("icon", wintypes.HICON),
            ("cursor", wintypes.HANDLE), ("background", wintypes.HBRUSH),
            ("menu", wintypes.LPCWSTR), ("class_name", wintypes.LPCWSTR),
        ]

    signatures = (
        (kernel.GetModuleHandleW, [wintypes.LPCWSTR], wintypes.HMODULE),
        (kernel.GetCurrentProcess, [], wintypes.HANDLE),
        (kernel.GetProcessTimes, [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4, wintypes.BOOL),
        (user.DefWindowProcW, [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM], ctypes.c_ssize_t),
        (user.RegisterClassW, [ctypes.POINTER(WindowClass)], wintypes.ATOM),
        (user.CreateWindowExW, [wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int, wintypes.HWND, wintypes.HMENU, wintypes.HINSTANCE, wintypes.LPVOID], wintypes.HWND),
        (user.DestroyWindow, [wintypes.HWND], wintypes.BOOL),
        (user.ShowWindow, [wintypes.HWND, ctypes.c_int], wintypes.BOOL),
        (user.SetTimer, [wintypes.HWND, ctypes.c_size_t, wintypes.UINT, ctypes.c_void_p], ctypes.c_size_t),
        (user.GetMessageW, [ctypes.POINTER(wintypes.MSG), wintypes.HWND, wintypes.UINT, wintypes.UINT], wintypes.BOOL),
        (user.TranslateMessage, [ctypes.POINTER(wintypes.MSG)], wintypes.BOOL),
        (user.DispatchMessageW, [ctypes.POINTER(wintypes.MSG)], ctypes.c_ssize_t),
    )
    for function, arguments, result in signatures:
        function.argtypes, function.restype = arguments, result
    remaining = count
    pending = set()

    @callback_type
    def receive(hwnd, message, wparam, lparam):
        nonlocal remaining
        if message == 0x0010:
            if mode == "ignore":
                return 0
            if delay and hwnd not in pending:
                pending.add(hwnd)
                user.SetTimer(hwnd, 1, delay, None)
            elif not delay:
                user.DestroyWindow(hwnd)
            return 0
        if message == 0x0113:
            user.DestroyWindow(hwnd)
            return 0
        if message == 0x0002:
            remaining -= 1
            if not remaining:
                user.PostQuitMessage(0)
            return 0
        return user.DefWindowProcW(hwnd, message, wparam, lparam)

    instance = kernel.GetModuleHandleW(None)
    definition = WindowClass()
    definition.callback, definition.instance, definition.class_name = receive, instance, "GuardianIsolatedCloseTest"
    if not user.RegisterClassW(ctypes.byref(definition)):
        raise ctypes.WinError(ctypes.get_last_error())
    for index in range(count):
        hwnd = user.CreateWindowExW(0x08000080, definition.class_name, "Guardian isolated close test", 0x00CF0000, -32000, -32000, 80, 80, None, None, instance, None)
        if not hwnd:
            raise ctypes.WinError(ctypes.get_last_error())
        user.ShowWindow(hwnd, 4)  # Off-screen, no activation, no taskbar entry.
    created, exited, kernel_time, user_time = (wintypes.FILETIME() for _ in range(4))
    if not kernel.GetProcessTimes(kernel.GetCurrentProcess(), ctypes.byref(created), ctypes.byref(exited), ctypes.byref(kernel_time), ctypes.byref(user_time)):
        raise ctypes.WinError(ctypes.get_last_error())
    print(json.dumps({"pid": os.getpid(), "started": created.dwHighDateTime << 32 | created.dwLowDateTime}), flush=True)
    message = wintypes.MSG()
    while user.GetMessageW(ctypes.byref(message), None, 0, 0) > 0:
        user.TranslateMessage(ctypes.byref(message))
        user.DispatchMessageW(ctypes.byref(message))


if __name__ == "__main__":
    main()
