from __future__ import annotations

import os
from pathlib import Path
import stat
from typing import BinaryIO


class SingletonAlreadyRunning(RuntimeError):
    pass


class SingleInstanceLock:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._stream: BinaryIO | None = None

    @property
    def acquired(self) -> bool:
        return self._stream is not None

    def acquire(self) -> None:
        if self._stream is not None:
            raise RuntimeError("singleton_lock_already_acquired")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.path.parent, stat.S_IRWXU)
        except OSError:
            pass
        stream = self.path.open("a+b")
        try:
            if self._try_lock(stream):
                stream.seek(0)
                stream.truncate()
                stream.write(f"{os.getpid()}\n".encode("ascii"))
                stream.flush()
                os.fsync(stream.fileno())
                self._stream = stream
                return
        except Exception:
            stream.close()
            raise
        stream.close()
        raise SingletonAlreadyRunning("guardian_gateway_already_running")

    def release(self) -> None:
        stream = self._stream
        if stream is None:
            return
        self._stream = None
        try:
            self._unlock(stream)
        finally:
            stream.close()

    def __enter__(self) -> SingleInstanceLock:
        self.acquire()
        return self

    def __exit__(self, *_args) -> None:
        self.release()

    @staticmethod
    def _try_lock(stream: BinaryIO) -> bool:
        if os.name == "nt":
            import msvcrt

            stream.seek(0)
            try:
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
                return True
            except OSError:
                return False
        import fcntl

        try:
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except BlockingIOError:
            return False

    @staticmethod
    def _unlock(stream: BinaryIO) -> None:
        if os.name == "nt":
            import msvcrt

            stream.seek(0)
            try:
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            except OSError:
                pass
            return
        import fcntl

        try:
            fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
        except OSError:
            pass
