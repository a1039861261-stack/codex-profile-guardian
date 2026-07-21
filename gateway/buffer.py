from __future__ import annotations

from .cancellation import CancellationToken
from .models import GatewayError


class BoundedMemoryBuffer:
    def __init__(self, max_bytes: int) -> None:
        if max_bytes <= 0:
            raise ValueError("buffer_limit_must_be_positive")
        self._max_bytes = max_bytes
        self._chunks: list[bytes] = []
        self._size = 0
        self._sealed = False

    @property
    def size(self) -> int:
        return self._size

    def append(self, chunk: bytes, cancellation: CancellationToken) -> None:
        if self._sealed:
            raise RuntimeError("buffer_is_sealed")
        cancellation.raise_if_cancelled()
        next_size = self._size + len(chunk)
        if next_size > self._max_bytes:
            self.destroy()
            raise GatewayError("guardian_response_too_large", "上游响应超过本地网关缓冲上限。", http_status=502)
        if chunk:
            self._chunks.append(bytes(chunk))
            self._size = next_size

    def seal(self) -> tuple[bytes, ...]:
        if self._sealed:
            raise RuntimeError("buffer_is_sealed")
        self._sealed = True
        return tuple(self._chunks)

    def destroy(self) -> None:
        self._chunks.clear()
        self._size = 0
        self._sealed = True
