from __future__ import annotations

import shutil
from pathlib import Path

from .models import GatewayError


class DiskWatermark:
    def __init__(self, path: str | Path, minimum_free_bytes: int) -> None:
        if minimum_free_bytes <= 0:
            raise ValueError("minimum_free_bytes_must_be_positive")
        self.path = Path(path)
        self.minimum_free_bytes = minimum_free_bytes

    def available_bytes(self) -> int:
        target = self.path
        while not target.exists() and target != target.parent:
            target = target.parent
        return shutil.disk_usage(target).free

    def admission_error(self) -> GatewayError | None:
        try:
            available = self.available_bytes()
        except OSError:
            return GatewayError(
                "guardian_disk_status_unavailable",
                "无法确认本地磁盘状态，网关已安全停止新请求。",
                http_status=503,
            )
        if available < self.minimum_free_bytes:
            return GatewayError(
                "guardian_disk_low_watermark",
                "本地磁盘可用空间低于安全水位，网关已停止新请求。",
                http_status=503,
            )
        return None
