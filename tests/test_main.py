from __future__ import annotations

import threading
import unittest

from main import QuotaRefreshWorker, UpdateRefreshWorker


class QuotaRefreshWorkerTests(unittest.TestCase):
    def test_refreshes_immediately_and_repeats_until_stopped(self) -> None:
        repeated = threading.Event()

        class Service:
            calls = 0

            def refresh_official_quotas(self) -> None:
                self.calls += 1
                if self.calls >= 2:
                    repeated.set()

        service = Service()
        worker = QuotaRefreshWorker(service, interval_seconds=0.01)
        worker.start()
        self.assertTrue(repeated.wait(timeout=1))
        worker.stop()
        self.assertGreaterEqual(service.calls, 2)
        self.assertFalse(worker.thread.is_alive())

    def test_refresh_errors_do_not_stop_the_worker(self) -> None:
        recovered = threading.Event()

        class Service:
            calls = 0

            def refresh_official_quotas(self) -> None:
                self.calls += 1
                if self.calls == 1:
                    raise RuntimeError("temporary quota failure")
                recovered.set()

        worker = QuotaRefreshWorker(Service(), interval_seconds=0.01)
        worker.start()
        self.assertTrue(recovered.wait(timeout=1))
        worker.stop()
        self.assertFalse(worker.thread.is_alive())


class UpdateRefreshWorkerTests(unittest.TestCase):
    def test_checks_after_startup_delay_and_repeats_until_stopped(self) -> None:
        repeated = threading.Event()

        class Service:
            calls = 0

            def automatic_update_cycle(self) -> None:
                self.calls += 1
                if self.calls >= 2:
                    repeated.set()

        service = Service()
        worker = UpdateRefreshWorker(
            service,
            interval_seconds=0.01,
            startup_delay_seconds=0.01,
        )
        worker.start()
        self.assertTrue(repeated.wait(timeout=1))
        worker.stop()
        self.assertGreaterEqual(service.calls, 2)
        self.assertFalse(worker.thread.is_alive())

    def test_update_errors_do_not_stop_the_worker(self) -> None:
        recovered = threading.Event()

        class Service:
            calls = 0

            def automatic_update_cycle(self) -> None:
                self.calls += 1
                if self.calls == 1:
                    raise RuntimeError("temporary update failure")
                recovered.set()

        worker = UpdateRefreshWorker(
            Service(),
            interval_seconds=0.01,
            startup_delay_seconds=0,
        )
        worker.start()
        self.assertTrue(recovered.wait(timeout=1))
        worker.stop()
        self.assertFalse(worker.thread.is_alive())


if __name__ == "__main__":
    unittest.main()
