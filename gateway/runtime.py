from __future__ import annotations

from threading import Lock

from .breaker import BreakerStateStore, CircuitBreakerRegistry
from .config import AtomicGroupConfig, FailoverGroupConfig, SecretResolver
from .failures import FailureClassifier
from .router import FailoverRouter


class FailoverRouterLease:
    def __init__(
        self,
        router: FailoverRouter,
        breaker: CircuitBreakerRegistry,
        versions: tuple[tuple[object, int, str], ...],
    ) -> None:
        self.router = router
        self._breaker = breaker
        self._versions = versions
        self._lock = Lock()
        self._released = False

    def release(self) -> None:
        with self._lock:
            if self._released:
                return
            self._released = True
        self._breaker.release_versions(self._versions)


class AtomicFailoverRouterProvider:
    def __init__(
        self,
        initial: FailoverGroupConfig,
        breaker: CircuitBreakerRegistry,
        classifier: FailureClassifier,
        secrets: SecretResolver,
        *,
        state_store: BreakerStateStore | None = None,
    ) -> None:
        self._configs = AtomicGroupConfig(initial)
        self._breaker = breaker
        self._classifier = classifier
        self._secrets = secrets
        self._lock = Lock()
        self._router = self._build(initial)
        self._restored_routes = 0
        if state_store is not None:
            self._restored_routes = breaker.restore_from_store(state_store)

    @property
    def restored_routes(self) -> int:
        return self._restored_routes

    def acquire(self) -> FailoverRouterLease:
        with self._lock:
            router = self._router
            versions = router.version_keys
            self._breaker.pin_versions(versions)
            return FailoverRouterLease(router, self._breaker, versions)

    def current_config(self) -> FailoverGroupConfig:
        with self._lock:
            return self._configs.snapshot()

    def activate(self, next_config: FailoverGroupConfig) -> FailoverGroupConfig:
        with self._lock:
            current = self._configs.snapshot()
            if next_config.instance_id != current.instance_id:
                raise ValueError("failover_group_identity_changed")
            if next_config.revision <= current.revision:
                raise ValueError("failover_group_revision_must_increase")
            next_router = self._build(next_config)
            previous = self._configs.activate(next_config)
            self._router = next_router
            return previous

    def _build(self, config: FailoverGroupConfig) -> FailoverRouter:
        return FailoverRouter(
            config,
            self._breaker,
            self._classifier,
            self._secrets,
        )
