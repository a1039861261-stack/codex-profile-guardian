"""Guardian Gateway data-plane core."""

from .models import (
    AttemptFailure,
    AttemptResult,
    BufferedResponse,
    CancelReason,
    CommitResult,
    CommitState,
    GatewayError,
    GatewayLimits,
    RequestSnapshot,
)
from .breaker import (
    BreakerSignal,
    BreakerState,
    BreakerTransition,
    CircuitBreakerPolicy,
    CircuitBreakerRegistry,
    RouteKey,
)
from .config import (
    FailoverGroupConfig,
    ProbeMode,
    ProbePolicy,
    RouteConfig,
    RouteRole,
    StateCompatibility,
)
from .failures import FailureClassifier, FailureDecision
from .router import FailoverRouter, RoutedResult, TrafficSignal
from .service import FailoverGatewayCore
from .state import AtomicBreakerStateStore
from .runtime import AtomicFailoverRouterProvider
from .probes import create_probe_snapshot

__all__ = [
    "AttemptFailure",
    "AttemptResult",
    "BufferedResponse",
    "CancelReason",
    "CommitResult",
    "CommitState",
    "GatewayError",
    "GatewayLimits",
    "RequestSnapshot",
    "AtomicBreakerStateStore",
    "AtomicFailoverRouterProvider",
    "BreakerState",
    "BreakerSignal",
    "BreakerTransition",
    "CircuitBreakerPolicy",
    "CircuitBreakerRegistry",
    "FailoverGatewayCore",
    "FailoverGroupConfig",
    "FailoverRouter",
    "FailureClassifier",
    "FailureDecision",
    "ProbeMode",
    "ProbePolicy",
    "RouteConfig",
    "RouteKey",
    "RouteRole",
    "RoutedResult",
    "StateCompatibility",
    "TrafficSignal",
    "create_probe_snapshot",
]
