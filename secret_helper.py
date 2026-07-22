from __future__ import annotations

import sys

from backend.guardian import GuardianService
from gateway.dpapi import unprotect_current_user
from gateway.tokens import read_gateway_ingress_token, read_gateway_token


def main() -> int:
    args = sys.argv[1:]
    if len(args) == 2 and args[0] == "gateway-ingress":
        try:
            token = read_gateway_ingress_token(
                args[1],
                unprotect=unprotect_current_user,
            )
            sys.stdout.buffer.write(token.encode("ascii"))
            sys.stdout.buffer.flush()
            return 0
        except Exception:
            return 1
    if len(args) == 2 and args[0] == "gateway-control":
        try:
            token = read_gateway_token(
                args[1],
                "control",
                unprotect=unprotect_current_user,
            )
            sys.stdout.buffer.write(token.encode("ascii"))
            sys.stdout.buffer.flush()
            return 0
        except Exception:
            return 1
    if len(args) != 2 or args[0] != "secret":
        return 2
    try:
        sys.stdout.buffer.write(GuardianService().decrypt_secret(args[1]))
        sys.stdout.buffer.flush()
        return 0
    except Exception:
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
