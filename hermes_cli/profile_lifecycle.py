"""Bounded profile lifecycle trigger for an operator-owned provisioning service.

The socket is inherited process configuration, captured at package startup.
Requests are untrusted notifications, not authorization: the operator service
must bind the peer/tenant/profile to its approved targets and derive the durable
operation identity. No host paths, credentials, or provisioning commands cross
this interface. Creation remains successful when provisioning is unavailable.
"""
from __future__ import annotations

import json
import os
import re
import socket
import time
from typing import Any

import hermes_cli

MAX_PACKET_BYTES = 64 * 1024
REQUEST_TIMEOUT = 2.0
_EVENTS = {"profile_created", "profile_configured", "profile_status"}
_STATUSES = {"INSTALLING", "WAITING_MODEL", "SEEDING", "WAITING_AUTH", "VALIDATING", "READY", "FAILED"}


def _local_status(profile: str, status: str, error: str) -> dict[str, Any]:
    return {"version": 1, "profile": profile, "operation_id": None, "status": status, "error": error}


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate response field")
        result[key] = value
    return result


def _invalid_constant(value):
    raise ValueError("Non-JSON response value")


def _validate_response(packet: bytes, profile: str) -> dict[str, Any]:
    result = json.loads(packet.decode("utf-8"), object_pairs_hook=_unique_object,
                        parse_constant=_invalid_constant)
    required = {"version", "profile", "operation_id", "status"}
    if not isinstance(result, dict) or not required <= result.keys() or result.keys() - required - {"error"}:
        raise ValueError("Unexpected response schema")
    if type(result["version"]) is not int or result["version"] != 1 or result["profile"] != profile:
        raise ValueError("Response identity or version mismatch")
    operation_id, status, error = result["operation_id"], result["status"], result.get("error")
    if not isinstance(operation_id, str) or not re.fullmatch(r"[0-9a-f]{64}", operation_id):
        raise ValueError("Invalid operation identity")
    if not isinstance(status, str) or status not in _STATUSES:
        raise ValueError("Unknown provisioning status")
    if error is not None and (not isinstance(error, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", error)):
        raise ValueError("Invalid provisioning error code")
    if status == "READY" and error is not None:
        raise ValueError("Contradictory readiness response")
    return result


def notify_profile(profile: str, event: str = "profile_status") -> dict[str, Any]:
    """Return a verified durable status, or an explicit non-ready local status.

    One JSON line is exchanged under a two-second total deadline. The service
    must acknowledge quickly and perform provisioning asynchronously. A timeout
    never removes or rolls back the already-created profile.
    """
    from hermes_cli.profiles import normalize_profile_name, validate_profile_name

    try:
        canonical = normalize_profile_name(profile)
        validate_profile_name(canonical)
        if event not in _EVENTS:
            raise ValueError("Unknown lifecycle event")
    except (TypeError, ValueError, AttributeError):
        return _local_status("", "FAILED", "INVALID_PROFILE_EVENT")
    path = hermes_cli._CONSOLIDA_CONTROL_SOCKET
    if not path:
        return _local_status(canonical, "WAITING_CONFIG", "CONTROL_NOT_CONFIGURED")
    if not isinstance(path, str) or not os.path.isabs(path) or "\0" in path:
        return _local_status(canonical, "FAILED", "INVALID_CONTROL_CONFIGURATION")
    if not hasattr(socket, "AF_UNIX"):
        return _local_status(canonical, "FAILED", "CONTROL_PLATFORM_UNSUPPORTED")
    request = json.dumps({"version": 1, "event": event, "profile": canonical},
                         separators=(",", ":")).encode("utf-8") + b"\n"
    deadline = time.monotonic() + REQUEST_TIMEOUT
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            def remaining():
                seconds = deadline - time.monotonic()
                if seconds <= 0:
                    raise TimeoutError("Lifecycle deadline exceeded")
                connection.settimeout(seconds)

            remaining()
            connection.connect(path)
            remaining()
            connection.sendall(request)
            packet = bytearray()
            while b"\n" not in packet:
                remaining()
                block = connection.recv(min(4096, MAX_PACKET_BYTES + 1 - len(packet)))
                if not block:
                    raise ValueError("Incomplete lifecycle response")
                packet.extend(block)
                if len(packet) > MAX_PACKET_BYTES:
                    raise ValueError("Lifecycle response exceeds limit")
            line, trailing = bytes(packet).split(b"\n", 1)
            if trailing:
                raise ValueError("Unexpected additional lifecycle response")
            return _validate_response(line, canonical)
    except TimeoutError:
        return _local_status(canonical, "FAILED", "CONTROL_TIMEOUT")
    except OSError:
        return _local_status(canonical, "FAILED", "CONTROL_UNAVAILABLE")
    except (ValueError, TypeError, RecursionError):
        return _local_status(canonical, "FAILED", "INVALID_CONTROL_RESPONSE")
