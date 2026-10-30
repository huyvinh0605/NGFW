"""Observe asynchronous M4 counters without accepting a pre-request heartbeat."""

import calendar
import re
import time
from datetime import datetime


class HealthObservationError(RuntimeError):
    def __init__(self, message, observations):
        super().__init__(message)
        self.observations = observations


def _rfc3339_ns(value):
    """Keep Go's RFC3339Nano precision when ordering engine timestamps."""
    match = re.fullmatch(
        r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:\d{2})",
        value if isinstance(value, str) else "",
    )
    if match is None:
        raise ValueError("missing or invalid engine observation timestamp")
    stamp = datetime.fromisoformat(match[1] + match[3].replace("Z", "+00:00"))
    return calendar.timegm(stamp.utctimetuple()) * 1_000_000_000 + int((match[2] or "0").ljust(9, "0"))


def wait_for_health_counters(fetch, *, generation, after, minimum_counters,
                             timeout=8.0, interval=0.2, monotonic=time.monotonic,
                             sleep=time.sleep):
    """Wait for a healthy heartbeat after engine request evidence in its generation.

    fetch receives the remaining per-call timeout and returns the lab API wrapper
    {status, response: {data: health}}. The deadline uses the controller's
    monotonic clock; timestamp ordering uses only the NGFW engine's timestamps.
    A changed generation fails immediately so another runtime cannot satisfy the
    counter assertions. A permanently zero counter still fails at the deadline.
    """
    if type(generation) is not int or generation < 1 or not 0 < interval <= timeout <= 60:
        raise ValueError("invalid health observation generation or deadline")
    if not minimum_counters or any(type(value) is not int or value < 0 for value in minimum_counters.values()):
        raise ValueError("minimum counters must be nonnegative integers")
    after_ns = _rfc3339_ns(after)
    deadline = monotonic() + timeout
    observations = []
    while monotonic() < deadline:
        remaining = deadline - monotonic()
        try:
            reply = fetch(min(2.0, remaining))
            data = reply.get("response", {}).get("data", {})
            counters = data.get("counters", {})
            sample = {
                "http_status": reply.get("status"),
                "generation": data.get("generation"),
                "status": data.get("status"),
                "updated_at": data.get("updated_at"),
                "counters": {name: counters.get(name) for name in minimum_counters},
            }
        except Exception as error:
            observations.append({"fetch_error": str(error)})
        else:
            observations.append(sample)
            if reply.get("status") == 200:
                if type(data.get("generation")) is int and data["generation"] != generation:
                    raise HealthObservationError("configuration generation changed while observing counters", observations)
                try:
                    newer_than_request = _rfc3339_ns(data.get("updated_at")) > after_ns
                except ValueError as error:
                    sample["timestamp_error"] = str(error)
                    newer_than_request = False
                counters_reached = all(type(counters.get(name)) is int and counters[name] >= minimum
                                       for name, minimum in minimum_counters.items())
                if (data.get("generation") == generation and data.get("enabled") is True
                        and data.get("status") == "healthy" and data.get("proxy_reachable") is True
                        and newer_than_request and counters_reached):
                    return reply, observations
        remaining = deadline - monotonic()
        if remaining > 0:
            sleep(min(interval, remaining))
    raise HealthObservationError("no healthy post-request heartbeat reached the required counters before the deadline",
                                 observations)
