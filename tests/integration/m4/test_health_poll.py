import unittest

from health_poll import HealthObservationError, wait_for_health_counters


BEFORE = "2026-10-24T05:40:10.650317533Z"
REQUEST = "2026-10-24T05:40:11.160997209Z"
AFTER = "2026-10-24T05:40:11.650317533Z"
MINIMUM = {"decrypted": 1, "intercepted": 1, "request_allowed": 1}


def health(stamp=AFTER, counters=None, **overrides):
    data = {"generation": 63, "enabled": True, "status": "healthy", "proxy_reachable": True,
            "updated_at": stamp, "counters": dict(MINIMUM if counters is None else counters)}
    data.update(overrides)
    return {"status": 200, "response": {"data": data}}


class FakeClock:
    def __init__(self):
        self.now = 0.0

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


class HealthPollingTests(unittest.TestCase):
    def observe(self, replies, **kwargs):
        clock = FakeClock()
        remaining = iter(replies)
        last = replies[-1]

        def fetch(timeout):
            self.assertGreater(timeout, 0)
            return next(remaining, last)

        return wait_for_health_counters(fetch, generation=63, after=REQUEST, minimum_counters=MINIMUM,
                                        timeout=1, interval=0.2, monotonic=clock.monotonic,
                                        sleep=clock.sleep, **kwargs)

    def test_old_vm_failure_waits_for_new_heartbeat(self):
        reply, observations = self.observe([health(BEFORE, {name: 0 for name in MINIMUM}), health()])
        self.assertEqual(reply, health())
        self.assertEqual(len(observations), 2)
        self.assertEqual(observations[0]["updated_at"], BEFORE)

    def test_old_snapshot_cannot_pass_even_with_large_counters(self):
        reply, observations = self.observe([health(BEFORE, {name: 100 for name in MINIMUM}), health()])
        self.assertEqual(reply, health())
        self.assertEqual(len(observations), 2)

    def test_fresh_snapshot_waits_until_all_required_counters_arrive(self):
        reply, observations = self.observe([health(counters={"decrypted": 1, "intercepted": 1, "request_allowed": 0}), health()])
        self.assertEqual(reply, health())
        self.assertEqual(len(observations), 2)

    def test_permanently_zero_counters_fail_with_bounded_observations(self):
        with self.assertRaises(HealthObservationError) as error:
            self.observe([health(counters={name: 0 for name in MINIMUM})])
        self.assertIn("before the deadline", str(error.exception))
        self.assertEqual(len(error.exception.observations), 5)

    def test_other_generation_cannot_satisfy_counters(self):
        with self.assertRaises(HealthObservationError) as error:
            self.observe([health(generation=64)])
        self.assertIn("generation changed", str(error.exception))
        self.assertEqual(len(error.exception.observations), 1)

    def test_nanosecond_equal_timestamp_is_not_after_request(self):
        _, observations = self.observe([health(REQUEST), health("2026-10-24T05:40:11.160997210Z")])
        self.assertEqual(len(observations), 2)

    def test_unhealthy_and_invalid_timestamp_do_not_pass(self):
        _, observations = self.observe([health(status="down"), health("invalid"), health()])
        self.assertEqual(len(observations), 3)
        self.assertIn("timestamp_error", observations[1])


if __name__ == "__main__":
    unittest.main()
