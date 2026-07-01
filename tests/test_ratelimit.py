import unittest
from unittest.mock import patch

from backend.ratelimit import RateLimiter


class RateLimiterTest(unittest.TestCase):
    def test_locks_after_max_attempts(self):
        limiter = RateLimiter(max_attempts=3, window_seconds=300)
        self.assertFalse(limiter.is_locked("1.2.3.4"))
        for _ in range(3):
            limiter.record_failure("1.2.3.4")
        self.assertTrue(limiter.is_locked("1.2.3.4"))

    def test_reset_clears_lock(self):
        limiter = RateLimiter(max_attempts=2, window_seconds=300)
        limiter.record_failure("1.2.3.4")
        limiter.record_failure("1.2.3.4")
        self.assertTrue(limiter.is_locked("1.2.3.4"))
        limiter.reset("1.2.3.4")
        self.assertFalse(limiter.is_locked("1.2.3.4"))

    def test_keys_are_isolated(self):
        limiter = RateLimiter(max_attempts=2, window_seconds=300)
        limiter.record_failure("1.1.1.1")
        limiter.record_failure("1.1.1.1")
        self.assertTrue(limiter.is_locked("1.1.1.1"))
        self.assertFalse(limiter.is_locked("2.2.2.2"))

    def test_old_attempts_expire_out_of_window(self):
        limiter = RateLimiter(max_attempts=2, window_seconds=300)
        with patch("backend.ratelimit.time.time", return_value=1000.0):
            limiter.record_failure("1.2.3.4")
            limiter.record_failure("1.2.3.4")
            self.assertTrue(limiter.is_locked("1.2.3.4"))
        # oltre la finestra: i tentativi vecchi escono, chiave sbloccata
        with patch("backend.ratelimit.time.time", return_value=1000.0 + 301):
            self.assertFalse(limiter.is_locked("1.2.3.4"))


if __name__ == "__main__":
    unittest.main()
