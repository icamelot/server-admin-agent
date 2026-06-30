import pytest
from tools.executor.rate_limiter import RateLimiter


class TestRateLimiter:
    def test_initial_state_not_locked(self):
        limiter = RateLimiter(max_per_hour=10)
        assert limiter.is_locked() is False
        assert limiter.get_remaining() == 10

    def test_check_and_increment_allows_up_to_limit(self):
        limiter = RateLimiter(max_per_hour=5)
        for _ in range(5):
            assert limiter.check_and_increment() is True
        assert limiter.get_remaining() == 0

    def test_exceeded_limit_returns_false(self):
        limiter = RateLimiter(max_per_hour=3)
        for _ in range(3):
            limiter.check_and_increment()
        assert limiter.check_and_increment() is False
        assert limiter.is_locked() is True

    def test_reset_unlocks_and_resets_count(self):
        limiter = RateLimiter(max_per_hour=3)
        for _ in range(3):
            limiter.check_and_increment()
        assert limiter.is_locked() is True

        limiter.reset()
        assert limiter.is_locked() is False
        assert limiter.get_remaining() == 3

    def test_get_remaining_decreases(self):
        limiter = RateLimiter(max_per_hour=5)
        limiter.check_and_increment()
        assert limiter.get_remaining() == 4
        limiter.check_and_increment()
        assert limiter.get_remaining() == 3

    def test_window_expires(self):
        import time

        # Use a very short window for testing
        limiter = RateLimiter(max_per_hour=5)
        # Override the window start to simulate elapsed time
        limiter._window_start = time.monotonic() - 3601  # force expiry

        limiter.check_and_increment()
        assert limiter.get_remaining() == 4  # window should have reset
