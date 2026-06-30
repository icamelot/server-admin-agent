"""Rate limiter — caps modifying commands per hour to prevent cascade failures."""

import time


class RateLimiter:
    """Limits the number of modifying commands within a rolling 1-hour window.

    When the limit is exceeded, the limiter locks until manually reset
    or the window rolls over.
    """

    def __init__(self, max_per_hour: int = 10):
        self._max_per_hour = max_per_hour
        self._count: int = 0
        self._window_start: float = time.monotonic()
        self._locked: bool = False

    def _maybe_roll_window(self) -> None:
        """Reset the window if an hour has elapsed."""
        now = time.monotonic()
        if now - self._window_start >= 3600:
            self._window_start = now
            self._count = 0
            self._locked = False

    def check_and_increment(self) -> bool:
        """Check if within limit, increment count if so.

        Returns True if the operation is allowed, False if limit exceeded.
        """
        self._maybe_roll_window()

        if self._locked:
            return False

        if self._count >= self._max_per_hour:
            self._locked = True
            return False

        self._count += 1
        if self._count >= self._max_per_hour:
            self._locked = True
        return True

    def get_remaining(self) -> int:
        """Return how many more modifying commands are allowed this hour."""
        self._maybe_roll_window()
        return max(0, self._max_per_hour - self._count)

    def is_locked(self) -> bool:
        """Return True if the limiter is currently locked."""
        self._maybe_roll_window()
        return self._locked

    def reset(self) -> None:
        """Manual reset — unlock and clear the counter."""
        self._window_start = time.monotonic()
        self._count = 0
        self._locked = False
