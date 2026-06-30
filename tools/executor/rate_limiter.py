"""Rate limiter — caps modifying commands per hour to prevent cascade failures."""

import json
import os
import time


class RateLimiter:
    """Limits the number of modifying commands within a rolling 1-hour window.

    When the limit is exceeded, the limiter locks until manually reset
    or the window rolls over.

    Optional persistence: call set_save_path() to enable automatic state
    saves after every count change. The state file is JSON with keys
    count, window_start, locked.
    """

    def __init__(self, max_per_hour: int = 10):
        self._max_per_hour = max_per_hour
        self._count: int = 0
        self._window_start: float = time.monotonic()
        self._locked: bool = False
        self._save_path: str | None = None

    def set_save_path(self, path: str) -> None:
        """Configure a path for automatic state persistence.

        After calling this, every check_and_increment that changes state
        will automatically call save_state(path).
        """
        self._save_path = path

    def save_state(self, path: str) -> None:
        """Write the current limiter state to a JSON file.

        Persisted keys: count, window_start, locked.
        """
        state = {
            "count": self._count,
            "window_start": self._window_start,
            "locked": self._locked,
        }
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w") as f:
            json.dump(state, f)

    def load_state(self, path: str) -> None:
        """Restore limiter state from a JSON file.

        If the file does not exist, the limiter keeps its defaults.
        """
        if not os.path.exists(path):
            return
        with open(path) as f:
            state = json.load(f)
        self._count = int(state.get("count", 0))
        self._window_start = float(state["window_start"])
        self._locked = bool(state.get("locked", False))

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
        If a save path has been set via set_save_path(), the state is
        automatically persisted after any count change.
        """
        self._maybe_roll_window()

        if self._locked:
            return False

        if self._count >= self._max_per_hour:
            self._locked = True
            if self._save_path:
                self.save_state(self._save_path)
            return False

        self._count += 1
        if self._count >= self._max_per_hour:
            self._locked = True
        if self._save_path:
            self.save_state(self._save_path)
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
