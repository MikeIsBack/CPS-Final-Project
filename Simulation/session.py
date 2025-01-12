# Session management: handles session timing and logging

import time

class SessionManager:
    def __init__(self, duration):
        self.duration = duration
        self.start_time = None

    def start_session(self):
        """Start a new session."""
        self.start_time = time.time()

    def is_session_active(self):
        """Check if the session is still active."""
        return time.time() - self.start_time < self.duration

    def end_session(self):
        """End the current session."""
        self.start_time = None
