#!/usr/bin/env python3
"""SessionExpAuth module"""

from datetime import datetime, timedelta
from os import getenv

from .session_auth import SessionAuth


class SessionExpAuth(SessionAuth):
    """SessionExpAuth class"""

    def __init__(self):
        """Initialize a new SessionExpAuth instance"""
        try:
            self.session_duration = int(getenv("SESSION_DURATION"))
        except ValueError:
            self.session_duration = 0

    def create_session(self, user_id=None):
        """Create a user session.

        Args:
            user_id (str, optional): The user id. Defaults to None.

        Returns:
            str: The session id.
        """
        session_id = super().create_session(user_id)

        if session_id is None:
            return None

        self.user_id_by_session_id[session_id] = {
            "user_id": user_id,
            "created_at": datetime.now(),
        }

        return session_id

    def user_id_for_session_id(self, session_id=None):
        """Retrieve user id based on session id.

        Args:
            session_id (str, optional): Current session id. Defaults to None.

        Returns:
            str: The user id corresponding to the session.
        """
        if session_id is None:
            return None

        if not isinstance(session_id, str):
            return None

        session_dictionary = self.user_id_by_session_id.get(session_id)

        if session_dictionary is None:
            return None

        if self.session_duration <= 0:
            return session_dictionary.get("user_id")

        if session_dictionary.get("created_at") is None:
            return None

        if (
            session_dictionary.get("created_at")
            + timedelta(seconds=self.session_duration)
            < datetime.now()
        ):
            return None

        return session_dictionary.get("user_id")
