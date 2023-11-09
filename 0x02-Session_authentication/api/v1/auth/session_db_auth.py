#!/usr/bin/env python3
"""SessionDBAuth module"""

from .session_exp_auth import SessionExpAuth
from models.user_session import UserSession


class SessionDBAuth(SessionExpAuth):
    """SessionDBAuth class"""

    def __init__(self):
        """Initialize a new SessionDBAuth instance"""
        super().__init__()
        UserSession.load_from_file()

    def create_session(self, user_id=None):
        """Creates a session id for a user_id.

        Args:
            user_id (str, optional): Id of the user. Defaults to None.

        Returns:
            str: The session id created.
        """
        session_id = super().create_session(user_id)

        if session_id is None:
            return None

        user_session = UserSession(user_id=user_id, session_id=session_id)
        user_session.save()

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

        if super().user_id_for_session_id(session_id) is None:
            # Expired session
            return None

        try:
            user_session = UserSession.search({"session_id": session_id})[0]
        except IndexError:
            return None

        return user_session.user_id

    def destroy_session(self, request=None):
        """Destroy a session.

        Args:
            request (flask.request, optional): Flask request. Defaults to None.

        Returns:
            Bool: True if a session was found ad deleted, else False.
        """
        session_destroyed = super().destroy_session(request)

        if not session_destroyed:
            return False

        try:
            user_session = UserSession.search(
                {"session_id": self.session_cookie(request)}
            )[0]
        except IndexError:
            return False

        user_session.remove()

        return True
