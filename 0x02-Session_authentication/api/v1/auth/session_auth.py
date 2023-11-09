#!/usr/bin/env python3
"""SessionAuth module"""

from uuid import uuid4

from .auth import Auth
from models.user import User


class SessionAuth(Auth):
    """SessionAuth class"""

    user_id_by_session_id = {}

    def create_session(self, user_id: str = None) -> str:
        """Creates a session id for a user_id.

        Args:
            user_id (str, optional): Id of the user. Defaults to None.

        Returns:
            str: The session id created.
        """
        if user_id is None:
            return None

        if not isinstance(user_id, str):
            return None

        session_id = str(uuid4())
        self.user_id_by_session_id[session_id] = user_id

        return session_id

    def user_id_for_session_id(self, session_id: str = None) -> str:
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

        return self.user_id_by_session_id.get(session_id)

    def current_user(self, request=None):
        """Returns User instance based on a cookie value.

        Args:
            request (flask.request, optional): A flask request.
                Defaults to None.

        Returns:
            User: A user instance,
        """
        session_id = self.session_cookie(request)
        user_id = self.user_id_for_session_id(session_id)

        return User.get(user_id)

    def destroy_session(self, request=None):
        """Destroy a session.

        Args:
            request (flask.request, optional): Flask request. Defaults to None.

        Returns:
            Bool: True if a session was found ad deleted, else False.
        """
        if request is None:
            return False

        session_id = self.session_cookie(request)
        if session_id is None:
            return False

        user_id = self.user_id_for_session_id(session_id)
        if user_id is None:
            return False

        del self.user_id_by_session_id[session_id]

        return True
