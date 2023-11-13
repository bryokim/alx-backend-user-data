#!/usr/bin/env python3
"""auth module"""

import bcrypt

from sqlalchemy.orm.exc import NoResultFound
from uuid import uuid4
from typing import Optional

# Local
from db import DB
from user import User


def _hash_password(password: str) -> bytes:
    """Hash a password using bcrypt.

    Args:
        password (str): Password to hash.

    Returns:
        bytes: Hashed password.
    """
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())


def _generate_uuid() -> str:
    """Generate a new UUID and return its string representation.
    Uses uuid4.

    Returns:
        str: UUID generated as a string.
    """
    return str(uuid4())


class Auth:
    """Auth class to interact with the authentication database."""

    def __init__(self):
        """Initialize a new Auth instance"""
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """Create a new user if they don't exist.

        Args:
            email (str): The user's email.
            password (str): The user's password.

        Raises:
            ValueError: If a user with the given email already exists.

        Returns:
            User: The newly created user.
        """
        try:
            if self._db.find_user_by(email=email):
                raise ValueError(f"User {email} already exists")
        except NoResultFound:
            pass

        hashed_password = _hash_password(password)

        return self._db.add_user(email, hashed_password)

    def valid_login(self, email: str, password: str) -> bool:
        """Validate a login.

        Args:
            email (str): The user's email.
            password (str): The user's password.

        Returns:
            bool: True if the user exists and password is valid, else False.
        """
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            return False

        return bcrypt.checkpw(password.encode(), user.hashed_password)

    def create_session(self, email: str) -> str:
        """Get session id.

        Args:
            email (str): The user's email.

        Returns:
            str: The user's session id.
        """
        try:
            user = self._db.find_user_by(email=email)
            session_id = _generate_uuid()
            self._db.update_user(user.id, session_id=session_id)
        except NoResultFound:
            return None

        return session_id

    def get_user_from_session_id(self, session_id: str) -> Optional[User]:
        """Get a user from the provided session id.

        Args:
            session_id (str): The user's session id.

        Returns:
            Optional[User]: user with the given session id or None if not found
        """
        if session_id is None:
            return None

        try:
            user = self._db.find_user_by(session_id=session_id)
        except NoResultFound:
            return None

        return user

    def destroy_session(self, user_id: int) -> None:
        """Destroy user session by setting session id to None.

        Args:
            user_id (int): The user's id
        """
        return self._db.update_user(user_id, session_id=None)

    def get_reset_password_token(self, email: str) -> str:
        """Generate a reset token and save it in db.

        Args:
            email (str): The user's email.

        Raises:
            ValueError: If no user is found with given email.
        Returns:
            str: The reset token.
        """
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            raise ValueError

        reset_token = _generate_uuid()

        self._db.update_user(user.id, reset_token=reset_token)

        return reset_token

    def update_password(self, reset_token: str, password: str) -> None:
        """Update a user's password.

        Args:
            reset_token (str): The reset token of the user.
            password (str): The new password.

        Raises:
            ValueError: If no user is found with the given reset_token
        """
        try:
            user = self._db.find_user_by(reset_token=reset_token)
        except NoResultFound:
            raise ValueError

        hashed_password = _hash_password(password)

        self._db.update_user(
            user.id, hashed_password=hashed_password, reset_token=None
        )
