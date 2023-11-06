#!/usr/bin/env python3
"""BasicAuth module"""

from base64 import urlsafe_b64decode
from typing import TypeVar

from models.user import User

from .auth import Auth


class BasicAuth(Auth):
    """BasicAuth class"""

    def extract_base64_authorization_header(
        self, authorization_header: str
    ) -> str:
        """Extract the base64 encoding of the authorization.

        Args:
            authorization_header (str): Value of the authorization header.

        Returns:
            str: The base64 encoded str after Basic.
                Returns None if the authorization_header is invalid.
        """
        if (
            authorization_header is None
            or not isinstance(authorization_header, str)
            or not authorization_header.startswith("Basic ")
        ):
            return None

        return authorization_header[6:]

    def decode_base64_authorization_header(
        self, base64_authorization_header: str
    ) -> str:
        """Decode base64 value of the basic authorization.

        Args:
            base64_authorization_header (str): String to decode.
        Returns:
            str: Decoded string in utf-8 encoding.
                Returns none if given string is invalid.
        """
        if base64_authorization_header is None:
            return None

        if not isinstance(base64_authorization_header, str):
            return None

        try:
            value = urlsafe_b64decode(base64_authorization_header)
            return value.decode("utf-8")
        except Exception:
            return None

    def extract_user_credentials(
        self, decoded_base64_authorization_header: str
    ) -> (str, str):
        """Extract user email and password from the decoded base64 string.

        Args:
            decoded_base64_authorization_header (str): Decoded base64 string.

        Returns:
            (str, str): Tuple of email and password. If the provided decoded base64
                string is invalid, (None, None) is returned.
        """
        if decoded_base64_authorization_header is None:
            return None, None

        if not isinstance(decoded_base64_authorization_header, str):
            return None, None

        if ":" not in decoded_base64_authorization_header:
            return None, None

        email, password = decoded_base64_authorization_header.split(":", 1)

        return email, password

    def user_object_from_credentials(
        self, user_email: str, user_pwd: str
    ) -> TypeVar("User"):
        """Get the user object from the database.

        Args:
            user_email (str): Email of the user.
            user_pwd (str): password of the user.

        Returns:
            User: User object representing he current user.
        """
        if not user_email or not isinstance(user_email, str):
            return None

        if not user_pwd or not isinstance(user_pwd, str):
            return None

        try:
            users = User.search({"email": user_email})
        except KeyError:  # If there are no users loaded into DATA
            return None

        if len(users) == 0:
            return None

        user = users[0]

        if not user.is_valid_password(user_pwd):
            return None

        return user

    def current_user(self, request=None) -> TypeVar("User"):
        """Get the current user from the database.

        Args:
            request(Flask.request): Flask request.

        Returns:
            User: user with the given credentials.
        """
        authorization_header = self.authorization_header(request)
        credentials_base64 = self.extract_base64_authorization_header(
            authorization_header
        )
        credentials_utf8 = self.decode_base64_authorization_header(
            credentials_base64
        )
        user_email, user_pwd = self.extract_user_credentials(credentials_utf8)
        user = self.user_object_from_credentials(user_email, user_pwd)

        return user
