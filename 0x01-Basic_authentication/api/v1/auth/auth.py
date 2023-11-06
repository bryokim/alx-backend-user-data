#!/usr/bin/env python3
"""Auth class module"""


from typing import List, TypeVar


class Auth:
    """Auth class
    Manages API authentication.
    """

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """Checks if a path requires authentication.

        Args:
            path (str): Path to check.
            excluded_paths (List[str]): List of paths that don't require
                authentication. Paths in this list are assumed to be ending
                in a slash(/).

        Returns:
            bool: True if the path is not in the list of strings excluded_paths
                else False.
        """
        if not path or not excluded_paths:
            return True

        # Ensure that path ends with /
        path = path if path.endswith("/") else path + "/"

        for excluded_path in excluded_paths:
            if excluded_path[-1] == "*" and path.startswith(
                excluded_path[0:-1]
            ):
                return False

            if excluded_path == path:
                return False

        return True

    def authorization_header(self, request=None) -> str:
        """Check if the authorization header has been given and return its
        value.

        Args:
            request (Flask.request, optional): Flask request. Defaults to
                None.

        Returns:
            str: Authorization header value if given, else None.
        """
        if request is None or request.headers.get("Authorization") is None:
            return None

        return request.headers.get("Authorization")

    def current_user(self, request=None) -> TypeVar("User"):
        """Get the current user"""
        return None
