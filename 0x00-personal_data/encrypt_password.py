#!/usr/bin/env python3
"""hash_password module"""

import bcrypt


def hash_password(password: str) -> bytes:
    """Hash a password.

    Args:
        password (str): Password to hash.

    Returns:
        bytes: Hashed password.
    """
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

    return hashed


def is_valid(hashed_password: bytes, password: str) -> bool:
    """Check if a password is valid.

    Args:
        hashed_password (bytes): Hashed password.
        password (str): Password to check

    Returns:
        bool: True if password is valid, else False.
    """
    return bcrypt.checkpw(password.encode(), hashed_password)
