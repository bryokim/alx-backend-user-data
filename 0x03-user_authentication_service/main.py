#!/usr/bin/env python3
"""Tests module"""

import requests


BASE_URL = "http://localhost:5000"


def register_user(email: str, password: str) -> None:
    """Test the /users endpoint.

    Args:
        email (str): The user email.
        password (str): The user password.
    """

    url = f"{BASE_URL}/users"
    data = {
        "email": email,
        "password": password,
    }
    res = requests.post(url, data)

    assert res.json() == {"email": email, "message": "user created"}

    # Register an existing user
    res = requests.post(url, data)

    assert res.json() == {"message": "email already registered"}
    assert res.status_code == 400


def log_in_wrong_password(email: str, password: str) -> None:
    """Test the /sessions login with wrong password.

    Args:
        email (str): The user email.
        password (str): The user password.
    """

    url = f"{BASE_URL}/sessions"
    data = {
        "email": email,
        "password": password,
    }

    res = requests.post(url, data)

    assert res.status_code == 401


def profile_unlogged() -> None:
    """Test /profile endpoint while user is not logged in."""

    url = f"{BASE_URL}/profile"

    res = requests.get(url)

    assert res.status_code == 403


def log_in(email: str, password: str) -> str:
    """Test the /sessions login with valid credentials.

    Args:
        email (str): The user's email.
        password (str): The user's password.

    Returns:
        str: The created session id.
    """
    url = f"{BASE_URL}/sessions"
    data = {
        "email": email,
        "password": password,
    }

    res = requests.post(url, data)

    assert res.json() == {"email": email, "message": "logged in"}
    assert res.headers.get("Set-cookie") is not None

    return res.headers.get("Set-cookie").split(";")[0].split("=")[1]


def profile_logged(session_id: str) -> None:
    """Test /profile endpoint with user logged in.

    Args:
        session_id (str): The user's session id.
    """

    url = f"{BASE_URL}/profile"

    res = requests.get(url, cookies={"session_id": session_id})

    assert res.json() == {"email": EMAIL}


def log_out(session_id: str) -> None:
    """Test the /sessions logout.

    Args:
        session_id (str): The session id.
    """

    url = f"{BASE_URL}/sessions"

    res = requests.delete(url, cookies={"session_id": session_id})

    # Redirects to / if the operation is successful
    assert res.url == f"{BASE_URL}/"
    assert res.json() == {"message": "Bienvenue"}

    # After the first logout, the session_id is invalidated.
    # Trying to logout with the same session_id should raise 403 HTTP Error.
    res = requests.delete(url, cookies={"session_id": session_id})

    assert res.status_code == 403

    # Not passing the session_id cookie should also raise 403 HTTP Error.
    res = requests.delete(url)

    assert res.status_code == 403


def reset_password_token(email: str) -> str:
    """Test the POST /reset_password endpoint.

    Args:
        email (str): The user email.

    Returns:
        str: The reset token.
    """

    url = f"{BASE_URL}/reset_password"

    res = requests.post(url, {"email": email})

    assert res.json().get("email") == email
    assert res.json().get("reset_token") is not None

    reset_token = res.json().get("reset_token")

    # Test with invalid email
    res = requests.post(url, {"email": "test@test.com"})

    assert res.status_code == 403

    return reset_token


def update_password(email: str, reset_token: str, new_password: str) -> None:
    """Test PUT /reset_password endpoint.

    Args:
        email (str): The user email.
        reset_token (str): The reset token.
        new_password (str): The new password.
    """

    url = f"{BASE_URL}/reset_password"
    data = {
        "email": email,
        "reset_token": reset_token,
        "new_password": new_password,
    }

    res = requests.put(url, data)

    assert res.json() == {"email": email, "message": "Password updated"}

    # After using a reset_token it's invalidated.
    # Using the same reset_token twice should raise a 403 HTTP Error.
    res = requests.put(url, data)

    assert res.status_code == 403

    # Not passing the reset_token should also raise a 403 HTTP Error
    res = requests.put(url, {"email": email, "new_password": new_password})

    assert res.status_code == 403


EMAIL = "guillaume@holberton.io"
PASSWD = "b4l0u"
NEW_PASSWD = "t4rt1fl3tt3"


if __name__ == "__main__":
    register_user(EMAIL, PASSWD)
    log_in_wrong_password(EMAIL, NEW_PASSWD)
    profile_unlogged()
    session_id = log_in(EMAIL, PASSWD)
    profile_logged(session_id)
    log_out(session_id)
    reset_token = reset_password_token(EMAIL)
    update_password(EMAIL, reset_token, NEW_PASSWD)
    log_in(EMAIL, NEW_PASSWD)
