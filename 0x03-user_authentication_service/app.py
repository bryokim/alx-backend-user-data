#!/usr/bin/env python3
"""flask app module"""

from flask import Flask, Response
from flask import abort, jsonify, redirect, request, url_for

from auth import Auth

app = Flask(__name__)

AUTH = Auth()


@app.route("/", methods=["GET"])
def home() -> Response:
    """Home route"""
    return jsonify({"message": "Bienvenue"})


@app.route("/users", methods=["POST"])
def users() -> Response:
    """Create a new user if they aren't registered yet.

    Returns:
        Response: A json response.
    """
    email = request.form.get("email")
    password = request.form.get("password")

    try:
        AUTH.register_user(email, password)
    except ValueError:
        return jsonify({"message": "email already registered"}), 400

    return jsonify({"email": email, "message": "user created"})


@app.route("/sessions", methods=["POST"])
def login() -> Response:
    """Login a user.

    Returns:
        Response: A json response.
    """
    email = request.form.get("email")
    password = request.form.get("password")

    if AUTH.valid_login(email, password) is False:
        abort(401)

    session_id = AUTH.create_session(email)

    response = jsonify({"email": email, "message": "logged in"})
    response.set_cookie("session_id", session_id)

    return response


@app.route("/sessions", methods=["DELETE"])
def logout() -> Response:
    """Logout a logged in user.

    Returns:
        Response: redirect to / or abort with 403 HTTP status.
    """
    session_id = request.cookies.get("session_id")

    user = AUTH.get_user_from_session_id(session_id)

    if user is None:
        abort(403)

    AUTH.destroy_session(user.id)

    return redirect(url_for("home"), code=303)


@app.route("/profile")
def profile() -> Response:
    """Get user profile.

    Returns:
        Response: User email as json, else abort with 403 HTTP status.
    """
    session_id = request.cookies.get("session_id")

    user = AUTH.get_user_from_session_id(session_id)

    if user is None:
        abort(403)

    return jsonify({"email": user.email})


@app.route("/reset_password", methods=["POST"])
def get_reset_password_token() -> Response:
    """Get password reset token.

    Returns:
        Response: A json response.
    """
    email = request.form.get("email")

    try:
        reset_token = AUTH.get_reset_password_token(email)
    except ValueError:
        abort(403)

    return jsonify({"email": email, "reset_token": reset_token})


@app.route("/reset_password", methods=["PUT"])
def update_password() -> Response:
    """Update a user's password.

    Returns:
        Response: A json response.
    """
    email = request.form.get("email")
    reset_token = request.form.get("reset_token", "")
    new_password = request.form.get("new_password")

    try:
        AUTH.update_password(reset_token, new_password)
    except ValueError:
        abort(403)

    return jsonify({"email": email, "message": "Password updated"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
