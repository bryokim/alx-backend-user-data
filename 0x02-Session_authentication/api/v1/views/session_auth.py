#!/usr/bin/env python3
"""SessionAuth views
"""

from flask import abort, jsonify, request
from os import getenv

from api.v1.views import app_views
from models.user import User


@app_views.route("/auth_session/login", methods=["POST"], strict_slashes=False)
def login():
    """Login and create a user session stored in a cookie"""

    email = request.form.get("email")
    password = request.form.get("password")

    if not email:
        return jsonify({"error": "email missing"}), 400

    if not password:
        return jsonify({"error": "password missing"}), 400

    try:
        user = User.search({"email": email})[0]
    except IndexError:
        return jsonify({"error": "no user found for this email"}), 404

    if not user.is_valid_password(password):
        return jsonify({"error": "wrong password"}), 401

    from api.v1.app import auth

    session_id = auth.create_session(user.id)

    response = jsonify(user.to_json())
    response.set_cookie(getenv("SESSION_NAME"), session_id)

    return response


@app_views.route(
    "/auth_session/logout", methods=["DELETE"], strict_slashes=False
)
def logout():
    """Logout of a session. Deletes the session id"""

    from api.v1.app import auth

    if auth.destroy_session(request):
        return {}, 200

    abort(404)
