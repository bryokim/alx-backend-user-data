#!/usr/bin/env python3
"""
Route module for the API
"""
from os import getenv

from flask import Flask, abort, jsonify, request
from flask_cors import CORS

from api.v1.views import app_views

app = Flask(__name__)
app.register_blueprint(app_views)
CORS(app, resources={r"/api/v1/*": {"origins": "*"}})

auth = None
AUTH_TYPE = getenv("AUTH_TYPE", None)

if AUTH_TYPE == "auth":
    from .auth.auth import Auth

    auth = Auth()
elif AUTH_TYPE == "basic_auth":
    from .auth.basic_auth import BasicAuth

    auth = BasicAuth()
elif AUTH_TYPE == "session_auth":
    from .auth.session_auth import SessionAuth

    auth = SessionAuth()
elif AUTH_TYPE == "session_exp_auth":
    from .auth.session_exp_auth import SessionExpAuth

    auth = SessionExpAuth()
elif AUTH_TYPE == "session_db_auth":
    from .auth.session_db_auth import SessionDBAuth

    auth = SessionDBAuth()


@app.before_request
def check_authentication():
    """Check if authentication credentials are valid."""
    excluded_paths = [
        "/api/v1/status/",
        "/api/v1/unauthorized/",
        "/api/v1/forbidden/",
        "/api/v1/auth_session/login/",
    ]
    if auth and auth.require_auth(request.path, excluded_paths):
        if (
            auth.authorization_header(request=request) is None
            and auth.session_cookie(request) is None
        ):  # If Authorization is not provided and the user is not in a session
            abort(401)

        request.current_user = auth.current_user(request=request)

        if request.current_user is None:
            abort(403)


@app.errorhandler(404)
def not_found(error) -> str:
    """Not found handler"""
    return jsonify({"error": "Not found"}), 404


@app.errorhandler(401)
def not_authorized(error) -> str:
    """Not authorized handler"""
    return jsonify({"error": "Unauthorized"}), 401


@app.errorhandler(403)
def forbidden(error) -> str:
    """Forbidden handler"""
    return jsonify({"error": "Forbidden"}), 403


if __name__ == "__main__":
    host = getenv("API_HOST", "0.0.0.0")
    port = getenv("API_PORT", "5000")
    app.run(host=host, port=port, debug=True)
