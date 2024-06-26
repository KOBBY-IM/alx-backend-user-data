#!/usr/bin/env python3
""" App module"""

from flask import Flask, jsonify, request, abort, make_response, redirect
from auth import Auth


app = Flask(__name__)
AUTH = Auth()


@app.route("/", methods=["GET"], strict_slashes=False)
def index() -> str:
    """ GET /
    Return:
      - a welcome message
    """
    return jsonify({"message": "Bienvenue"})


@app.route("/users", methods=["POST"], strict_slashes=False)
def register_user() -> str:
    try:
        email = request.form["email"]
        password = request.form["password"]

        AUTH.register_user(email, password)
        return jsonify({"email": email, "message": "user created"}), 200
    except ValueError:
        return jsonify({"message": "email already registered"}), 400


@app.route("/sessions", methods=["POST"], strict_slashes=False)
def login() -> str:
    email = request.form.get("email")
    password = request.form.get("password")

    try:
        user = AUTH.login(email, password)
        if user:
            session_id = user.session_id
            if session_id:
                response = make_response(jsonify(
                    {"email": email, "message": "logged in"}), 200)
                response.set_cookie("session_id", value=session_id)
                return response
            else:
                # Handle case where user has no session ID
                abort(500)
        else:
            abort(401)
    except ValueError:
        abort(401)


@app.route("/sessions", methods=["DELETE"], strict_slashes=False)
def logout() -> str:
    session_id = request.cookies.get("session_id")

    try:
        user = AUTH.get_user_by_session_id(session_id)
        if user:
            AUTH.destroy_session(session_id)
            response = make_response(redirect("/"))
            response.delete_cookie("session_id")
            return response
        else:
            abort(403)
    except ValueError:
        abort(403)


@app.route("/profile", methods=["GET"], strict_slashes=False)
def profile() -> str:
    session_id = request.cookies.get("session_id")

    try:
        user = AUTH.get_user_by_session_id(session_id)
        if user:
            return jsonify({"email": user["email"]}), 200
        else:
            abort(403)
    except ValueError:
        abort(403)


@app.route("/reset_password", methods=["POST"], strict_slashes=False)
def get_reset_password_token() -> str:
    email = request.form.get("email")

    try:
        user = AUTH.get_user_by_email(email)
        if user:
            reset_token = AUTH.generate_reset_token(email)
            return jsonify({"email": email, "reset_token": reset_token}), 200
        else:
            abort(403)
    except ValueError:
        abort(403)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
