#!/usr/bin/env python3
"""Auth module
"""
import bcrypt
from db import DB
from user import User
from uuid import uuid4
from typing import ByteString

from sqlalchemy.orm.exc import NoResultFound


def _hash_password(password: str) -> bytes:
    """Hash a password

    Returns:
        Hashed password as bytes
    """
    salt: bytes = bcrypt.gensalt()
    hashed_pw: bytes = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_pw


def _generate_uuid() -> str:
    """Generate uuid
    """
    UUID = str(uuid4())
    return UUID


class Auth:
    """Auth class
    """
    def __init__(self):
        """Initialize a new Auth instance
        """
        self._db = DB()

    def _hash_password(self, password: str) -> bytes:
        """Hash a password

        Returns:
            Hashed password as bytes
        """
        salt: bytes = bcrypt.gensalt()
        hashed_pw: bytes = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed_pw

    def register_user(self, email: str, password: str) -> User:
        """Register a new user
        """
        try:
            self._db.find_user_by(email=email)
            raise ValueError('User {} already exists'.format(email))
        except NoResultFound:
            hashed_pw = self._hash_password(password)
            user = self._db.add_user(email, hashed_pw)
            return user

    def login(self, email: str, password: str) -> User:
        """Login a user
        """
        try:
            user = self._db.find_user_by(email=email)
            if bcrypt.checkpw(password.encode('utf-8'), user.hashed_password):
                return user
            else:
                raise ValueError('Incorrect password')
        except NoResultFound:
            raise ValueError('User {} not found'.format(email))

    def create_session(self, email: str) -> str:
        """Creates new session"""
        try:
            user = self._db.find_user_by(email=email)
            session_id = _generate_uuid()
            self._db.update_user(user.id, session_id=session_id)
            return session_id
        except NoResultFound:
            return None

    def get_user_from_session_id(self, session_id: str) -> str:
        """gets user from session id"""
        if not session_id:
            return None
        try:
            return self._db.find_user_by(session_id=session_id)
        except NoResultFound:
            return None

    def destroy_session(self, user_id: int) -> None:
        """destroys the current session"""
        try:
            self._db.update_user(user_id, session_id=None)
        except NoResultFound:
            return None

    def get_reset_password_token(self, email: str) -> str:
        """generates a password reset token using uuid"""
        try:
            user = self._db.find_user_by(email=email)
            password_token = _generate_uuid()
            self._db.update_user(user.id, reset_token=password_token)
            return password_token
        except NoResultFound:
            raise ValueError

    def update_password(self, reset_token: str, password: str) -> None:
        """checks the reset token with the database then
        sets the new password"""
        try:
            user = self._db.find_user_by(reset_token=reset_token)
            NPwd = _hash_password(password)
            self._db.update_user(user.id, hashed_password=NPwd,
                                 reset_token=None)
        except NoResultFound:
            raise ValueError
