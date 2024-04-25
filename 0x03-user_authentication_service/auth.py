#!/usr/bin/env python3
"""Auth module
"""
import bcrypt
from db import DB
from user import User
from auth import Auth
from sqlalchemy.orm.exc import NoResultFound


def _hash_password(password: str) -> bytes:
    """Hash a password

    Returns:
        Hashed password as bytes
    """
    salt: bytes = bcrypt.gensalt()
    hashed_pw: bytes = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_pw


class Auth:
    """Auth class
    """
    def __init__(self):
        """Initialize a new Auth instance
        """
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """Register a new user
        """
        try:
            self._db.find_user_by(email=email)
            raise ValueError('User {} already exists'.format(email))
        except NoResultFound:
            hashed_pw = auth._hash_password(password)
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