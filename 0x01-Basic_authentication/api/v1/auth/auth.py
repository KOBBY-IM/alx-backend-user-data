#!/usr/bin/env python3
""" Auth class"""

from flask import request
from typing import List, TypeVar


class Auth:
    """ auth class"""
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """Require authentication for a given path, except for excluded paths.
        """
        if not excluded_paths:
            return True

        for excluded_path in excluded_paths:
            if excluded_path.endswith('*'):
                if path.startswith(excluded_path[:-1]):
                    return False
            elif path == excluded_path:
                return False

        return True

    def authorization_header(self, request=None) -> str:
        """ authorization header"""
        if request is None:
            return None
        if request.headers.get('Authorization') is None:
            return None
        return request.headers.get('Authorization')
    def current_user(self, request=None) -> TypeVar('User'):
        """ current user"""
        return None
