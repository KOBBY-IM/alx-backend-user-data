#!/usr/bin/env python3
""" Auth class"""

from flask import request
from typing import List, TypeVar


class Auth:
    """ auth class"""
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """ require auth
        """
        if excluded_paths is None or excluded_paths == []:
            return True
        for excluded_path in excluded_paths:
            if excluded_path[-1] != '/':
                excluded_path += '/'
        if path is None:
            return True
        if path[-1] != '/':
            path += '/'
        if path not in excluded_paths:
            return True
        return False

    def authorization_header(self, request= None) -> str:
        """ authorization header"""
        if request is None or 'Authorization' not in request.headers:
            return None
        else:
            return request.headers.get('Authorization')

    def current_user(self, request= None) -> TypeVar('User'):
        """ current user"""
        return None