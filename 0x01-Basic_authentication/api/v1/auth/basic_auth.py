#!/usr/bin/env python3
""" basic auth """

from api.v1.auth.auth import Auth
import base64
from typing import TypeVar

class BasicAuth(Auth):
    """ basic auth """
    def extract_base64_authorization_header(self,
                            authorization_header: str) -> str:
        """Extract base64 authorization header
        """
        if authorization_header is None or not isinstance(authorization_header,
                                                          str):
            return None
        
        if not authorization_header.startswith("Basic "):
            return None
        
        # Split the Authorization header and return the Base64 part
        return authorization_header.split(" ")[1]

   
    def decode_base64_authorization_header(self, base64_authorization_header:
                                           str) -> str:
        """Decode base64 authorization header and return decoded string
        """
        if base64_authorization_header is None or not isinstance(
            base64_authorization_header, str):
            return None
        
        try:
            decoded_value = base64.b64decode(base64_authorization_header)
            return decoded_value.decode('utf-8')
        except Exception:
            return None
    
    def extract_user_credentials(self,
                    decoded_base64_authorization_header:str) -> (str, str):
        """Extract user credentials
        """
        if decoded_base64_authorization_header is None or not isinstance(
            decoded_base64_authorization_header, str):
            return None, None
        if ":" not in decoded_base64_authorization_header:
            return None, None
        
        credentials = decoded_base64_authorization_header.split(":", 1)
        return credentials[0], credentials[1]
    
    def user_object_from_credentials(self, user_email: str,
                                     user_pwd: str) -> TypeVar('User'):
        """ user_object_from_credentials
        """
        from models.user import User
        if user_email is None or type(user_email) != str:
            return None
        if user_pwd is None or type(user_pwd) != str:
            return None
        try:
            users = User.search({'email': user_email})
        except Exception:
            return None
        for user in users:
            if user.is_valid_password(user_pwd):
                return user
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """ current_user
        """
        auth_h = self.authorization_header(request)
        base64_auth_h = self.extract_base64_authorization_header(auth_h)
        decoded_base64_auth_h = self.decode_base64_authorization_header(
            base64_auth_h
        )
        if decoded_base64_auth_h is None:
            return None
        user_credential = self.extract_user_credentials(decoded_base64_auth_h)
        if user_credential is None or any(cred is None for cred in
                                          user_credential):
            return None
        user_email, user_pwd = user_creds
        return self.user_object_from_credentials(user_email, user_pwd)