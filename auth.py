"""
https://accounts.google.com/.well-known/openid-configuration
"""
import os
from http import HTTPStatus

import requests
from fastapi import Depends, Security
from fastapi.security import OAuth2AuthorizationCodeBearer, SecurityScopes

AUTHORIZATION_URL = os.environ.get(
    "AUTHORIZATION_URL", "https://accounts.google.com/o/oauth2/auth"
)
TOKEN_URL = os.environ.get("TOKEN_URL", "https://oauth2.googleapis.com/token")
JWKS_URI = os.environ.get(
    "JWKS_URI", "https://www.googleapis.com/oauth2/v3/certs"
)
ALGORITHMS = ["RS256"]
USER_INFO_URL = (
    "https://www.googleapis.com/oauth2/v2/userinfo?access_token={access_token}"
)


class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


# Define a Authorization scheme specific to our Auth0 config
auth0_scheme = OAuth2AuthorizationCodeBearer(
    authorizationUrl=AUTHORIZATION_URL,
    tokenUrl=TOKEN_URL,
    scopes={"openid": "openid", "email": "email", "profile": "profile"},
)


async def get_current_user(
    security_scopes: SecurityScopes, token: str = Security(auth0_scheme)
):
    response = requests.get(USER_INFO_URL.format(access_token=token))
    if response.status_code == HTTPStatus.OK:
        return response.json()
