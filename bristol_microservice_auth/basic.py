import os
import secrets

from fastapi import Depends, HTTPException
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from starlette import status

security = HTTPBasic()


def check_user(credentials: HTTPBasicCredentials = Depends(security)) -> str:
    """Авторизация."""
    is_username_correct = secrets.compare_digest(
        credentials.username, os.environ['CORRECT_USER'],
    )
    is_password_correct = secrets.compare_digest(
        credentials.password, os.environ['CORRECT_PWD'],
    )
    if not all([is_username_correct, is_password_correct]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Incorrect user or password',
            headers={'WWW-Authenticate': 'Basic'},
        )
    return credentials.username
