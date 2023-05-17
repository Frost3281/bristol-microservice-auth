import secrets

from fastapi import Depends, HTTPException
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from starlette import status

security = HTTPBasic()


def check_user(
    credentials: HTTPBasicCredentials = Depends(security),
    *,
    correct_user: str,
    correct_pwd: str,
) -> str:
    """Авторизация."""
    is_username_correct = secrets.compare_digest(
        credentials.username, correct_user,
    )
    is_password_correct = secrets.compare_digest(
        credentials.password, correct_pwd,
    )
    if not all([is_username_correct, is_password_correct]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Incorrect user or password',
            headers={'WWW-Authenticate': 'Basic'},
        )
    return credentials.username
