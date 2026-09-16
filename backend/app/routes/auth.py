from fastapi import APIRouter, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from fastapi import Depends
from pydantic import BaseModel

from ..core.database import get_sync_connection
from ..core.security import (
    verify_password,
    create_access_token,
    create_refresh_token,
    decode_token,
    get_current_user,
    write_audit_log,
)
from ..core.metrics import auth_attempts_total

router = APIRouter(prefix="/auth", tags=["auth"])


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    user: dict


class RefreshRequest(BaseModel):
    refresh_token: str


@router.post("/login", response_model=TokenResponse)
def login(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
):
    """Authenticate with email + password, receive JWT tokens."""
    source_ip = request.client.host if request.client else None

    with get_sync_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, email, full_name, role, hashed_password, is_active
                FROM users
                WHERE email = %s
                """,
                (form_data.username,),
            )
            user = cur.fetchone()

    if user is None or not verify_password(form_data.password, user["hashed_password"]):
        auth_attempts_total.labels(result="failure").inc()
        write_audit_log(
            actor_id=None,
            actor=form_data.username,
            action="LOGIN_FAILED",
            details={"reason": "invalid credentials"},
            source_ip=source_ip,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    if not user["is_active"]:
        auth_attempts_total.labels(result="failure").inc()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is disabled",
        )

    token_data = {"sub": str(user["id"]), "role": user["role"]}
    access_token = create_access_token(token_data)
    refresh_token = create_refresh_token(token_data)

    # Update last_login
    with get_sync_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE users SET last_login = now() WHERE id = %s",
                (user["id"],),
            )
            conn.commit()

    auth_attempts_total.labels(result="success").inc()
    write_audit_log(
        actor_id=user["id"],
        actor=user["email"],
        action="LOGIN_SUCCESS",
        source_ip=source_ip,
    )

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "user": {
            "id": str(user["id"]),
            "email": user["email"],
            "full_name": user["full_name"],
            "role": user["role"],
        },
    }


@router.post("/refresh", response_model=TokenResponse)
def refresh_token(body: RefreshRequest, current_user: dict = Depends(get_current_user)):
    """Exchange a refresh token for a new access token."""
    payload = decode_token(body.refresh_token)
    if payload.get("type") != "refresh":
        raise HTTPException(status_code=400, detail="Not a refresh token")

    token_data = {"sub": payload["sub"], "role": payload["role"]}
    return {
        "access_token": create_access_token(token_data),
        "refresh_token": create_refresh_token(token_data),
        "token_type": "bearer",
        "user": {
            "id": current_user["id"],
            "email": current_user["email"],
            "full_name": current_user["full_name"],
            "role": current_user["role"],
        },
    }


@router.get("/me")
def me(current_user: dict = Depends(get_current_user)):
    """Return the authenticated user's profile."""
    return {
        "id": str(current_user["id"]),
        "email": current_user["email"],
        "full_name": current_user["full_name"],
        "role": current_user["role"],
    }
