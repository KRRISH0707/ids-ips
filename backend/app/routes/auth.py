import logging
import time
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel

from ..core.database import get_sync_connection
from ..core.metrics import auth_attempts_total
from ..core.security import (
    compute_client_fingerprint,
    create_access_token,
    create_refresh_token,
    decode_token,
    get_current_user,
    verify_password,
    write_audit_log,
)

logger = logging.getLogger("ids.auth")
router = APIRouter(prefix="/auth", tags=["auth"])

# In-memory fallback if Redis is unreachable: key -> (count, expire_timestamp)
_mem_fail_tracker: dict[str, tuple[int, float]] = {}


def _check_account_lockout(username: str) -> bool:
    try:
        from ..core.redis_client import get_sync_redis
        r = get_sync_redis()
        return bool(r.exists(f"auth:lockout:{username}"))
    except Exception:
        now = time.time()
        val = _mem_fail_tracker.get(f"auth:lockout:{username}")
        return bool(val and val[1] > now)


def _record_failed_attempt(key: str, ttl: int = 300) -> int:
    try:
        from ..core.redis_client import get_sync_redis
        r = get_sync_redis()
        pipe = r.pipeline()
        pipe.incr(key)
        pipe.expire(key, ttl)
        res = pipe.execute()
        return int(res[0])
    except Exception:
        now = time.time()
        count, exp = _mem_fail_tracker.get(key, (0, now + ttl))
        if now > exp:
            count = 0
            exp = now + ttl
        count += 1
        _mem_fail_tracker[key] = (count, exp)
        return count


def _set_account_lockout(username: str, ttl: int = 900) -> None:
    try:
        from ..core.redis_client import get_sync_redis
        r = get_sync_redis()
        r.setex(f"auth:lockout:{username}", ttl, "1")
    except Exception:
        _mem_fail_tracker[f"auth:lockout:{username}"] = (1, time.time() + ttl)


def _clear_failed_attempts(source_ip: str, username: str) -> None:
    try:
        from ..core.redis_client import get_sync_redis
        r = get_sync_redis()
        r.delete(f"auth:fail:ip:{source_ip}", f"auth:fail:user:{username}")
    except Exception:
        _mem_fail_tracker.pop(f"auth:fail:ip:{source_ip}", None)
        _mem_fail_tracker.pop(f"auth:fail:user:{username}", None)


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
    """Authenticate with email + password, receive JWT tokens with session fingerprinting."""
    forwarded = request.headers.get("x-forwarded-for")
    source_ip = forwarded.split(",")[0].strip() if forwarded else (request.client.host if request.client else "127.0.0.1")

    clean_username = form_data.username.strip().lower()
    clean_password = form_data.password.strip()

    # 1. Distributed Account Lockout Guard
    if _check_account_lockout(clean_username):
        logger.warning("Account %s is locked due to multiple failed login attempts", clean_username)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Account is temporarily locked due to excessive authentication failures. Please try again in 15 minutes.",
        )

    # 2. Database User Lookup
    with get_sync_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, email, full_name, role, hashed_password, is_active
                FROM users
                WHERE LOWER(email) = %s
                """,
                (clean_username,),
            )
            user = cur.fetchone()

    # 3. Credential Verification & Brute-Force Jail
    if user is None or not verify_password(clean_password, user["hashed_password"]):
        auth_attempts_total.labels(result="failure").inc()
        write_audit_log(
            actor_id=None,
            actor=form_data.username,
            action="LOGIN_FAILED",
            details={"reason": "invalid credentials"},
            source_ip=source_ip,
        )

        ip_fail_count = _record_failed_attempt(f"auth:fail:ip:{source_ip}", ttl=300)
        user_fail_count = _record_failed_attempt(f"auth:fail:user:{clean_username}", ttl=300)

        # Trigger Autonomous IPS Quarantine if 5 attempts failed from this IP
        if ip_fail_count >= 5:
            try:
                from ..core.ips_middleware import _execute_autonomous_block
                _execute_autonomous_block(
                    src_ip=source_ip,
                    signature="Credential: Authentication Brute Force Attack",
                    category="credential",
                    severity="CRITICAL",
                    risk_score=95,
                    raw_event={
                        "endpoint": "/api/v1/auth/login",
                        "username": clean_username,
                        "failed_attempts": ip_fail_count,
                        "source_ip": source_ip,
                    },
                    reason=f"Autonomous IPS: Brute Force Ingress Threshold Exceeded ({ip_fail_count} failed logins)",
                )
            except Exception as exc:
                logger.error("Failed to trigger autonomous block for brute force IP %s: %s", source_ip, exc)

            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Apex Sentinel Autonomous IPS: Maximum authentication attempts exceeded. IP {source_ip} quarantined.",
            )

        # Trigger Account Lockout if 5 attempts failed on this account across any IPs
        if user_fail_count >= 5:
            _set_account_lockout(clean_username, ttl=900)
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Account locked due to multiple failed login attempts. Try again in 15 minutes.",
            )

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid email or password. Attempt {ip_fail_count} of 5 before IP quarantine.",
        )

    if not user["is_active"]:
        auth_attempts_total.labels(result="failure").inc()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is disabled",
        )

    # 4. Success: Clear fail counters and issue cryptographically bound token
    _clear_failed_attempts(source_ip, clean_username)
    client_fingerprint = compute_client_fingerprint(request.headers.get("user-agent", ""), source_ip)

    token_data = {"sub": str(user["id"]), "role": user["role"]}
    access_token = create_access_token(token_data, fingerprint=client_fingerprint)
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
        details={"email": user["email"], "role": user["role"], "auth_type": "password"},
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
def refresh_token(
    request: Request,
    body: RefreshRequest,
    current_user: dict = Depends(get_current_user),
):
    """Exchange a refresh token for a new access token bound to client fingerprint."""
    forwarded = request.headers.get("x-forwarded-for")
    source_ip = forwarded.split(",")[0].strip() if forwarded else (request.client.host if request.client else "127.0.0.1")
    client_fingerprint = compute_client_fingerprint(request.headers.get("user-agent", ""), source_ip)

    payload = decode_token(body.refresh_token)
    if payload.get("type") != "refresh":
        raise HTTPException(status_code=400, detail="Not a refresh token")

    token_data = {"sub": payload["sub"], "role": payload["role"]}
    return {
        "access_token": create_access_token(token_data, fingerprint=client_fingerprint),
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
