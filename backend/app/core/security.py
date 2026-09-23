import hashlib
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID

import bcrypt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from psycopg.types.json import Jsonb

from .config import get_settings
from .database import get_sync_connection

settings = get_settings()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")


# ── Password hashing ──────────────────────────────────────────────────────────
def hash_password(plain: str) -> str:
    pwd_bytes = plain.encode('utf-8')
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(pwd_bytes, salt).decode('utf-8')


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode('utf-8'), hashed.encode('utf-8'))
    except Exception:
        return False


# ── Session Fingerprinting (Anti-Token-Theft / Replay Defense) ────────────────
def compute_client_fingerprint(user_agent: str, client_ip: str) -> str:
    """Computes a cryptographically salted fingerprint of the client session.
    Tolerates minor dynamic IP shifts (matches /24 subnet) while binding to the User-Agent.
    """
    ua_clean = (user_agent or "unknown").strip().lower()
    ip_parts = client_ip.split(".") if "." in client_ip else client_ip.split(":")
    ip_prefix = ".".join(ip_parts[:3]) if len(ip_parts) >= 3 and "." in client_ip else client_ip
    raw = f"{settings.jwt_secret}:{ua_clean}:{ip_prefix}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


# ── JWT ───────────────────────────────────────────────────────────────────────
def create_access_token(data: dict[str, Any], fingerprint: str | None = None) -> str:
    payload = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(
        minutes=settings.jwt_expire_minutes
    )
    payload.update({"exp": expire, "type": "access"})
    if fingerprint:
        payload["fgp"] = fingerprint
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def create_refresh_token(data: dict[str, Any]) -> str:
    payload = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(
        days=settings.jwt_refresh_expire_days
    )
    payload.update({"exp": expire, "type": "refresh"})
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def decode_token(token: str) -> dict[str, Any]:
    try:
        return jwt.decode(
            token,
            settings.jwt_secret,
            algorithms=[settings.jwt_algorithm],
        )
    except JWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


# ── Current user dependency ───────────────────────────────────────────────────
def get_current_user(request: Request, token: str = Depends(oauth2_scheme)) -> dict[str, Any]:
    payload = decode_token(token)

    # Session Fingerprint Verification (Anti-Replay / Stolen Token Defense)
    expected_fgp = payload.get("fgp")
    if expected_fgp:
        forwarded = request.headers.get("x-forwarded-for")
        client_ip = forwarded.split(",")[0].strip() if forwarded else (request.client.host if request.client else "127.0.0.1")
        user_agent = request.headers.get("user-agent", "")
        actual_fgp = compute_client_fingerprint(user_agent, client_ip)
        if expected_fgp != actual_fgp:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Security Violation: Session fingerprint mismatch. Replay / Stolen token detected.",
                headers={"WWW-Authenticate": "Bearer"},
            )

    user_id: str | None = payload.get("sub")
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token missing subject claim",
        )

    with get_sync_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, email, full_name, role, is_active
                FROM users
                WHERE id = %s
                """,
                (user_id,),
            )
            user = cur.fetchone()

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )

    if not user["is_active"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is disabled",
        )

    return user


# ── Role-based access helpers ─────────────────────────────────────────────────
def require_role(*roles: str):
    def _check(current_user: dict = Depends(get_current_user)):
        if current_user["role"] not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{current_user['role']}' is not authorized for this action",
            )
        return current_user

    return _check


# ── Audit log helper ──────────────────────────────────────────────────────────
def write_audit_log(
    *,
    actor_id: UUID | str | None,
    actor: str | None,
    action: str,
    resource: str | None = None,
    resource_id: str | None = None,
    details: dict | None = None,
    source_ip: str | None = None,
) -> None:
    inserted_log = None
    with get_sync_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO audit_logs
                    (actor_id, actor, action, resource, resource_id, details, source_ip)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                RETURNING id, actor_id, actor, action, resource, resource_id, details, source_ip, created_at
                """,
                (
                    str(actor_id) if actor_id else None,
                    actor,
                    action,
                    resource,
                    resource_id,
                    Jsonb(details) if details is not None else None,
                    source_ip,
                ),
            )
            inserted_log = cur.fetchone()
            conn.commit()

    if inserted_log:
        try:
            from ..services.redis_pubsub import publish_audit_log
            publish_audit_log(dict(inserted_log))
        except Exception:
            pass
