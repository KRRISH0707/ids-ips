from typing import Optional
from uuid import UUID

import psycopg
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, EmailStr, Field

from ..core.database import get_sync_connection
from ..core.security import (
    get_current_user,
    require_role,
    hash_password,
    write_audit_log,
)

router = APIRouter(prefix="/users", tags=["users"])


class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8)
    full_name: Optional[str] = None
    role: str = Field(default="ANALYST", pattern="^(VIEWER|ANALYST|ADMIN)$")


class UserUpdate(BaseModel):
    full_name: Optional[str] = None
    role: Optional[str] = Field(default=None, pattern="^(VIEWER|ANALYST|ADMIN)$")
    is_active: Optional[bool] = None


class PasswordReset(BaseModel):
    password: Optional[str] = Field(default=None, min_length=8)


@router.get("")
def list_users(current_user: dict = Depends(require_role("ADMIN"))):
    """List all registered users along with their provisioned credentials (ADMIN only)."""
    with get_sync_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, email, full_name, role, is_active, last_login, created_at, managed_password, substring(hashed_password from 1 for 22) as hash_preview
                FROM users
                ORDER BY created_at DESC
                """
            )
            users = cur.fetchall()
            for u in users:
                u["credentials"] = {
                    "password": u.get("managed_password") or "••••••••••••",
                    "has_plaintext": bool(u.get("managed_password")),
                    "hash_preview": (u.get("hash_preview") + "...") if u.get("hash_preview") else None,
                    "algorithm": "bcrypt-blowfish-2b (12 rounds)",
                    "status": "Active / Verified" if u.get("is_active") else "Disabled / Revoked"
                }
    return {"items": users, "total": len(users)}


@router.post("", status_code=status.HTTP_201_CREATED)
def create_user(
    body: UserCreate,
    request: Request,
    current_user: dict = Depends(require_role("ADMIN")),
):
    with get_sync_connection() as conn:
        with conn.cursor() as cur:
            try:
                cur.execute(
                    """
                    INSERT INTO users (email, hashed_password, managed_password, full_name, role)
                    VALUES (%s, %s, %s, %s, %s)
                    RETURNING id, email, full_name, role, is_active, created_at, managed_password
                    """,
                    (
                        body.email,
                        hash_password(body.password),
                        body.password,
                        body.full_name,
                        body.role,
                    ),
                )
                user = cur.fetchone()
                user["credentials"] = {
                    "password": body.password,
                    "has_plaintext": True,
                    "algorithm": "bcrypt-blowfish-2b (12 rounds)",
                    "status": "Active / Verified"
                }
                conn.commit()
            except psycopg.errors.UniqueViolation:
                conn.rollback()
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=f"Email '{body.email}' is already registered",
                )

    write_audit_log(
        actor_id=current_user["id"],
        actor=current_user["email"],
        action="USER_CREATED",
        resource="users",
        resource_id=str(user["id"]),
        details={"email": body.email, "role": body.role},
        source_ip=request.client.host if request.client else None,
    )
    return user


@router.post("/{user_id}/reset-password")
def reset_user_password(
    user_id: UUID,
    body: PasswordReset,
    request: Request,
    current_user: dict = Depends(require_role("ADMIN")),
):
    """Rotate or assign a new password to any user (ADMIN only)."""
    import secrets
    import string
    new_password = body.password
    if not new_password:
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
        new_password = "".join(secrets.choice(alphabet) for _ in range(12))

    new_hash = hash_password(new_password)

    with get_sync_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE users
                SET hashed_password = %s, managed_password = %s, updated_at = now()
                WHERE id = %s
                RETURNING id, email, full_name, role, is_active, managed_password
                """,
                (new_hash, new_password, str(user_id)),
            )
            user = cur.fetchone()
            conn.commit()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user["credentials"] = {
        "password": new_password,
        "has_plaintext": True,
        "algorithm": "bcrypt-blowfish-2b (12 rounds)",
        "status": "Active / Verified" if user.get("is_active") else "Disabled / Revoked"
    }

    write_audit_log(
        actor_id=current_user["id"],
        actor=current_user["email"],
        action="USER_PASSWORD_RESET",
        resource="users",
        resource_id=str(user_id),
        details={"target_email": user["email"], "rotated_by": current_user["email"]},
        source_ip=request.client.host if request.client else None,
    )

    return {
        "status": "success",
        "message": f"Password reset successfully for {user['email']}",
        "user": user,
        "new_password": new_password,
    }


@router.get("/{user_id}")
def get_user(
    user_id: UUID,
    current_user: dict = Depends(require_role("ADMIN")),
):
    with get_sync_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, email, full_name, role, is_active, last_login, created_at, managed_password, substring(hashed_password from 1 for 22) as hash_preview
                FROM users WHERE id = %s
                """,
                (str(user_id),),
            )
            user = cur.fetchone()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user["credentials"] = {
        "password": user.get("managed_password") or "••••••••••••",
        "has_plaintext": bool(user.get("managed_password")),
        "hash_preview": (user.get("hash_preview") + "...") if user.get("hash_preview") else None,
        "algorithm": "bcrypt-blowfish-2b (12 rounds)",
        "status": "Active / Verified" if user.get("is_active") else "Disabled / Revoked"
    }
    return user


@router.patch("/{user_id}")
def update_user(
    user_id: UUID,
    body: UserUpdate,
    request: Request,
    current_user: dict = Depends(require_role("ADMIN")),
):
    updates = body.model_dump(exclude_none=True)
    if not updates:
        raise HTTPException(status_code=400, detail="No fields to update")

    set_clauses = ", ".join(f"{k} = %s" for k in updates)
    values = list(updates.values()) + [str(user_id)]

    with get_sync_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"""
                UPDATE users SET {set_clauses}, updated_at = now()
                WHERE id = %s
                RETURNING id, email, full_name, role, is_active
                """,
                values,
            )
            user = cur.fetchone()
            conn.commit()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    write_audit_log(
        actor_id=current_user["id"],
        actor=current_user["email"],
        action="USER_UPDATED",
        resource="users",
        resource_id=str(user_id),
        details={"email": user["email"], **updates},
        source_ip=request.client.host if request.client else None,
    )
    return user


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(
    user_id: UUID,
    request: Request,
    current_user: dict = Depends(require_role("ADMIN")),
):
    if str(user_id) == str(current_user["id"]):
        raise HTTPException(status_code=400, detail="Cannot delete your own account")

    with get_sync_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM users WHERE id = %s RETURNING id, email, role", (str(user_id),))
            deleted = cur.fetchone()
            conn.commit()

    if not deleted:
        raise HTTPException(status_code=404, detail="User not found")

    write_audit_log(
        actor_id=current_user["id"],
        actor=current_user["email"],
        action="USER_DELETED",
        resource="users",
        resource_id=str(user_id),
        details={"deleted_user_email": deleted["email"], "deleted_user_role": deleted["role"]},
        source_ip=request.client.host if request.client else None,
    )
