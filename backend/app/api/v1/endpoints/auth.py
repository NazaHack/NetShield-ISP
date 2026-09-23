"""Sign-in and self-service account endpoints."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request, status

from app.api.dependencies import PrincipalDep, SessionDep
from app.core.config import settings
from app.core.logging import get_logger
from app.core.passwords import (
    PasswordTooWeakError,
    hash_password,
    needs_rehash,
    verify_password,
)
from app.core.ratelimit import (
    check_login_allowed,
    record_failed_login,
    reset_login_counters,
)
from app.core.security import create_access_token
from app.models import AuditAction
from app.repositories.audit import add_event
from app.repositories.user import get_user_by_email, get_user_by_id, record_successful_login
from app.schemas.auth import LoginRequest, LoginResponse, PasswordChange, UserRead

router = APIRouter(prefix="/auth", tags=["authentication"])
logger = get_logger(__name__)

#: The single message every failed sign-in returns.
#:
#: Distinguishing "no such account" from "wrong password", or naming a disabled
#: account, would let anyone confirm which email addresses are registered.
_INVALID_CREDENTIALS = "Invalid email or password."


def _client_ip(request: Request) -> str:
    """Best-effort source address for rate limiting.

    In production Uvicorn runs with ``--proxy-headers``, so ``request.client``
    already reflects the forwarded client address rather than the proxy. A
    missing client (possible in some test transports) falls back to a constant,
    which simply means all such attempts share one bucket.
    """
    return request.client.host if request.client else "unknown"


@router.post(
    "/login",
    response_model=LoginResponse,
    summary="Sign in and receive a bearer token",
)
async def login(payload: LoginRequest, request: Request, session: SessionDep) -> LoginResponse:
    """Exchange an email and password for an access token.

    Failed attempts are rate limited per email and per source IP, so the
    endpoint cannot be used to guess passwords at speed. Within the limit, the
    password is verified even when the address is unknown, against a dummy hash,
    so a failed sign-in takes the same time either way and cannot be used to
    enumerate accounts.

    Raises:
        HTTPException: 429 when the attempt limit is reached, otherwise 401 for
            any failure with one message for all of them.
    """
    ip = _client_ip(request)

    decision = await check_login_allowed(email=payload.email, ip=ip)
    if not decision.allowed:
        logger.warning("api.login_rate_limited", email=payload.email.lower(), ip=ip)
        add_event(
            session,
            action=AuditAction.LOGIN_RATE_LIMITED,
            actor_email=payload.email,
            source_ip=ip,
        )
        await session.commit()
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many sign-in attempts. Try again later.",
            headers={"Retry-After": str(decision.retry_after_seconds)},
        )

    user = await get_user_by_email(session, email=payload.email)
    credentials_ok = verify_password(payload.password, user.password_hash if user else None)

    # A disabled account is treated exactly like a wrong password: same message,
    # and the same failed-attempt accounting.
    if not credentials_ok or user is None or not user.is_active:
        await record_failed_login(email=payload.email, ip=ip)
        reason = "bad credentials" if not credentials_ok else "disabled"
        logger.warning("api.login_failed", email=payload.email.lower(), ip=ip, reason=reason)
        add_event(
            session,
            action=AuditAction.LOGIN_FAILED,
            actor_email=payload.email,
            source_ip=ip,
            detail={"reason": reason},
        )
        await session.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=_INVALID_CREDENTIALS,
            headers={"WWW-Authenticate": "Bearer"},
        )

    # A good sign-in wipes the failure counters so earlier typos do not count.
    await reset_login_counters(email=payload.email, ip=ip)

    # Upgrade the stored hash transparently when the cost parameters have moved.
    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(payload.password)

    await record_successful_login(session, user=user)
    add_event(
        session,
        action=AuditAction.LOGIN_SUCCEEDED,
        actor_user_id=user.id,
        actor_email=user.email,
        actor_role=user.role.value,
        tenant_id=user.tenant_id,
        source_ip=ip,
    )
    await session.commit()
    await session.refresh(user)

    token = create_access_token(
        user_id=user.id,
        role=user.role,
        tenant_id=user.tenant_id,
    )

    logger.info(
        "api.login_succeeded",
        user_id=str(user.id),
        role=user.role.value,
        tenant_id=str(user.tenant_id) if user.tenant_id else None,
    )

    return LoginResponse(
        access_token=token,
        expires_in_seconds=settings.access_token_expire_minutes * 60,
        user=UserRead.model_validate(user),
    )


@router.get("/me", response_model=UserRead, summary="Read the signed-in account")
async def read_me(principal: PrincipalDep, session: SessionDep) -> UserRead:
    """Return the account behind the current token.

    The console uses this to decide which sections to show, so it reflects the
    live account rather than whatever the token asserted when it was issued.
    """
    user = await get_user_by_id(session, user_id=principal.user_id)
    if user is None:
        # The dependency already resolved this account, so its disappearance
        # between then and now is a race rather than an ordinary 404.
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return UserRead.model_validate(user)


@router.post(
    "/password",
    status_code=status.HTTP_204_NO_CONTENT,
    response_model=None,
    summary="Change your own password",
)
async def change_password(
    payload: PasswordChange,
    principal: PrincipalDep,
    session: SessionDep,
) -> None:
    """Replace the signed-in account's password.

    The current password is required: possession of a valid token is not enough
    to set a new one, so a stolen token cannot be used to take over the account
    permanently.

    Raises:
        HTTPException: 401 when the current password is wrong, 422 when the new
            one is too weak.
    """
    user = await get_user_by_id(session, user_id=principal.user_id)
    if user is None or not verify_password(payload.current_password, user.password_hash):
        logger.warning("api.password_change_rejected", user_id=str(principal.user_id))
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="The current password is incorrect.",
        )

    try:
        user.password_hash = hash_password(payload.new_password)
    except PasswordTooWeakError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc

    add_event(
        session,
        action=AuditAction.PASSWORD_CHANGED,
        actor=principal,
        tenant_id=principal.tenant_id,
        target=user.email,
    )
    await session.commit()
    logger.info("api.password_changed", user_id=str(user.id))
