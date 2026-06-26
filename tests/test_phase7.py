"""Phase 7 — End-to-end HTTP test suite.

Exhaustive endpoint coverage via httpx.AsyncClient + ASGITransport against
real routes. Phase 6 proved the wiring works; Phase 7 proves every endpoint's
success and failure paths behave correctly at the HTTP layer.
"""
from __future__ import annotations
import asyncio
import pytest
import pyotp
import respx
import httpx
from httpx import ASGITransport, AsyncClient
from fastapi import Depends, FastAPI

from authwarden import AuthWarden, WardenConfig, MemoryUserStore
from authwarden.core.config import OAuthProviderConfig
from authwarden.models.user import UserInDB
from authwarden.utils import generate_otp, hash_token, utcnow
from datetime import timedelta


def make_warden(**kwargs) -> AuthWarden:
    kwargs.setdefault("require_email_verification", False)
    config = WardenConfig(secret_key="phase7-secret", **kwargs)
    return AuthWarden(config=config, user_store=MemoryUserStore())


def make_app(warden: AuthWarden) -> FastAPI:
    app = FastAPI()
    app.include_router(warden.router, prefix="/auth")

    @app.get("/protected")
    async def protected(user: UserInDB = Depends(warden.current_user)):
        return {"id": user.id, "email": user.email}

    return app


def client_for(warden: AuthWarden) -> AsyncClient:
    app = make_app(warden)
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


# ══════════════════════════════════════════════════════════════════
# REGISTER
# ══════════════════════════════════════════════════════════════════

class TestRegisterEndpoint:

    @pytest.mark.asyncio
    async def test_register_success_201(self):
        warden = make_warden()
        async with client_for(warden) as c:
            r = await c.post("/auth/register", json={"email": "a@x.com", "password": "strongpass123"})
            assert r.status_code == 201
            body = r.json()
            assert body["email"] == "a@x.com"
            assert "hashed_password" not in body

    @pytest.mark.asyncio
    async def test_register_with_username_and_phone(self):
        warden = make_warden()
        async with client_for(warden) as c:
            r = await c.post("/auth/register", json={
                "email": "b@x.com", "password": "strongpass123",
                "username": "buser", "phone_number": "+2348011112222",
            })
            assert r.status_code == 201
            assert r.json()["username"] == "buser"

    @pytest.mark.asyncio
    async def test_register_duplicate_email_409(self):
        warden = make_warden()
        async with client_for(warden) as c:
            await c.post("/auth/register", json={"email": "c@x.com", "password": "strongpass123"})
            r = await c.post("/auth/register", json={"email": "c@x.com", "password": "anotherpass"})
            assert r.status_code == 409

    @pytest.mark.asyncio
    async def test_register_duplicate_username_409(self):
        warden = make_warden()
        async with client_for(warden) as c:
            await c.post("/auth/register", json={"email": "d1@x.com", "password": "strongpass123", "username": "dupe"})
            r = await c.post("/auth/register", json={"email": "d2@x.com", "password": "strongpass123", "username": "dupe"})
            assert r.status_code == 409

    @pytest.mark.asyncio
    async def test_register_duplicate_phone_409(self):
        warden = make_warden()
        async with client_for(warden) as c:
            await c.post("/auth/register", json={"email": "e1@x.com", "password": "strongpass123", "phone_number": "+1111"})
            r = await c.post("/auth/register", json={"email": "e2@x.com", "password": "strongpass123", "phone_number": "+1111"})
            assert r.status_code == 409

    @pytest.mark.asyncio
    async def test_register_weak_password_422(self):
        warden = make_warden()
        async with client_for(warden) as c:
            r = await c.post("/auth/register", json={"email": "f@x.com", "password": "x"})
            assert r.status_code == 422

    @pytest.mark.asyncio
    async def test_register_malformed_email_422(self):
        warden = make_warden()
        async with client_for(warden) as c:
            r = await c.post("/auth/register", json={"email": "not-an-email", "password": "strongpass123"})
            assert r.status_code == 422

    @pytest.mark.asyncio
    async def test_register_link_mode_unverified(self):
        warden = make_warden(require_email_verification=True)
        async with client_for(warden) as c:
            r = await c.post("/auth/register", json={"email": "g@x.com", "password": "strongpass123"})
            assert r.status_code == 201
            assert r.json()["is_verified"] is False

    @pytest.mark.asyncio
    async def test_register_otp_mode_sends_otp(self):
        warden = make_warden(require_email_verification=True, verification_method="otp")
        async with client_for(warden) as c:
            r = await c.post("/auth/register", json={"email": "h@x.com", "password": "strongpass123"})
            assert r.status_code == 201
            user = await warden.store.get_by_email("h@x.com")
            assert user.verification_otp_hash is not None


# ══════════════════════════════════════════════════════════════════
# VERIFY EMAIL / OTP / RESEND
# ══════════════════════════════════════════════════════════════════

class TestVerificationEndpoints:

    @pytest.mark.asyncio
    async def test_verify_email_link_success(self):
        warden = make_warden(require_email_verification=True)
        async with client_for(warden) as c:
            await c.post("/auth/register", json={"email": "v1@x.com", "password": "strongpass123"})
            user = await warden.store.get_by_email("v1@x.com")
            from itsdangerous import URLSafeTimedSerializer
            s = URLSafeTimedSerializer(warden.config.secret_key, salt="email-verification")
            token = s.dumps(user.email)
            r = await c.post("/auth/verify-email", json={"token": token})
            assert r.status_code == 200
            assert r.json()["is_verified"] is True

    @pytest.mark.asyncio
    async def test_verify_email_invalid_token_400(self):
        warden = make_warden(require_email_verification=True)
        async with client_for(warden) as c:
            r = await c.post("/auth/verify-email", json={"token": "garbage"})
            assert r.status_code == 400

    @pytest.mark.asyncio
    async def test_verify_email_already_verified_409(self):
        warden = make_warden(require_email_verification=True)
        async with client_for(warden) as c:
            await c.post("/auth/register", json={"email": "v2@x.com", "password": "strongpass123"})
            user = await warden.store.get_by_email("v2@x.com")
            from itsdangerous import URLSafeTimedSerializer
            s = URLSafeTimedSerializer(warden.config.secret_key, salt="email-verification")
            token = s.dumps(user.email)
            await c.post("/auth/verify-email", json={"token": token})
            r = await c.post("/auth/verify-email", json={"token": token})
            assert r.status_code == 409

    @pytest.mark.asyncio
    async def test_verify_otp_success(self):
        warden = make_warden(require_email_verification=True, verification_method="otp")
        async with client_for(warden) as c:
            await c.post("/auth/register", json={"email": "v3@x.com", "password": "strongpass123"})
            user = await warden.store.get_by_email("v3@x.com")
            otp = generate_otp(6)
            user.verification_otp_hash = hash_token(otp)
            await warden.store.update(user)
            r = await c.post("/auth/verify-otp", json={"identifier": "v3@x.com", "otp": otp})
            assert r.status_code == 200

    @pytest.mark.asyncio
    async def test_verify_otp_wrong_code_400(self):
        warden = make_warden(require_email_verification=True, verification_method="otp")
        async with client_for(warden) as c:
            await c.post("/auth/register", json={"email": "v4@x.com", "password": "strongpass123"})
            r = await c.post("/auth/verify-otp", json={"identifier": "v4@x.com", "otp": "000000"})
            assert r.status_code == 400

    @pytest.mark.asyncio
    async def test_verify_otp_attempt_limit_exhausted(self):
        warden = make_warden(require_email_verification=True, verification_method="otp", max_otp_attempts=2)
        async with client_for(warden) as c:
            await c.post("/auth/register", json={"email": "v5@x.com", "password": "strongpass123"})
            for _ in range(2):
                await c.post("/auth/verify-otp", json={"identifier": "v5@x.com", "otp": "000000"})
            user = await warden.store.get_by_email("v5@x.com")
            assert user.verification_otp_hash is None  # invalidated after limit

    @pytest.mark.asyncio
    async def test_resend_verification_success(self):
        warden = make_warden(require_email_verification=True)
        async with client_for(warden) as c:
            await c.post("/auth/register", json={"email": "v6@x.com", "password": "strongpass123"})
            r = await c.post("/auth/resend-verification", json={"identifier": "v6@x.com"})
            assert r.status_code == 200

    @pytest.mark.asyncio
    async def test_resend_verification_rate_limited_429(self):
        warden = make_warden(require_email_verification=True)
        async with client_for(warden) as c:
            await c.post("/auth/register", json={"email": "v7@x.com", "password": "strongpass123"})
            await c.post("/auth/resend-verification", json={"identifier": "v7@x.com"})
            r = await c.post("/auth/resend-verification", json={"identifier": "v7@x.com"})
            assert r.status_code == 429

    @pytest.mark.asyncio
    async def test_resend_verification_unknown_identifier_still_200(self):
        warden = make_warden(require_email_verification=True)
        async with client_for(warden) as c:
            r = await c.post("/auth/resend-verification", json={"identifier": "ghost@x.com"})
            assert r.status_code == 200  # anti-enumeration


# ══════════════════════════════════════════════════════════════════
# LOGIN
# ══════════════════════════════════════════════════════════════════

class TestLoginEndpoint:

    @pytest.mark.asyncio
    async def test_login_by_email_success(self):
        warden = make_warden()
        async with client_for(warden) as c:
            await c.post("/auth/register", json={"email": "l1@x.com", "password": "strongpass123"})
            r = await c.post("/auth/login", json={"identifier": "l1@x.com", "password": "strongpass123"})
            assert r.status_code == 200
            assert r.json()["access_token"]

    @pytest.mark.asyncio
    async def test_login_by_username(self):
        warden = make_warden(login_identifier_fields=["username", "email"])
        async with client_for(warden) as c:
            await c.post("/auth/register", json={"email": "l2@x.com", "password": "strongpass123", "username": "l2user"})
            r = await c.post("/auth/login", json={"identifier": "l2user", "password": "strongpass123"})
            assert r.status_code == 200

    @pytest.mark.asyncio
    async def test_login_by_phone(self):
        warden = make_warden(login_identifier_fields=["phone", "email"])
        async with client_for(warden) as c:
            await c.post("/auth/register", json={"email": "l3@x.com", "password": "strongpass123", "phone_number": "+2222"})
            r = await c.post("/auth/login", json={"identifier": "+2222", "password": "strongpass123"})
            assert r.status_code == 200

    @pytest.mark.asyncio
    async def test_login_wrong_password_401(self):
        warden = make_warden()
        async with client_for(warden) as c:
            await c.post("/auth/register", json={"email": "l4@x.com", "password": "correctpass"})
            r = await c.post("/auth/login", json={"identifier": "l4@x.com", "password": "wrongpass"})
            assert r.status_code == 401

    @pytest.mark.asyncio
    async def test_login_account_locked_423(self):
        warden = make_warden(max_failed_attempts=3)
        async with client_for(warden) as c:
            await c.post("/auth/register", json={"email": "l5@x.com", "password": "correctpass"})
            for _ in range(3):
                await c.post("/auth/login", json={"identifier": "l5@x.com", "password": "wrongpass"})
            r = await c.post("/auth/login", json={"identifier": "l5@x.com", "password": "correctpass"})
            assert r.status_code == 403

    @pytest.mark.asyncio
    async def test_login_unverified_403(self):
        warden = make_warden(require_email_verification=True)
        async with client_for(warden) as c:
            await c.post("/auth/register", json={"email": "l6@x.com", "password": "strongpass123"})
            r = await c.post("/auth/login", json={"identifier": "l6@x.com", "password": "strongpass123"})
            assert r.status_code == 403

    @pytest.mark.asyncio
    async def test_login_unknown_identifier_401(self):
        warden = make_warden()
        async with client_for(warden) as c:
            r = await c.post("/auth/login", json={"identifier": "ghost@x.com", "password": "x"})
            assert r.status_code == 401

    @pytest.mark.asyncio
    async def test_login_mfa_required_403(self):
        warden = make_warden(enable_mfa=True)
        async with client_for(warden) as c:
            await c.post("/auth/register", json={"email": "l7@x.com", "password": "strongpass123"})
            login = await c.post("/auth/login", json={"identifier": "l7@x.com", "password": "strongpass123"})
            token = login.json()["access_token"]
            setup = await c.post("/auth/mfa/setup", headers={"Authorization": f"Bearer {token}"})
            secret = setup.json()["secret"]
            code = pyotp.TOTP(secret).now()
            await c.post("/auth/mfa/confirm", json={"totp_code": code}, headers={"Authorization": f"Bearer {token}"})
            r = await c.post("/auth/login", json={"identifier": "l7@x.com", "password": "strongpass123"})
            assert r.status_code == 403

    @pytest.mark.asyncio
    async def test_login_mfa_wrong_code_401(self):
        warden = make_warden(enable_mfa=True)
        async with client_for(warden) as c:
            await c.post("/auth/register", json={"email": "l8@x.com", "password": "strongpass123"})
            login = await c.post("/auth/login", json={"identifier": "l8@x.com", "password": "strongpass123"})
            token = login.json()["access_token"]
            setup = await c.post("/auth/mfa/setup", headers={"Authorization": f"Bearer {token}"})
            secret = setup.json()["secret"]
            code = pyotp.TOTP(secret).now()
            await c.post("/auth/mfa/confirm", json={"totp_code": code}, headers={"Authorization": f"Bearer {token}"})
            r = await c.post("/auth/login", json={"identifier": "l8@x.com", "password": "strongpass123", "totp_code": "000000"})
            assert r.status_code == 401

    @pytest.mark.asyncio
    async def test_login_mfa_correct_code_succeeds(self):
        warden = make_warden(enable_mfa=True)
        async with client_for(warden) as c:
            await c.post("/auth/register", json={"email": "l9@x.com", "password": "strongpass123"})
            login = await c.post("/auth/login", json={"identifier": "l9@x.com", "password": "strongpass123"})
            token = login.json()["access_token"]
            setup = await c.post("/auth/mfa/setup", headers={"Authorization": f"Bearer {token}"})
            secret = setup.json()["secret"]
            code = pyotp.TOTP(secret).now()
            await c.post("/auth/mfa/confirm", json={"totp_code": code}, headers={"Authorization": f"Bearer {token}"})
            fresh_code = pyotp.TOTP(secret).now()
            r = await c.post("/auth/login", json={"identifier": "l9@x.com", "password": "strongpass123", "totp_code": fresh_code})
            assert r.status_code == 200


# ══════════════════════════════════════════════════════════════════
# LOGOUT / REFRESH / PROTECTED ROUTES
# ══════════════════════════════════════════════════════════════════

class TestLogoutRefreshProtected:

    @pytest.mark.asyncio
    async def test_logout_204(self):
        warden = make_warden()
        async with client_for(warden) as c:
            await c.post("/auth/register", json={"email": "m1@x.com", "password": "strongpass123"})
            login = await c.post("/auth/login", json={"identifier": "m1@x.com", "password": "strongpass123"})
            token = login.json()["access_token"]
            r = await c.post("/auth/logout", headers={"Authorization": f"Bearer {token}"})
            assert r.status_code == 204

    @pytest.mark.asyncio
    async def test_logout_revokes_token(self):
        warden = make_warden()
        async with client_for(warden) as c:
            await c.post("/auth/register", json={"email": "m2@x.com", "password": "strongpass123"})
            login = await c.post("/auth/login", json={"identifier": "m2@x.com", "password": "strongpass123"})
            token = login.json()["access_token"]
            await c.post("/auth/logout", headers={"Authorization": f"Bearer {token}"})
            r = await c.get("/protected", headers={"Authorization": f"Bearer {token}"})
            assert r.status_code == 401

    @pytest.mark.asyncio
    async def test_logout_with_refresh_token_revokes_both(self):
        warden = make_warden()
        async with client_for(warden) as c:
            await c.post("/auth/register", json={"email": "m3@x.com", "password": "strongpass123"})
            login = await c.post("/auth/login", json={"identifier": "m3@x.com", "password": "strongpass123"})
            token = login.json()["access_token"]
            refresh_token = login.json()["refresh_token"]
            await c.post("/auth/logout", json={"refresh_token": refresh_token}, headers={"Authorization": f"Bearer {token}"})
            r = await c.post("/auth/refresh", json={"refresh_token": refresh_token})
            assert r.status_code == 401

    @pytest.mark.asyncio
    async def test_refresh_success(self):
        warden = make_warden()
        async with client_for(warden) as c:
            await c.post("/auth/register", json={"email": "m4@x.com", "password": "strongpass123"})
            login = await c.post("/auth/login", json={"identifier": "m4@x.com", "password": "strongpass123"})
            r = await c.post("/auth/refresh", json={"refresh_token": login.json()["refresh_token"]})
            assert r.status_code == 200
            assert r.json()["access_token"] != login.json()["access_token"]

    @pytest.mark.asyncio
    async def test_refresh_invalid_token_400(self):
        warden = make_warden()
        async with client_for(warden) as c:
            r = await c.post("/auth/refresh", json={"refresh_token": "garbage"})
            assert r.status_code == 400

    @pytest.mark.asyncio
    async def test_refresh_rotated_old_token_revoked(self):
        warden = make_warden()
        async with client_for(warden) as c:
            await c.post("/auth/register", json={"email": "m5@x.com", "password": "strongpass123"})
            login = await c.post("/auth/login", json={"identifier": "m5@x.com", "password": "strongpass123"})
            old_refresh = login.json()["refresh_token"]
            await c.post("/auth/refresh", json={"refresh_token": old_refresh})
            r = await c.post("/auth/refresh", json={"refresh_token": old_refresh})
            assert r.status_code == 401

    @pytest.mark.asyncio
    async def test_protected_route_no_token_401(self):
        warden = make_warden()
        async with client_for(warden) as c:
            r = await c.get("/protected")
            assert r.status_code == 401

    @pytest.mark.asyncio
    async def test_protected_route_deactivated_user_403(self):
        warden = make_warden()
        async with client_for(warden) as c:
            await c.post("/auth/register", json={"email": "m6@x.com", "password": "strongpass123"})
            login = await c.post("/auth/login", json={"identifier": "m6@x.com", "password": "strongpass123"})
            token = login.json()["access_token"]
            user = await warden.store.get_by_email("m6@x.com")
            user.is_active = False
            await warden.store.update(user)
            r = await c.get("/protected", headers={"Authorization": f"Bearer {token}"})
            assert r.status_code == 403


# ══════════════════════════════════════════════════════════════════
# PASSWORD FLOWS — FORGOT / RESET (LINK + OTP) / CHANGE / SET
# ══════════════════════════════════════════════════════════════════

class TestPasswordEndpoints:

    @pytest.mark.asyncio
    async def test_forgot_password_success(self):
        warden = make_warden()
        async with client_for(warden) as c:
            await c.post("/auth/register", json={"email": "p1@x.com", "password": "oldpassword"})
            r = await c.post("/auth/forgot-password", json={"identifier": "p1@x.com"})
            assert r.status_code == 200

    @pytest.mark.asyncio
    async def test_forgot_password_rate_limited_429(self):
        warden = make_warden()
        async with client_for(warden) as c:
            await c.post("/auth/register", json={"email": "p2@x.com", "password": "oldpassword"})
            await c.post("/auth/forgot-password", json={"identifier": "p2@x.com"})
            r = await c.post("/auth/forgot-password", json={"identifier": "p2@x.com"})
            assert r.status_code == 429

    @pytest.mark.asyncio
    async def test_forgot_password_unknown_still_200(self):
        warden = make_warden()
        async with client_for(warden) as c:
            r = await c.post("/auth/forgot-password", json={"identifier": "ghost@x.com"})
            assert r.status_code == 200

    @pytest.mark.asyncio
    async def test_reset_password_link_success(self):
        warden = make_warden()
        async with client_for(warden) as c:
            await c.post("/auth/register", json={"email": "p3@x.com", "password": "oldpassword"})
            user = await warden.store.get_by_email("p3@x.com")
            from itsdangerous import URLSafeTimedSerializer
            s = URLSafeTimedSerializer(warden.config.secret_key, salt="password-reset")
            token = s.dumps(user.email)
            user.reset_token_hash = hash_token(token)
            await warden.store.update(user)
            r = await c.post("/auth/reset-password", json={"token": token, "new_password": "newstrongpassword"})
            assert r.status_code == 200
            login = await c.post("/auth/login", json={"identifier": "p3@x.com", "password": "newstrongpassword"})
            assert login.status_code == 200

    @pytest.mark.asyncio
    async def test_reset_password_invalid_token_400(self):
        warden = make_warden()
        async with client_for(warden) as c:
            r = await c.post("/auth/reset-password", json={"token": "garbage", "new_password": "newpassword"})
            assert r.status_code == 400

    @pytest.mark.asyncio
    async def test_reset_password_otp_success(self):
        warden = make_warden(password_reset_method="otp")
        async with client_for(warden) as c:
            await c.post("/auth/register", json={"email": "p4@x.com", "password": "oldpassword"})
            user = await warden.store.get_by_email("p4@x.com")
            otp = generate_otp(6)
            user.reset_otp_hash = hash_token(otp)
            user.reset_otp_expires_at = utcnow() + timedelta(minutes=10)
            await warden.store.update(user)
            r = await c.post("/auth/reset-password-otp", json={"identifier": "p4@x.com", "otp": otp, "new_password": "newstrongpassword"})
            assert r.status_code == 200

    @pytest.mark.asyncio
    async def test_reset_password_otp_wrong_code_400(self):
        warden = make_warden(password_reset_method="otp")
        async with client_for(warden) as c:
            await c.post("/auth/register", json={"email": "p5@x.com", "password": "oldpassword"})
            r = await c.post("/auth/reset-password-otp", json={"identifier": "p5@x.com", "otp": "000000", "new_password": "newpassword"})
            assert r.status_code == 400

    @pytest.mark.asyncio
    async def test_change_password_success(self):
        warden = make_warden()
        async with client_for(warden) as c:
            await c.post("/auth/register", json={"email": "p6@x.com", "password": "oldpassword"})
            login = await c.post("/auth/login", json={"identifier": "p6@x.com", "password": "oldpassword"})
            token = login.json()["access_token"]
            r = await c.post("/auth/change-password",
                json={"current_password": "oldpassword", "new_password": "newstrongpassword"},
                headers={"Authorization": f"Bearer {token}"})
            assert r.status_code == 200

    @pytest.mark.asyncio
    async def test_change_password_wrong_current_401(self):
        warden = make_warden()
        async with client_for(warden) as c:
            await c.post("/auth/register", json={"email": "p7@x.com", "password": "correctpass"})
            login = await c.post("/auth/login", json={"identifier": "p7@x.com", "password": "correctpass"})
            token = login.json()["access_token"]
            r = await c.post("/auth/change-password",
                json={"current_password": "wrongpass", "new_password": "newpassword"},
                headers={"Authorization": f"Bearer {token}"})
            assert r.status_code == 401

    @pytest.mark.asyncio
    async def test_change_password_same_password_422(self):
        warden = make_warden()
        async with client_for(warden) as c:
            await c.post("/auth/register", json={"email": "p8@x.com", "password": "samepassword"})
            login = await c.post("/auth/login", json={"identifier": "p8@x.com", "password": "samepassword"})
            token = login.json()["access_token"]
            r = await c.post("/auth/change-password",
                json={"current_password": "samepassword", "new_password": "samepassword"},
                headers={"Authorization": f"Bearer {token}"})
            assert r.status_code == 422

    @pytest.mark.asyncio
    async def test_set_password_oauth_only_account(self):
        warden = make_warden()
        async with client_for(warden) as c:
            from authwarden.models.user import UserInDB as UDB
            user = UDB(email="p9@x.com", hashed_password=None, is_active=True, is_verified=True)
            await warden.store.create(user)
            pair = warden.jwt_handler.create_token_pair(user.id)
            r = await c.post("/auth/set-password", json={"new_password": "newstrongpassword"},
                headers={"Authorization": f"Bearer {pair.access_token}"})
            assert r.status_code == 200

    @pytest.mark.asyncio
    async def test_set_password_already_set_400(self):
        warden = make_warden()
        async with client_for(warden) as c:
            await c.post("/auth/register", json={"email": "p10@x.com", "password": "existingpass"})
            login = await c.post("/auth/login", json={"identifier": "p10@x.com", "password": "existingpass"})
            token = login.json()["access_token"]
            r = await c.post("/auth/set-password", json={"new_password": "newpassword"},
                headers={"Authorization": f"Bearer {token}"})
            assert r.status_code == 400


# ══════════════════════════════════════════════════════════════════
# MFA ENDPOINTS
# ══════════════════════════════════════════════════════════════════

class TestMfaEndpoints:

    async def _register_login(self, c, email="mfa@x.com", password="strongpass123"):
        await c.post("/auth/register", json={"email": email, "password": password})
        login = await c.post("/auth/login", json={"identifier": email, "password": password})
        return login.json()["access_token"]

    @pytest.mark.asyncio
    async def test_mfa_setup_returns_secret_and_8_codes(self):
        warden = make_warden(enable_mfa=True)
        async with client_for(warden) as c:
            token = await self._register_login(c)
            r = await c.post("/auth/mfa/setup", headers={"Authorization": f"Bearer {token}"})
            assert r.status_code == 200
            assert len(r.json()["backup_codes"]) == 8

    @pytest.mark.asyncio
    async def test_mfa_confirm_success(self):
        warden = make_warden(enable_mfa=True)
        async with client_for(warden) as c:
            token = await self._register_login(c, email="mfa2@x.com")
            setup = await c.post("/auth/mfa/setup", headers={"Authorization": f"Bearer {token}"})
            secret = setup.json()["secret"]
            code = pyotp.TOTP(secret).now()
            r = await c.post("/auth/mfa/confirm", json={"totp_code": code}, headers={"Authorization": f"Bearer {token}"})
            assert r.status_code == 200

    @pytest.mark.asyncio
    async def test_mfa_confirm_wrong_code_401(self):
        warden = make_warden(enable_mfa=True)
        async with client_for(warden) as c:
            token = await self._register_login(c, email="mfa3@x.com")
            await c.post("/auth/mfa/setup", headers={"Authorization": f"Bearer {token}"})
            r = await c.post("/auth/mfa/confirm", json={"totp_code": "000000"}, headers={"Authorization": f"Bearer {token}"})
            assert r.status_code == 401

    @pytest.mark.asyncio
    async def test_mfa_disable_with_totp(self):
        warden = make_warden(enable_mfa=True)
        async with client_for(warden) as c:
            token = await self._register_login(c, email="mfa4@x.com")
            setup = await c.post("/auth/mfa/setup", headers={"Authorization": f"Bearer {token}"})
            secret = setup.json()["secret"]
            code = pyotp.TOTP(secret).now()
            await c.post("/auth/mfa/confirm", json={"totp_code": code}, headers={"Authorization": f"Bearer {token}"})
            fresh_code = pyotp.TOTP(secret).now()
            r = await c.post("/auth/mfa/disable", json={"password": "strongpass123", "totp_or_backup_code": fresh_code},
                headers={"Authorization": f"Bearer {token}"})
            assert r.status_code == 200

    @pytest.mark.asyncio
    async def test_mfa_disable_with_backup_code(self):
        warden = make_warden(enable_mfa=True)
        async with client_for(warden) as c:
            token = await self._register_login(c, email="mfa5@x.com")
            setup = await c.post("/auth/mfa/setup", headers={"Authorization": f"Bearer {token}"})
            secret = setup.json()["secret"]
            backup_code = setup.json()["backup_codes"][0]
            code = pyotp.TOTP(secret).now()
            await c.post("/auth/mfa/confirm", json={"totp_code": code}, headers={"Authorization": f"Bearer {token}"})
            r = await c.post("/auth/mfa/disable", json={"password": "strongpass123", "totp_or_backup_code": backup_code},
                headers={"Authorization": f"Bearer {token}"})
            assert r.status_code == 200

    @pytest.mark.asyncio
    async def test_mfa_disable_wrong_password_401(self):
        warden = make_warden(enable_mfa=True)
        async with client_for(warden) as c:
            token = await self._register_login(c, email="mfa6@x.com")
            setup = await c.post("/auth/mfa/setup", headers={"Authorization": f"Bearer {token}"})
            secret = setup.json()["secret"]
            code = pyotp.TOTP(secret).now()
            await c.post("/auth/mfa/confirm", json={"totp_code": code}, headers={"Authorization": f"Bearer {token}"})
            fresh_code = pyotp.TOTP(secret).now()
            r = await c.post("/auth/mfa/disable", json={"password": "wrongpass", "totp_or_backup_code": fresh_code},
                headers={"Authorization": f"Bearer {token}"})
            assert r.status_code == 401

    @pytest.mark.asyncio
    async def test_mfa_disable_not_enabled_400(self):
        warden = make_warden(enable_mfa=True)
        async with client_for(warden) as c:
            token = await self._register_login(c, email="mfa7@x.com")
            r = await c.post("/auth/mfa/disable", json={"password": "strongpass123", "totp_or_backup_code": "123456"},
                headers={"Authorization": f"Bearer {token}"})
            assert r.status_code == 400

    @pytest.mark.asyncio
    async def test_mfa_setup_no_auth_401(self):
        warden = make_warden(enable_mfa=True)
        async with client_for(warden) as c:
            r = await c.post("/auth/mfa/setup")
            assert r.status_code == 401


# ══════════════════════════════════════════════════════════════════
# OAUTH ENDPOINTS
# ══════════════════════════════════════════════════════════════════

def make_oauth_warden(**kwargs) -> AuthWarden:
    config = WardenConfig(
        secret_key="phase7-secret", require_email_verification=False,
        oauth_providers={
            "google": OAuthProviderConfig(client_id="g-cid", client_secret="g-sec", redirect_uri="https://app.com/cb/google"),
            "github": OAuthProviderConfig(client_id="gh-cid", client_secret="gh-sec", redirect_uri="https://app.com/cb/github"),
        },
        **kwargs,
    )
    return AuthWarden(config=config, user_store=MemoryUserStore())


def mock_google_success(email="newuser@gmail.com", sub="google-uid-1"):
    respx.post("https://oauth2.googleapis.com/token").mock(
        return_value=httpx.Response(200, json={"access_token": "gtok", "token_type": "bearer", "expires_in": 3600})
    )
    respx.get("https://openidconnect.googleapis.com/v1/userinfo").mock(
        return_value=httpx.Response(200, json={"sub": sub, "email": email, "email_verified": True, "name": "New User"})
    )


def mock_github_success(uid="gh-uid-1"):
    respx.post("https://github.com/login/oauth/access_token").mock(
        return_value=httpx.Response(200, json={"access_token": "ghtok", "token_type": "bearer"})
    )
    respx.get("https://api.github.com/user").mock(
        return_value=httpx.Response(200, json={"id": uid, "login": "ghuser", "name": "GH User", "email": "gh@example.com"})
    )


class TestOAuthEndpoints:

    @pytest.mark.asyncio
    async def test_authorize_returns_url(self):
        warden = make_oauth_warden()
        async with client_for(warden) as c:
            r = await c.get("/auth/oauth/google/authorize")
            assert r.status_code == 200
            assert "accounts.google.com" in r.json()["authorization_url"]

    @pytest.mark.asyncio
    async def test_authorize_unknown_provider_404(self):
        warden = make_oauth_warden()
        async with client_for(warden) as c:
            r = await c.get("/auth/oauth/notreal/authorize")
            assert r.status_code == 404

    @respx.mock
    @pytest.mark.asyncio
    async def test_callback_new_user_login_200(self):
        warden = make_oauth_warden()
        async with client_for(warden) as c:
            mock_google_success(email="cb1@gmail.com", sub="google-uid-cb1")
            authorize = await c.get("/auth/oauth/google/authorize")
            state = authorize.json()["authorization_url"].split("state=")[1].split("&")[0]
            r = await c.post("/auth/oauth/google/callback", json={"code": "code", "state": state})
            assert r.status_code == 200
            assert r.json()["is_new_user"] is True
            assert r.json()["user"]["email"] == "cb1@gmail.com"

    @pytest.mark.asyncio
    async def test_callback_bad_state_400(self):
        warden = make_oauth_warden()
        async with client_for(warden) as c:
            r = await c.post("/auth/oauth/google/callback", json={"code": "code", "state": "never-existed"})
            assert r.status_code == 400

    @respx.mock
    @pytest.mark.asyncio
    async def test_callback_existing_account_logs_in_not_new(self):
        warden = make_oauth_warden()
        async with client_for(warden) as c:
            mock_google_success(email="cb2@gmail.com", sub="google-uid-cb2")
            a1 = await c.get("/auth/oauth/google/authorize")
            s1 = a1.json()["authorization_url"].split("state=")[1].split("&")[0]
            r1 = await c.post("/auth/oauth/google/callback", json={"code": "code1", "state": s1})
            assert r1.json()["is_new_user"] is True

            mock_google_success(email="cb2@gmail.com", sub="google-uid-cb2")
            a2 = await c.get("/auth/oauth/google/authorize")
            s2 = a2.json()["authorization_url"].split("state=")[1].split("&")[0]
            r2 = await c.post("/auth/oauth/google/callback", json={"code": "code2", "state": s2})
            assert r2.json()["is_new_user"] is False
            assert r2.json()["user"]["id"] == r1.json()["user"]["id"]

    @pytest.mark.asyncio
    async def test_accounts_list_requires_auth_401(self):
        warden = make_oauth_warden()
        async with client_for(warden) as c:
            r = await c.get("/auth/oauth/accounts")
            assert r.status_code == 401

    @pytest.mark.asyncio
    async def test_accounts_list_empty_for_new_user(self):
        warden = make_oauth_warden()
        async with client_for(warden) as c:
            await c.post("/auth/register", json={"email": "oa1@x.com", "password": "strongpass123"})
            login = await c.post("/auth/login", json={"identifier": "oa1@x.com", "password": "strongpass123"})
            token = login.json()["access_token"]
            r = await c.get("/auth/oauth/accounts", headers={"Authorization": f"Bearer {token}"})
            assert r.status_code == 200
            assert r.json() == []

    @respx.mock
    @pytest.mark.asyncio
    async def test_connect_links_provider(self):
        warden = make_oauth_warden()
        async with client_for(warden) as c:
            await c.post("/auth/register", json={"email": "oa2@x.com", "password": "strongpass123"})
            login = await c.post("/auth/login", json={"identifier": "oa2@x.com", "password": "strongpass123"})
            token = login.json()["access_token"]

            mock_github_success(uid="gh-connect-1")
            authorize = await c.get("/auth/oauth/github/authorize", headers={"Authorization": f"Bearer {token}"})
            state = authorize.json()["authorization_url"].split("state=")[1].split("&")[0]
            r = await c.post("/auth/oauth/github/connect", json={"code": "code", "state": state},
                headers={"Authorization": f"Bearer {token}"})
            assert r.status_code == 200
            assert r.json()["provider"] == "github"

    @pytest.mark.asyncio
    async def test_disconnect_last_method_400(self):
        warden = make_oauth_warden()
        async with client_for(warden) as c:
            from authwarden.models.user import OAuthAccount, UserInDB as UDB
            user = UDB(email="oa3@x.com", hashed_password=None, is_active=True, is_verified=True)
            await warden.store.create(user)
            await warden.store.create_oauth_account(OAuthAccount(user_id=user.id, provider="google", provider_user_id="gid"))
            pair = warden.jwt_handler.create_token_pair(user.id)
            r = await c.delete("/auth/oauth/google/disconnect", headers={"Authorization": f"Bearer {pair.access_token}"})
            assert r.status_code == 400

    @pytest.mark.asyncio
    async def test_disconnect_unlinked_provider_404(self):
        warden = make_oauth_warden()
        async with client_for(warden) as c:
            await c.post("/auth/register", json={"email": "oa4@x.com", "password": "strongpass123"})
            login = await c.post("/auth/login", json={"identifier": "oa4@x.com", "password": "strongpass123"})
            token = login.json()["access_token"]
            r = await c.delete("/auth/oauth/google/disconnect", headers={"Authorization": f"Bearer {token}"})
            assert r.status_code == 404

    @pytest.mark.asyncio
    async def test_disconnect_with_password_succeeds(self):
        warden = make_oauth_warden()
        async with client_for(warden) as c:
            from authwarden.models.user import OAuthAccount
            await c.post("/auth/register", json={"email": "oa5@x.com", "password": "strongpass123"})
            login = await c.post("/auth/login", json={"identifier": "oa5@x.com", "password": "strongpass123"})
            token = login.json()["access_token"]
            user = await warden.store.get_by_email("oa5@x.com")
            await warden.store.create_oauth_account(OAuthAccount(user_id=user.id, provider="google", provider_user_id="gid2"))
            r = await c.delete("/auth/oauth/google/disconnect", headers={"Authorization": f"Bearer {token}"})
            assert r.status_code == 204