"""Phase 3 tests — auth flows with full flexibility."""
from __future__ import annotations
import io
from datetime import timedelta
from urllib.parse import parse_qs, urlparse
import pytest

from authwarden.authentication.jwt import JWTHandler, MemoryTokenBlacklist
from authwarden.authentication.password import PasswordHandler
from authwarden.core.config import WardenConfig
from authwarden.email.console import ConsoleEmailBackend
from authwarden.email.templates import EmailTemplates
from authwarden.exceptions import (
    AccountInactive, AlreadyVerified, EmailAlreadyExists, EmailNotVerified,
    InvalidCredentials, InvalidToken, PasswordNotSet, RateLimited, SamePassword,
    TokenAlreadyUsed, TokenExpired, TokenRevoked, UserNotFound, WeakPassword,
)
from authwarden.flows.change_password import change_password_flow
from authwarden.flows.forgot_password import forgot_password_flow
from authwarden.flows.login import login_flow
from authwarden.flows.logout import logout_flow
from authwarden.flows.refresh import refresh_flow
from authwarden.flows.register import register_flow
from authwarden.flows.resend_verification import resend_verification_flow
from authwarden.flows.reset_password import reset_password_flow
from authwarden.flows.reset_password_otp import reset_password_otp_flow
from authwarden.flows.verify_email import verify_email_flow
from authwarden.flows.verify_otp import verify_otp_flow
from authwarden.models.user import UserCreate, UserInDB, UserRead
from authwarden.notifications.service import NotificationService
from authwarden.sms.console import ConsoleSmsBackend
from authwarden.sms.templates import SmsTemplates
from authwarden.storage.memory import MemoryUserStore
from authwarden.utils import generate_otp, hash_token, utcnow


class MockNotificationService:
    def __init__(self): self.calls: list[dict] = []
    def _record(self, method, **kw): self.calls.append({"method": method, **kw})
    @property
    def last(self):
        assert self.calls; return self.calls[-1]
    @property
    def last_otp(self):
        for c in reversed(self.calls):
            if "otp" in c: return c["otp"]
        raise AssertionError("No OTP sent")
    @property
    def last_link(self):
        for c in reversed(self.calls):
            if "link" in c: return c["link"]
        raise AssertionError("No link sent")
    def count(self): return len(self.calls)
    def clear(self): self.calls.clear()
    def methods_called(self): return [c["method"] for c in self.calls]
    async def send_verification_link(self, u, link): self._record("send_verification_link", user=u, link=link)
    async def send_verification_otp(self, u, otp): self._record("send_verification_otp", user=u, otp=otp)
    async def send_welcome(self, u): self._record("send_welcome", user=u)
    async def send_password_reset_link(self, u, link): self._record("send_password_reset_link", user=u, link=link)
    async def send_password_reset_otp(self, u, otp): self._record("send_password_reset_otp", user=u, otp=otp)
    async def send_password_changed(self, u): self._record("send_password_changed", user=u)
    async def send_mfa_enabled(self, u): self._record("send_mfa_enabled", user=u)
    async def send_mfa_disabled(self, u): self._record("send_mfa_disabled", user=u)


def extract_token(link: str) -> str:
    return parse_qs(urlparse(link).query)["token"][0]


@pytest.fixture
def config(): return WardenConfig(secret_key="phase3-secret")
@pytest.fixture
def config_otp(): return WardenConfig(secret_key="phase3-secret", verification_method="otp", otp_length=6, otp_ttl=600)
@pytest.fixture
def config_no_verify(): return WardenConfig(secret_key="phase3-secret", require_email_verification=False)
@pytest.fixture
def config_username(): return WardenConfig(secret_key="phase3-secret", login_identifier_fields=["username","email"], require_email_verification=False)
@pytest.fixture
def config_phone(): return WardenConfig(secret_key="phase3-secret", login_identifier_fields=["phone","email"], require_email_verification=False)
@pytest.fixture
def config_reset_otp(): return WardenConfig(secret_key="phase3-secret", require_email_verification=False, password_reset_method="otp", otp_ttl=600)
@pytest.fixture
def store(): return MemoryUserStore()
@pytest.fixture
def notif(): return MockNotificationService()
@pytest.fixture
def pw(config): return PasswordHandler(config)
@pytest.fixture
def jwt(config): return JWTHandler(config, blacklist=MemoryTokenBlacklist())


async def _reg_verify(email, password, store, config, pw, notif):
    await register_flow(UserCreate(email=email, password=password),
        store=store, config=config, password_handler=pw, notification_service=notif)
    token = extract_token(notif.last_link)
    return await verify_email_flow(token, store=store, config=config, notification_service=notif)

async def _reg_verify_otp(email, password, store, config, pw, notif):
    await register_flow(UserCreate(email=email, password=password),
        store=store, config=config, password_handler=pw, notification_service=notif)
    return await verify_otp_flow(email, notif.last_otp, store=store, config=config, notification_service=notif)

async def _reg_active(email, password, store, config, pw, notif):
    await register_flow(UserCreate(email=email, password=password),
        store=store, config=config, password_handler=pw, notification_service=notif)


class TestRegisterFlow:
    @pytest.mark.asyncio
    async def test_success(self, store, config, pw, notif):
        r = await register_flow(UserCreate(email="a@x.com", password="strongpass"),
            store=store, config=config, password_handler=pw, notification_service=notif)
        assert isinstance(r, UserRead) and r.is_verified is False

    @pytest.mark.asyncio
    async def test_sends_link(self, store, config, pw, notif):
        await register_flow(UserCreate(email="b@x.com", password="strongpass"),
            store=store, config=config, password_handler=pw, notification_service=notif)
        assert "send_verification_link" in notif.methods_called()

    @pytest.mark.asyncio
    async def test_sends_otp(self, store, config_otp, pw, notif):
        await register_flow(UserCreate(email="c@x.com", password="strongpass"),
            store=store, config=config_otp, password_handler=pw, notification_service=notif)
        assert "send_verification_otp" in notif.methods_called()
        assert notif.last_otp.isdigit() and len(notif.last_otp) == 6

    @pytest.mark.asyncio
    async def test_duplicate_email(self, store, config, pw, notif):
        await register_flow(UserCreate(email="d@x.com", password="strongpass"),
            store=store, config=config, password_handler=pw, notification_service=notif)
        with pytest.raises(EmailAlreadyExists):
            await register_flow(UserCreate(email="d@x.com", password="anotherpass"),
                store=store, config=config, password_handler=pw, notification_service=notif)

    @pytest.mark.asyncio
    async def test_weak_password(self, store, config, pw, notif):
        with pytest.raises(WeakPassword):
            await register_flow(UserCreate(email="e@x.com", password="x"),
                store=store, config=config, password_handler=pw, notification_service=notif)

    @pytest.mark.asyncio
    async def test_no_verification_active_immediately(self, store, config_no_verify, pw, notif):
        r = await register_flow(UserCreate(email="f@x.com", password="strongpass"),
            store=store, config=config_no_verify, password_handler=pw, notification_service=notif)
        assert r.is_active is True and r.is_verified is True and notif.count() == 0

    @pytest.mark.asyncio
    async def test_stores_hashed_password(self, store, config, pw, notif):
        await register_flow(UserCreate(email="g@x.com", password="mypassword"),
            store=store, config=config, password_handler=pw, notification_service=notif)
        user = await store.get_by_email("g@x.com")
        assert pw.verify_password("mypassword", user.hashed_password)


class TestVerifyEmailFlow:
    @pytest.mark.asyncio
    async def test_link_success(self, store, config, pw, notif):
        r = await _reg_verify("v@x.com", "strongpass", store, config, pw, notif)
        assert r.is_verified is True and r.is_active is True

    @pytest.mark.asyncio
    async def test_sends_welcome(self, store, config, pw, notif):
        await _reg_verify("w@x.com", "strongpass", store, config, pw, notif)
        assert "send_welcome" in notif.methods_called()

    @pytest.mark.asyncio
    async def test_invalid_token(self, store, config, notif):
        with pytest.raises(InvalidToken):
            await verify_email_flow("bad.tok", store=store, config=config, notification_service=notif)

    @pytest.mark.asyncio
    async def test_already_verified(self, store, config, pw, notif):
        await register_flow(UserCreate(email="av@x.com", password="strongpass"),
            store=store, config=config, password_handler=pw, notification_service=notif)
        tok = extract_token(notif.last_link)
        await verify_email_flow(tok, store=store, config=config, notification_service=notif)
        with pytest.raises(AlreadyVerified):
            await verify_email_flow(tok, store=store, config=config, notification_service=notif)


class TestVerifyOtpFlow:
    @pytest.mark.asyncio
    async def test_otp_success(self, store, config_otp, pw, notif):
        r = await _reg_verify_otp("ov@x.com", "strongpass", store, config_otp, pw, notif)
        assert r.is_verified is True

    @pytest.mark.asyncio
    async def test_otp_wrong_code(self, store, config_otp, pw, notif):
        await register_flow(UserCreate(email="ow@x.com", password="strongpass"),
            store=store, config=config_otp, password_handler=pw, notification_service=notif)
        with pytest.raises(InvalidToken):
            await verify_otp_flow("ow@x.com", "000000", store=store, config=config_otp, notification_service=notif)

    @pytest.mark.asyncio
    async def test_otp_expired(self, store, config_otp, pw, notif):
        await register_flow(UserCreate(email="oe@x.com", password="strongpass"),
            store=store, config=config_otp, password_handler=pw, notification_service=notif)
        user = await store.get_by_email("oe@x.com")
        user.verification_otp_expires_at = utcnow() - timedelta(seconds=1)
        await store.update(user)
        with pytest.raises(TokenExpired):
            await verify_otp_flow("oe@x.com", notif.last_otp, store=store, config=config_otp, notification_service=notif)

    @pytest.mark.asyncio
    async def test_otp_by_phone(self, store, config_otp, notif):
        otp = generate_otp(6)
        user = UserInDB(email="ph@x.com", phone_number="+2341111111111",
            hashed_password="h", is_active=False, is_verified=False,
            verification_otp_hash=hash_token(otp),
            verification_otp_expires_at=utcnow() + timedelta(minutes=10))
        await store.create(user)
        r = await verify_otp_flow("+2341111111111", otp, store=store, config=config_otp, notification_service=notif)
        assert r.is_verified is True


class TestResendVerification:
    @pytest.mark.asyncio
    async def test_resend_link(self, store, config, pw, notif):
        await register_flow(UserCreate(email="rl@x.com", password="strongpass"),
            store=store, config=config, password_handler=pw, notification_service=notif)
        notif.clear()
        await resend_verification_flow("rl@x.com", store=store, config=config, notification_service=notif)
        assert "send_verification_link" in notif.methods_called()

    @pytest.mark.asyncio
    async def test_resend_otp(self, store, config_otp, pw, notif):
        await register_flow(UserCreate(email="ro@x.com", password="strongpass"),
            store=store, config=config_otp, password_handler=pw, notification_service=notif)
        notif.clear()
        await resend_verification_flow("ro@x.com", store=store, config=config_otp, notification_service=notif)
        assert "send_verification_otp" in notif.methods_called()

    @pytest.mark.asyncio
    async def test_rate_limited(self, store, config, pw, notif):
        await register_flow(UserCreate(email="rrl@x.com", password="strongpass"),
            store=store, config=config, password_handler=pw, notification_service=notif)
        await resend_verification_flow("rrl@x.com", store=store, config=config, notification_service=notif)
        with pytest.raises(RateLimited):
            await resend_verification_flow("rrl@x.com", store=store, config=config, notification_service=notif)

    @pytest.mark.asyncio
    async def test_unknown_silent(self, store, config, notif):
        await resend_verification_flow("ghost@x.com", store=store, config=config, notification_service=notif)
        assert notif.count() == 0

    @pytest.mark.asyncio
    async def test_already_verified_silent(self, store, config, pw, notif):
        await _reg_verify("avs@x.com", "strongpass", store, config, pw, notif)
        notif.clear()
        await resend_verification_flow("avs@x.com", store=store, config=config, notification_service=notif)
        assert notif.count() == 0


class TestLoginFlow:
    @pytest.mark.asyncio
    async def test_login_by_email(self, store, config_no_verify, pw, jwt, notif):
        await _reg_active("le@x.com", "pass1234", store, config_no_verify, pw, notif)
        pair, user = await login_flow("le@x.com", "pass1234",
            store=store, config=config_no_verify, password_handler=pw, jwt_handler=jwt)
        assert pair.access_token and user.email == "le@x.com"

    @pytest.mark.asyncio
    async def test_login_by_username(self, store, config_username, pw, notif):
        jwt2 = JWTHandler(config_username, blacklist=MemoryTokenBlacklist())
        user = UserInDB(email="lu@x.com", username="johndoe",
            hashed_password=pw.hash_password("pass1234"), is_active=True, is_verified=True)
        await store.create(user)
        pair, r = await login_flow("johndoe", "pass1234",
            store=store, config=config_username, password_handler=pw, jwt_handler=jwt2)
        assert pair.access_token and r.username == "johndoe"

    @pytest.mark.asyncio
    async def test_login_by_phone(self, store, config_phone, pw, notif):
        jwt2 = JWTHandler(config_phone, blacklist=MemoryTokenBlacklist())
        user = UserInDB(email="lp@x.com", phone_number="+2348012345678",
            hashed_password=pw.hash_password("pass1234"), is_active=True, is_verified=True)
        await store.create(user)
        pair, _ = await login_flow("+2348012345678", "pass1234",
            store=store, config=config_phone, password_handler=pw, jwt_handler=jwt2)
        assert pair.access_token

    @pytest.mark.asyncio
    async def test_login_tries_fields_in_order(self, store, config_username, pw, notif):
        jwt2 = JWTHandler(config_username, blacklist=MemoryTokenBlacklist())
        user = UserInDB(email="lo@x.com", username="order_test",
            hashed_password=pw.hash_password("pass1234"), is_active=True, is_verified=True)
        await store.create(user)
        pair, _ = await login_flow("order_test", "pass1234",
            store=store, config=config_username, password_handler=pw, jwt_handler=jwt2)
        assert pair.access_token

    @pytest.mark.asyncio
    async def test_wrong_password(self, store, config_no_verify, pw, jwt, notif):
        await _reg_active("lw@x.com", "correctpass", store, config_no_verify, pw, notif)
        with pytest.raises(InvalidCredentials):
            await login_flow("lw@x.com", "wrong", store=store, config=config_no_verify,
                password_handler=pw, jwt_handler=jwt)

    @pytest.mark.asyncio
    async def test_unknown_identifier(self, store, config_no_verify, pw, jwt):
        with pytest.raises(InvalidCredentials):
            await login_flow("nobody@x.com", "pass",
                store=store, config=config_no_verify, password_handler=pw, jwt_handler=jwt)

    @pytest.mark.asyncio
    async def test_unverified_blocked(self, store, config, pw, jwt, notif):
        # Create active but unverified user — is_active=True so active check passes,
        # but is_verified=False so EmailNotVerified fires
        user = UserInDB(email="uv@x.com",
            hashed_password=pw.hash_password("strongpass"),
            is_active=True, is_verified=False)
        await store.create(user)
        with pytest.raises(EmailNotVerified):
            await login_flow("uv@x.com", "strongpass",
                store=store, config=config, password_handler=pw, jwt_handler=jwt)

    @pytest.mark.asyncio
    async def test_inactive_blocked(self, store, config_no_verify, pw, jwt, notif):
        await _reg_active("ia@x.com", "pass1234", store, config_no_verify, pw, notif)
        user = await store.get_by_email("ia@x.com")
        user.is_active = False
        await store.update(user)
        with pytest.raises(AccountInactive):
            await login_flow("ia@x.com", "pass1234",
                store=store, config=config_no_verify, password_handler=pw, jwt_handler=jwt)

    @pytest.mark.asyncio
    async def test_token_verifiable(self, store, config_no_verify, pw, jwt, notif):
        await _reg_active("tv@x.com", "pass1234", store, config_no_verify, pw, notif)
        pair, user = await login_flow("tv@x.com", "pass1234",
            store=store, config=config_no_verify, password_handler=pw, jwt_handler=jwt)
        payload = await jwt.verify_token(pair.access_token)
        assert payload.sub == user.id


class TestLogoutFlow:
    @pytest.mark.asyncio
    async def test_blacklists_access(self, store, config_no_verify, pw, jwt, notif):
        await _reg_active("lo@x.com", "pass1234", store, config_no_verify, pw, notif)
        pair, _ = await login_flow("lo@x.com", "pass1234",
            store=store, config=config_no_verify, password_handler=pw, jwt_handler=jwt)
        await logout_flow(pair.access_token, jwt_handler=jwt)
        with pytest.raises(TokenRevoked):
            await jwt.verify_token(pair.access_token)

    @pytest.mark.asyncio
    async def test_blacklists_refresh(self, store, config_no_verify, pw, jwt, notif):
        await _reg_active("lor@x.com", "pass1234", store, config_no_verify, pw, notif)
        pair, _ = await login_flow("lor@x.com", "pass1234",
            store=store, config=config_no_verify, password_handler=pw, jwt_handler=jwt)
        await logout_flow(pair.access_token, jwt_handler=jwt, refresh_token=pair.refresh_token)
        with pytest.raises(TokenRevoked):
            await jwt.verify_token(pair.refresh_token, expected_type="refresh")


class TestRefreshFlow:
    @pytest.mark.asyncio
    async def test_returns_new_pair(self, store, config_no_verify, pw, jwt, notif):
        await _reg_active("rf@x.com", "pass1234", store, config_no_verify, pw, notif)
        pair, _ = await login_flow("rf@x.com", "pass1234",
            store=store, config=config_no_verify, password_handler=pw, jwt_handler=jwt)
        new_pair = await refresh_flow(pair.refresh_token,
            store=store, config=config_no_verify, jwt_handler=jwt)
        assert new_pair.access_token != pair.access_token

    @pytest.mark.asyncio
    async def test_rotation_blacklists_old(self, store, config_no_verify, pw, jwt, notif):
        await _reg_active("rfr@x.com", "pass1234", store, config_no_verify, pw, notif)
        pair, _ = await login_flow("rfr@x.com", "pass1234",
            store=store, config=config_no_verify, password_handler=pw, jwt_handler=jwt)
        await refresh_flow(pair.refresh_token, store=store, config=config_no_verify, jwt_handler=jwt)
        with pytest.raises(TokenRevoked):
            await jwt.verify_token(pair.refresh_token, expected_type="refresh")

    @pytest.mark.asyncio
    async def test_invalid_token(self, store, config_no_verify, jwt):
        with pytest.raises(InvalidToken):
            await refresh_flow("garbage", store=store, config=config_no_verify, jwt_handler=jwt)

    @pytest.mark.asyncio
    async def test_revoked_token(self, store, config_no_verify, pw, jwt, notif):
        await _reg_active("rrev@x.com", "pass1234", store, config_no_verify, pw, notif)
        pair, _ = await login_flow("rrev@x.com", "pass1234",
            store=store, config=config_no_verify, password_handler=pw, jwt_handler=jwt)
        await logout_flow(pair.access_token, jwt_handler=jwt, refresh_token=pair.refresh_token)
        with pytest.raises(TokenRevoked):
            await refresh_flow(pair.refresh_token, store=store, config=config_no_verify, jwt_handler=jwt)


class TestForgotPasswordFlow:
    @pytest.mark.asyncio
    async def test_sends_link(self, store, config_no_verify, pw, jwt, notif):
        await _reg_active("fp@x.com", "pass1234", store, config_no_verify, pw, notif)
        notif.clear()
        await forgot_password_flow("fp@x.com", store=store, config=config_no_verify, notification_service=notif)
        assert "send_password_reset_link" in notif.methods_called()

    @pytest.mark.asyncio
    async def test_sends_otp(self, store, config_reset_otp, pw, notif):
        await _reg_active("fpo@x.com", "pass1234", store, config_reset_otp, pw, notif)
        notif.clear()
        await forgot_password_flow("fpo@x.com", store=store, config=config_reset_otp, notification_service=notif)
        assert "send_password_reset_otp" in notif.methods_called()
        assert notif.last_otp.isdigit()

    @pytest.mark.asyncio
    async def test_unknown_silent(self, store, config_no_verify, notif):
        await forgot_password_flow("ghost@x.com", store=store, config=config_no_verify, notification_service=notif)
        assert notif.count() == 0

    @pytest.mark.asyncio
    async def test_rate_limited(self, store, config_no_verify, pw, jwt, notif):
        await _reg_active("rl2@x.com", "pass1234", store, config_no_verify, pw, notif)
        await forgot_password_flow("rl2@x.com", store=store, config=config_no_verify, notification_service=notif)
        with pytest.raises(RateLimited):
            await forgot_password_flow("rl2@x.com", store=store, config=config_no_verify, notification_service=notif)

    @pytest.mark.asyncio
    async def test_stores_token_hash(self, store, config_no_verify, pw, jwt, notif):
        await _reg_active("fph@x.com", "pass1234", store, config_no_verify, pw, notif)
        await forgot_password_flow("fph@x.com", store=store, config=config_no_verify, notification_service=notif)
        user = await store.get_by_email("fph@x.com")
        assert user.reset_token_hash is not None and user.reset_token_used_at is None


class TestResetPasswordLinkFlow:
    @pytest.mark.asyncio
    async def test_success(self, store, config_no_verify, pw, jwt, notif):
        await _reg_active("rp@x.com", "oldpassword", store, config_no_verify, pw, notif)
        await forgot_password_flow("rp@x.com", store=store, config=config_no_verify, notification_service=notif)
        tok = extract_token(notif.last_link)
        await reset_password_flow(tok, "newpassword",
            store=store, config=config_no_verify, password_handler=pw, notification_service=notif)
        user = await store.get_by_email("rp@x.com")
        assert pw.verify_password("newpassword", user.hashed_password)

    @pytest.mark.asyncio
    async def test_invalid_token(self, store, config_no_verify, pw, notif):
        with pytest.raises(InvalidToken):
            await reset_password_flow("bad.tok", "newpass",
                store=store, config=config_no_verify, password_handler=pw, notification_service=notif)

    @pytest.mark.asyncio
    async def test_already_used(self, store, config_no_verify, pw, jwt, notif):
        await _reg_active("ru@x.com", "oldpassword", store, config_no_verify, pw, notif)
        await forgot_password_flow("ru@x.com", store=store, config=config_no_verify, notification_service=notif)
        tok = extract_token(notif.last_link)
        await reset_password_flow(tok, "newpass1",
            store=store, config=config_no_verify, password_handler=pw, notification_service=notif)
        with pytest.raises(TokenAlreadyUsed):
            await reset_password_flow(tok, "newpass2",
                store=store, config=config_no_verify, password_handler=pw, notification_service=notif)

    @pytest.mark.asyncio
    async def test_same_password(self, store, config_no_verify, pw, jwt, notif):
        await _reg_active("rs@x.com", "samepass", store, config_no_verify, pw, notif)
        await forgot_password_flow("rs@x.com", store=store, config=config_no_verify, notification_service=notif)
        tok = extract_token(notif.last_link)
        with pytest.raises(SamePassword):
            await reset_password_flow(tok, "samepass",
                store=store, config=config_no_verify, password_handler=pw, notification_service=notif)

    @pytest.mark.asyncio
    async def test_weak_password(self, store, config_no_verify, pw, jwt, notif):
        await _reg_active("rw@x.com", "oldpassword", store, config_no_verify, pw, notif)
        await forgot_password_flow("rw@x.com", store=store, config=config_no_verify, notification_service=notif)
        tok = extract_token(notif.last_link)
        with pytest.raises(WeakPassword):
            await reset_password_flow(tok, "x",
                store=store, config=config_no_verify, password_handler=pw, notification_service=notif)

    @pytest.mark.asyncio
    async def test_sends_confirmation(self, store, config_no_verify, pw, jwt, notif):
        await _reg_active("rc@x.com", "oldpassword", store, config_no_verify, pw, notif)
        await forgot_password_flow("rc@x.com", store=store, config=config_no_verify, notification_service=notif)
        tok = extract_token(notif.last_link)
        notif.clear()
        await reset_password_flow(tok, "newpassword",
            store=store, config=config_no_verify, password_handler=pw, notification_service=notif)
        assert "send_password_changed" in notif.methods_called()


class TestResetPasswordOtpFlow:
    @pytest.mark.asyncio
    async def test_success(self, store, config_reset_otp, pw, notif):
        await _reg_active("roo@x.com", "oldpassword", store, config_reset_otp, pw, notif)
        await forgot_password_flow("roo@x.com", store=store, config=config_reset_otp, notification_service=notif)
        otp = notif.last_otp
        await reset_password_otp_flow("roo@x.com", otp, "newpassword",
            store=store, config=config_reset_otp, password_handler=pw, notification_service=notif)
        user = await store.get_by_email("roo@x.com")
        assert pw.verify_password("newpassword", user.hashed_password)

    @pytest.mark.asyncio
    async def test_wrong_otp(self, store, config_reset_otp, pw, notif):
        await _reg_active("row@x.com", "oldpassword", store, config_reset_otp, pw, notif)
        await forgot_password_flow("row@x.com", store=store, config=config_reset_otp, notification_service=notif)
        with pytest.raises(InvalidToken):
            await reset_password_otp_flow("row@x.com", "000000", "newpass",
                store=store, config=config_reset_otp, password_handler=pw, notification_service=notif)

    @pytest.mark.asyncio
    async def test_expired_otp(self, store, config_reset_otp, pw, notif):
        await _reg_active("roe@x.com", "oldpassword", store, config_reset_otp, pw, notif)
        await forgot_password_flow("roe@x.com", store=store, config=config_reset_otp, notification_service=notif)
        user = await store.get_by_email("roe@x.com")
        user.reset_otp_expires_at = utcnow() - timedelta(seconds=1)
        await store.update(user)
        with pytest.raises(TokenExpired):
            await reset_password_otp_flow("roe@x.com", notif.last_otp, "newpass",
                store=store, config=config_reset_otp, password_handler=pw, notification_service=notif)

    @pytest.mark.asyncio
    async def test_same_password(self, store, config_reset_otp, pw, notif):
        await _reg_active("ros@x.com", "samepass", store, config_reset_otp, pw, notif)
        await forgot_password_flow("ros@x.com", store=store, config=config_reset_otp, notification_service=notif)
        with pytest.raises(SamePassword):
            await reset_password_otp_flow("ros@x.com", notif.last_otp, "samepass",
                store=store, config=config_reset_otp, password_handler=pw, notification_service=notif)

    @pytest.mark.asyncio
    async def test_by_phone(self, store, config_reset_otp, pw, notif):
        user = UserInDB(email="rop@x.com", phone_number="+2349988776655",
            hashed_password=pw.hash_password("oldpassword"), is_active=True, is_verified=True)
        await store.create(user)
        await forgot_password_flow("+2349988776655", store=store, config=config_reset_otp, notification_service=notif)
        otp = notif.last_otp
        await reset_password_otp_flow("+2349988776655", otp, "newpassword",
            store=store, config=config_reset_otp, password_handler=pw, notification_service=notif)
        updated = await store.get_by_phone("+2349988776655")
        assert pw.verify_password("newpassword", updated.hashed_password)


class TestChangePasswordFlow:
    @pytest.mark.asyncio
    async def test_success(self, store, config_no_verify, pw, jwt, notif):
        await _reg_active("cp@x.com", "oldpassword", store, config_no_verify, pw, notif)
        user = await store.get_by_email("cp@x.com")
        new_pair = await change_password_flow(user.id, "oldpassword", "newpassword",
            store=store, config=config_no_verify, password_handler=pw,
            jwt_handler=jwt, notification_service=notif)
        assert new_pair.access_token
        updated = await store.get_by_email("cp@x.com")
        assert pw.verify_password("newpassword", updated.hashed_password)

    @pytest.mark.asyncio
    async def test_wrong_current(self, store, config_no_verify, pw, jwt, notif):
        await _reg_active("cwc@x.com", "correctpass", store, config_no_verify, pw, notif)
        user = await store.get_by_email("cwc@x.com")
        with pytest.raises(InvalidCredentials):
            await change_password_flow(user.id, "wrong", "newpass",
                store=store, config=config_no_verify, password_handler=pw,
                jwt_handler=jwt, notification_service=notif)

    @pytest.mark.asyncio
    async def test_same_password(self, store, config_no_verify, pw, jwt, notif):
        await _reg_active("csp@x.com", "samepass", store, config_no_verify, pw, notif)
        user = await store.get_by_email("csp@x.com")
        with pytest.raises(SamePassword):
            await change_password_flow(user.id, "samepass", "samepass",
                store=store, config=config_no_verify, password_handler=pw,
                jwt_handler=jwt, notification_service=notif)

    @pytest.mark.asyncio
    async def test_weak_new_password(self, store, config_no_verify, pw, jwt, notif):
        await _reg_active("cwp@x.com", "goodpass", store, config_no_verify, pw, notif)
        user = await store.get_by_email("cwp@x.com")
        with pytest.raises(WeakPassword):
            await change_password_flow(user.id, "goodpass", "x",
                store=store, config=config_no_verify, password_handler=pw,
                jwt_handler=jwt, notification_service=notif)

    @pytest.mark.asyncio
    async def test_no_password_set(self, store, config_no_verify, pw, jwt, notif):
        oauth_user = UserInDB(email="oauth@x.com", hashed_password=None, is_active=True, is_verified=True)
        await store.create(oauth_user)
        with pytest.raises(PasswordNotSet):
            await change_password_flow(oauth_user.id, "x", "newpass",
                store=store, config=config_no_verify, password_handler=pw,
                jwt_handler=jwt, notification_service=notif)

    @pytest.mark.asyncio
    async def test_user_not_found(self, store, config_no_verify, pw, jwt, notif):
        with pytest.raises(UserNotFound):
            await change_password_flow("bad-id", "x", "newpass",
                store=store, config=config_no_verify, password_handler=pw,
                jwt_handler=jwt, notification_service=notif)

    @pytest.mark.asyncio
    async def test_sends_confirmation(self, store, config_no_verify, pw, jwt, notif):
        await _reg_active("cconf@x.com", "oldpassword", store, config_no_verify, pw, notif)
        user = await store.get_by_email("cconf@x.com")
        notif.clear()
        await change_password_flow(user.id, "oldpassword", "newpassword",
            store=store, config=config_no_verify, password_handler=pw,
            jwt_handler=jwt, notification_service=notif)
        assert "send_password_changed" in notif.methods_called()

    @pytest.mark.asyncio
    async def test_returns_valid_token(self, store, config_no_verify, pw, jwt, notif):
        await _reg_active("cvt@x.com", "oldpassword", store, config_no_verify, pw, notif)
        user = await store.get_by_email("cvt@x.com")
        new_pair = await change_password_flow(user.id, "oldpassword", "newpassword",
            store=store, config=config_no_verify, password_handler=pw,
            jwt_handler=jwt, notification_service=notif)
        payload = await jwt.verify_token(new_pair.access_token)
        assert payload.sub == user.id


class TestNotificationServiceRouting:
    @pytest.mark.asyncio
    async def test_otp_to_email(self):
        stream = io.StringIO()
        svc = NotificationService(
            config=WardenConfig(secret_key="s", otp_ttl=600),
            email_backend=ConsoleEmailBackend(stream=stream))
        user = UserInDB(email="n@x.com")
        await svc.send_verification_otp(user, "123456")
        assert "123456" in stream.getvalue()

    @pytest.mark.asyncio
    async def test_otp_to_sms(self):
        stream = io.StringIO()
        svc = NotificationService(
            config=WardenConfig(secret_key="s", otp_ttl=600, verification_channels=["sms"]),
            sms_backend=ConsoleSmsBackend(stream=stream))
        user = UserInDB(email="ns@x.com", phone_number="+2341234567890")
        await svc.send_verification_otp(user, "654321")
        assert "654321" in stream.getvalue()

    @pytest.mark.asyncio
    async def test_skips_sms_if_no_phone(self):
        stream = io.StringIO()
        svc = NotificationService(
            config=WardenConfig(secret_key="s", otp_ttl=600, verification_channels=["sms"]),
            sms_backend=ConsoleSmsBackend(stream=stream))
        user = UserInDB(email="nophone@x.com")  # no phone
        await svc.send_verification_otp(user, "999999")
        assert stream.getvalue() == ""

    @pytest.mark.asyncio
    async def test_both_channels(self):
        es, ss = io.StringIO(), io.StringIO()
        svc = NotificationService(
            config=WardenConfig(secret_key="s", otp_ttl=600, verification_channels=["email","sms"]),
            email_backend=ConsoleEmailBackend(stream=es),
            sms_backend=ConsoleSmsBackend(stream=ss))
        user = UserInDB(email="both@x.com", phone_number="+2341112223334")
        await svc.send_verification_otp(user, "111222")
        assert "111222" in es.getvalue() and "111222" in ss.getvalue()

    def test_sms_templates_overridable(self):
        class My(SmsTemplates):
            def verify_otp(self, u, otp, mins): return f"[CUSTOM] {otp}"
        t = My()
        assert t.verify_otp(UserInDB(email="t@x.com"), "123", 10) == "[CUSTOM] 123"

    def test_email_templates_overridable(self):
        class My(EmailTemplates):
            def verify_otp(self, u, otp, mins): return "custom", f"code:{otp}", "<b>x</b>"
        s, p, h = My().verify_otp(UserInDB(email="t@x.com"), "999", 5)
        assert "999" in p


class TestStorageFlexibility:
    @pytest.mark.asyncio
    async def test_get_by_username(self, store):
        user = UserInDB(email="u@x.com", username="testuser")
        await store.create(user)
        found = await store.get_by_username("testuser")
        assert found is not None

    @pytest.mark.asyncio
    async def test_username_case_insensitive(self, store):
        user = UserInDB(email="ci@x.com", username="TestUser")
        await store.create(user)
        assert await store.get_by_username("testuser") is not None

    @pytest.mark.asyncio
    async def test_get_by_phone(self, store):
        user = UserInDB(email="p@x.com", phone_number="+2341234567890")
        await store.create(user)
        assert await store.get_by_phone("+2341234567890") is not None

    @pytest.mark.asyncio
    async def test_phone_index_updated_on_update(self, store):
        user = UserInDB(email="pi@x.com", phone_number="+111")
        await store.create(user)
        user.phone_number = "+222"
        await store.update(user)
        assert await store.get_by_phone("+111") is None
        assert await store.get_by_phone("+222") is not None

    def test_extra_data(self):
        user = UserInDB(email="ex@x.com", extra_data={"tier": "pro", "company": "acme"})
        assert user.extra_data["tier"] == "pro"

    def test_user_subclass(self):
        class MyUser(UserInDB):
            company_id: str | None = None
            tier: str = "free"
        user = MyUser(email="my@x.com", company_id="xyz", tier="pro")
        assert user.company_id == "xyz"
        read = user.to_read()
        assert read.email == "my@x.com"