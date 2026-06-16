"""Phase 4 tests — MFA, Permissions, Security fixes."""
from __future__ import annotations
from datetime import timedelta
import pytest
import pyotp

from authwarden.authentication.jwt import JWTHandler, MemoryTokenBlacklist
from authwarden.authentication.password import PasswordHandler
from authwarden.core.config import WardenConfig
from authwarden.exceptions import (
    AccountLocked, EmailAlreadyExists, ForbiddenError,
    InvalidCredentials, InvalidMFACode, InvalidToken,
    MFAAlreadyEnabled, MFANotEnabled, MFARequired,
    PhoneAlreadyExists, TokenExpired, UsernameAlreadyExists, UserNotFound,
)
from authwarden.flows.login import login_flow
from authwarden.flows.register import register_flow
from authwarden.flows.verify_otp import verify_otp_flow
from authwarden.flows.reset_password_otp import reset_password_otp_flow
from authwarden.flows.forgot_password import forgot_password_flow
from authwarden.mfa.backup_codes import consume_backup_code
from authwarden.mfa.totp import confirm_mfa_flow, disable_mfa_flow, setup_mfa_flow
from authwarden.models.token import TokenPayload
from authwarden.models.user import UserCreate, UserInDB
from authwarden.permissions.policies import has_scope, require_scopes
from authwarden.permissions.roles import (
    has_min_role, has_role, require_min_role, require_roles,
)
from authwarden.storage.memory import MemoryUserStore
from authwarden.utils import generate_otp, hash_token, utcnow


class MockNotificationService:
    def __init__(self): self.calls: list[str] = []
    async def send_verification_link(self, u, link): self.calls.append("link")
    async def send_verification_otp(self, u, otp): self.calls.append(f"otp:{otp}")
    async def send_welcome(self, u): self.calls.append("welcome")
    async def send_password_reset_link(self, u, link): self.calls.append("reset_link")
    async def send_password_reset_otp(self, u, otp): self.calls.append(f"reset_otp:{otp}")
    async def send_password_changed(self, u): self.calls.append("pw_changed")
    async def send_mfa_enabled(self, u): self.calls.append("mfa_enabled")
    async def send_mfa_disabled(self, u): self.calls.append("mfa_disabled")

    @property
    def last_otp(self):
        for c in reversed(self.calls):
            if c.startswith("otp:") or c.startswith("reset_otp:"):
                return c.split(":", 1)[1]
        raise AssertionError("No OTP sent")


@pytest.fixture
def config():
    return WardenConfig(secret_key="phase4-secret", require_email_verification=False)

@pytest.fixture
def config_mfa():
    return WardenConfig(secret_key="phase4-secret", require_email_verification=False, enable_mfa=True)

@pytest.fixture
def config_lockout():
    return WardenConfig(secret_key="phase4-secret", require_email_verification=False,
                        max_failed_attempts=3, login_lockout_duration=900)

@pytest.fixture
def config_otp_limit():
    return WardenConfig(secret_key="phase4-secret", require_email_verification=True,
                        verification_method="otp", otp_length=6, otp_ttl=600, max_otp_attempts=3)

@pytest.fixture
def store(): return MemoryUserStore()
@pytest.fixture
def notif(): return MockNotificationService()
@pytest.fixture
def pw(config): return PasswordHandler(config)
@pytest.fixture
def jwt(config): return JWTHandler(config, blacklist=MemoryTokenBlacklist())


def make_payload(roles=None, scopes=None) -> TokenPayload:
    return TokenPayload(sub="uid", jti="jti", type="access",
                        roles=roles or [], scopes=scopes or [],
                        exp=9999999999, iat=1000000000)


async def _create_active_user(email, password, store, config, pw, notif,
                               username=None, phone=None):
    data = UserCreate(email=email, password=password, username=username, phone_number=phone)
    return await register_flow(data, store=store, config=config,
                                password_handler=pw, notification_service=notif)


# ══════════════════════════════════════════════════════════════════
# UNIQUENESS CHECKS ON REGISTRATION
# ══════════════════════════════════════════════════════════════════

class TestRegistrationUniqueness:

    @pytest.mark.asyncio
    async def test_duplicate_email_rejected(self, store, config, pw, notif):
        await _create_active_user("a@x.com", "strongpass", store, config, pw, notif)
        with pytest.raises(EmailAlreadyExists):
            await _create_active_user("a@x.com", "anotherpass", store, config, pw, notif)

    @pytest.mark.asyncio
    async def test_duplicate_username_rejected(self, store, config, pw, notif):
        await _create_active_user("a@x.com", "strongpass", store, config, pw, notif, username="johndoe")
        with pytest.raises(UsernameAlreadyExists):
            await _create_active_user("b@x.com", "strongpass", store, config, pw, notif, username="johndoe")

    @pytest.mark.asyncio
    async def test_duplicate_phone_rejected(self, store, config, pw, notif):
        await _create_active_user("a@x.com", "strongpass", store, config, pw, notif, phone="+2348012345678")
        with pytest.raises(PhoneAlreadyExists):
            await _create_active_user("b@x.com", "strongpass", store, config, pw, notif, phone="+2348012345678")

    @pytest.mark.asyncio
    async def test_unique_identifiers_allowed(self, store, config, pw, notif):
        await _create_active_user("a@x.com", "strongpass", store, config, pw, notif,
                                   username="user1", phone="+111")
        r = await _create_active_user("b@x.com", "strongpass", store, config, pw, notif,
                                       username="user2", phone="+222")
        assert r.email == "b@x.com"

    @pytest.mark.asyncio
    async def test_no_username_no_uniqueness_check(self, store, config, pw, notif):
        """Username uniqueness only checked when username is provided."""
        r1 = await _create_active_user("a@x.com", "strongpass", store, config, pw, notif)
        r2 = await _create_active_user("b@x.com", "strongpass", store, config, pw, notif)
        assert r1 and r2  # no error


# ══════════════════════════════════════════════════════════════════
# BRUTE FORCE — LOGIN
# ══════════════════════════════════════════════════════════════════

class TestLoginBruteForce:

    @pytest.mark.asyncio
    async def test_failed_attempts_incremented(self, store, config_lockout, pw, notif):
        jwt2 = JWTHandler(config_lockout, blacklist=MemoryTokenBlacklist())
        await _create_active_user("bf@x.com", "correctpass", store, config_lockout, pw, notif)
        for _ in range(2):
            try:
                await login_flow("bf@x.com", "wrongpass",
                    store=store, config=config_lockout, password_handler=pw, jwt_handler=jwt2)
            except InvalidCredentials:
                pass
        user = await store.get_by_email("bf@x.com")
        assert user.failed_login_attempts == 2

    @pytest.mark.asyncio
    async def test_account_locked_after_max_attempts(self, store, config_lockout, pw, notif):
        jwt2 = JWTHandler(config_lockout, blacklist=MemoryTokenBlacklist())
        await _create_active_user("lock@x.com", "correctpass", store, config_lockout, pw, notif)
        for _ in range(3):
            try:
                await login_flow("lock@x.com", "wrongpass",
                    store=store, config=config_lockout, password_handler=pw, jwt_handler=jwt2)
            except InvalidCredentials:
                pass
        with pytest.raises(AccountLocked):
            await login_flow("lock@x.com", "correctpass",
                store=store, config=config_lockout, password_handler=pw, jwt_handler=jwt2)

    @pytest.mark.asyncio
    async def test_locked_until_set(self, store, config_lockout, pw, notif):
        jwt2 = JWTHandler(config_lockout, blacklist=MemoryTokenBlacklist())
        await _create_active_user("lu@x.com", "correctpass", store, config_lockout, pw, notif)
        for _ in range(3):
            try:
                await login_flow("lu@x.com", "wrongpass",
                    store=store, config=config_lockout, password_handler=pw, jwt_handler=jwt2)
            except InvalidCredentials:
                pass
        user = await store.get_by_email("lu@x.com")
        assert user.locked_until is not None
        assert user.locked_until > utcnow()

    @pytest.mark.asyncio
    async def test_counter_resets_on_success(self, store, config_lockout, pw, notif):
        jwt2 = JWTHandler(config_lockout, blacklist=MemoryTokenBlacklist())
        await _create_active_user("rst@x.com", "correctpass", store, config_lockout, pw, notif)
        for _ in range(2):
            try:
                await login_flow("rst@x.com", "wrongpass",
                    store=store, config=config_lockout, password_handler=pw, jwt_handler=jwt2)
            except InvalidCredentials:
                pass
        await login_flow("rst@x.com", "correctpass",
            store=store, config=config_lockout, password_handler=pw, jwt_handler=jwt2)
        user = await store.get_by_email("rst@x.com")
        assert user.failed_login_attempts == 0
        assert user.locked_until is None

    @pytest.mark.asyncio
    async def test_expired_lockout_allows_login(self, store, config_lockout, pw, notif):
        jwt2 = JWTHandler(config_lockout, blacklist=MemoryTokenBlacklist())
        await _create_active_user("exp@x.com", "correctpass", store, config_lockout, pw, notif)
        # Manually set an expired lockout
        user = await store.get_by_email("exp@x.com")
        user.locked_until = utcnow() - timedelta(seconds=1)
        user.failed_login_attempts = 3
        await store.update(user)
        # Should succeed since lockout expired
        pair, _ = await login_flow("exp@x.com", "correctpass",
            store=store, config=config_lockout, password_handler=pw, jwt_handler=jwt2)
        assert pair.access_token

    @pytest.mark.asyncio
    async def test_no_lockout_when_disabled(self, store, config, pw, jwt, notif):
        """max_login_attempts=0 disables lockout."""
        cfg = WardenConfig(secret_key="s", require_email_verification=False, max_failed_attempts=0)
        jwt2 = JWTHandler(cfg, blacklist=MemoryTokenBlacklist())
        await _create_active_user("nd@x.com", "correctpass", store, cfg, pw, notif)
        for _ in range(10):
            try:
                await login_flow("nd@x.com", "wrongpass",
                    store=store, config=cfg, password_handler=pw, jwt_handler=jwt2)
            except InvalidCredentials:
                pass
        user = await store.get_by_email("nd@x.com")
        assert user.locked_until is None


# ══════════════════════════════════════════════════════════════════
# BRUTE FORCE — OTP
# ══════════════════════════════════════════════════════════════════

class TestOtpBruteForce:

    @pytest.mark.asyncio
    async def test_otp_attempt_incremented(self, store, config_otp_limit, pw, notif):
        await register_flow(UserCreate(email="oa@x.com", password="strongpass"),
            store=store, config=config_otp_limit, password_handler=pw, notification_service=notif)
        for _ in range(2):
            try:
                await verify_otp_flow("oa@x.com", "000000",
                    store=store, config=config_otp_limit, notification_service=notif)
            except InvalidToken:
                pass
        user = await store.get_by_email("oa@x.com")
        assert user.verification_otp_attempts == 2

    @pytest.mark.asyncio
    async def test_otp_invalidated_after_max_attempts(self, store, config_otp_limit, pw, notif):
        await register_flow(UserCreate(email="om@x.com", password="strongpass"),
            store=store, config=config_otp_limit, password_handler=pw, notification_service=notif)
        for _ in range(3):
            try:
                await verify_otp_flow("om@x.com", "000000",
                    store=store, config=config_otp_limit, notification_service=notif)
            except (InvalidToken, TokenExpired):
                pass
        user = await store.get_by_email("om@x.com")
        assert user.verification_otp_hash is None
        assert user.verification_otp_attempts == 0

    @pytest.mark.asyncio
    async def test_otp_attempt_reset_on_success(self, store, config_otp_limit, pw, notif):
        await register_flow(UserCreate(email="ok@x.com", password="strongpass"),
            store=store, config=config_otp_limit, password_handler=pw, notification_service=notif)
        # 1 wrong attempt
        try:
            await verify_otp_flow("ok@x.com", "000000",
                store=store, config=config_otp_limit, notification_service=notif)
        except InvalidToken:
            pass
        # Get the real OTP
        user = await store.get_by_email("ok@x.com")
        # Inject known OTP
        otp = generate_otp(6)
        user.verification_otp_hash = hash_token(otp)
        await store.update(user)
        await verify_otp_flow("ok@x.com", otp,
            store=store, config=config_otp_limit, notification_service=notif)
        user = await store.get_by_email("ok@x.com")
        assert user.verification_otp_attempts == 0


# ══════════════════════════════════════════════════════════════════
# MFA — SETUP
# ══════════════════════════════════════════════════════════════════

class TestMFASetup:

    @pytest.mark.asyncio
    async def test_setup_returns_result(self, store, config, pw, notif):
        await _create_active_user("s@x.com", "strongpass", store, config, pw, notif)
        user = await store.get_by_email("s@x.com")
        result = await setup_mfa_flow(user.id, store=store, config=config, password_handler=pw)
        assert result.secret
        assert result.qr_uri
        assert len(result.backup_codes) == 8
        assert all(len(c) == 8 for c in result.backup_codes)

    @pytest.mark.asyncio
    async def test_setup_stores_pending_secret(self, store, config, pw, notif):
        await _create_active_user("sp@x.com", "strongpass", store, config, pw, notif)
        user = await store.get_by_email("sp@x.com")
        await setup_mfa_flow(user.id, store=store, config=config, password_handler=pw)
        updated = await store.get_by_id(user.id)
        assert updated.mfa_pending_secret is not None
        assert updated.mfa_enabled is False  # not yet confirmed

    @pytest.mark.asyncio
    async def test_setup_stores_hashed_backup_codes(self, store, config, pw, notif):
        await _create_active_user("sh@x.com", "strongpass", store, config, pw, notif)
        user = await store.get_by_email("sh@x.com")
        result = await setup_mfa_flow(user.id, store=store, config=config, password_handler=pw)
        updated = await store.get_by_id(user.id)
        # stored codes are hashes, not plaintext
        assert updated.backup_codes[0] != result.backup_codes[0]

    @pytest.mark.asyncio
    async def test_setup_user_not_found(self, store, config, pw):
        with pytest.raises(UserNotFound):
            await setup_mfa_flow("bad-id", store=store, config=config, password_handler=pw)

    @pytest.mark.asyncio
    async def test_setup_already_enabled(self, store, config, pw, notif):
        await _create_active_user("ae@x.com", "strongpass", store, config, pw, notif)
        user = await store.get_by_email("ae@x.com")
        user.mfa_enabled = True
        await store.update(user)
        with pytest.raises(MFAAlreadyEnabled):
            await setup_mfa_flow(user.id, store=store, config=config, password_handler=pw)


# ══════════════════════════════════════════════════════════════════
# MFA — CONFIRM
# ══════════════════════════════════════════════════════════════════

class TestMFAConfirm:

    @pytest.mark.asyncio
    async def test_confirm_activates_mfa(self, store, config, pw, notif):
        await _create_active_user("c@x.com", "strongpass", store, config, pw, notif)
        user = await store.get_by_email("c@x.com")
        result = await setup_mfa_flow(user.id, store=store, config=config, password_handler=pw)
        totp_code = pyotp.TOTP(result.secret).now()
        await confirm_mfa_flow(user.id, totp_code, store=store, notification_service=notif)
        updated = await store.get_by_id(user.id)
        assert updated.mfa_enabled is True
        assert updated.mfa_secret == result.secret
        assert updated.mfa_pending_secret is None

    @pytest.mark.asyncio
    async def test_confirm_wrong_code(self, store, config, pw, notif):
        await _create_active_user("cw@x.com", "strongpass", store, config, pw, notif)
        user = await store.get_by_email("cw@x.com")
        await setup_mfa_flow(user.id, store=store, config=config, password_handler=pw)
        with pytest.raises(InvalidMFACode):
            await confirm_mfa_flow(user.id, "000000", store=store, notification_service=notif)

    @pytest.mark.asyncio
    async def test_confirm_sends_notification(self, store, config, pw, notif):
        await _create_active_user("cn@x.com", "strongpass", store, config, pw, notif)
        user = await store.get_by_email("cn@x.com")
        result = await setup_mfa_flow(user.id, store=store, config=config, password_handler=pw)
        code = pyotp.TOTP(result.secret).now()
        await confirm_mfa_flow(user.id, code, store=store, notification_service=notif)
        assert "mfa_enabled" in notif.calls

    @pytest.mark.asyncio
    async def test_confirm_without_setup_raises(self, store, config, pw, notif):
        await _create_active_user("ns@x.com", "strongpass", store, config, pw, notif)
        user = await store.get_by_email("ns@x.com")
        with pytest.raises(InvalidMFACode):
            await confirm_mfa_flow(user.id, "123456", store=store, notification_service=notif)


# ══════════════════════════════════════════════════════════════════
# MFA — DISABLE
# ══════════════════════════════════════════════════════════════════

class TestMFADisable:

    async def _setup_and_confirm(self, user_id, store, config, pw, notif):
        result = await setup_mfa_flow(user_id, store=store, config=config, password_handler=pw)
        code = pyotp.TOTP(result.secret).now()
        await confirm_mfa_flow(user_id, code, store=store, notification_service=notif)
        return result

    @pytest.mark.asyncio
    async def test_disable_with_totp(self, store, config, pw, notif):
        await _create_active_user("d@x.com", "strongpass", store, config, pw, notif)
        user = await store.get_by_email("d@x.com")
        result = await self._setup_and_confirm(user.id, store, config, pw, notif)
        totp_code = pyotp.TOTP(result.secret).now()
        await disable_mfa_flow(user.id, "strongpass", totp_code,
            store=store, password_handler=pw, notification_service=notif)
        updated = await store.get_by_id(user.id)
        assert updated.mfa_enabled is False
        assert updated.mfa_secret is None
        assert updated.backup_codes == []

    @pytest.mark.asyncio
    async def test_disable_with_backup_code(self, store, config, pw, notif):
        await _create_active_user("db@x.com", "strongpass", store, config, pw, notif)
        user = await store.get_by_email("db@x.com")
        result = await self._setup_and_confirm(user.id, store, config, pw, notif)
        backup_code = result.backup_codes[0]
        await disable_mfa_flow(user.id, "strongpass", backup_code,
            store=store, password_handler=pw, notification_service=notif)
        updated = await store.get_by_id(user.id)
        assert updated.mfa_enabled is False

    @pytest.mark.asyncio
    async def test_disable_wrong_password(self, store, config, pw, notif):
        await _create_active_user("dp@x.com", "strongpass", store, config, pw, notif)
        user = await store.get_by_email("dp@x.com")
        result = await self._setup_and_confirm(user.id, store, config, pw, notif)
        code = pyotp.TOTP(result.secret).now()
        with pytest.raises(InvalidCredentials):
            await disable_mfa_flow(user.id, "wrongpass", code,
                store=store, password_handler=pw, notification_service=notif)

    @pytest.mark.asyncio
    async def test_disable_wrong_totp(self, store, config, pw, notif):
        await _create_active_user("dt@x.com", "strongpass", store, config, pw, notif)
        user = await store.get_by_email("dt@x.com")
        await self._setup_and_confirm(user.id, store, config, pw, notif)
        with pytest.raises(InvalidMFACode):
            await disable_mfa_flow(user.id, "strongpass", "000000",
                store=store, password_handler=pw, notification_service=notif)

    @pytest.mark.asyncio
    async def test_disable_not_enabled(self, store, config, pw, notif):
        await _create_active_user("dne@x.com", "strongpass", store, config, pw, notif)
        user = await store.get_by_email("dne@x.com")
        with pytest.raises(MFANotEnabled):
            await disable_mfa_flow(user.id, "strongpass", "123456",
                store=store, password_handler=pw, notification_service=notif)

    @pytest.mark.asyncio
    async def test_disable_sends_notification(self, store, config, pw, notif):
        await _create_active_user("dn@x.com", "strongpass", store, config, pw, notif)
        user = await store.get_by_email("dn@x.com")
        result = await self._setup_and_confirm(user.id, store, config, pw, notif)
        code = pyotp.TOTP(result.secret).now()
        await disable_mfa_flow(user.id, "strongpass", code,
            store=store, password_handler=pw, notification_service=notif)
        assert "mfa_disabled" in notif.calls


# ══════════════════════════════════════════════════════════════════
# MFA — BACKUP CODES
# ══════════════════════════════════════════════════════════════════

class TestBackupCodes:

    @pytest.mark.asyncio
    async def test_backup_code_consumed(self, store, config, pw, notif):
        await _create_active_user("bc@x.com", "strongpass", store, config, pw, notif)
        user = await store.get_by_email("bc@x.com")
        result = await setup_mfa_flow(user.id, store=store, config=config, password_handler=pw)
        plain_code = result.backup_codes[0]
        user = await store.get_by_id(user.id)
        consumed = await consume_backup_code(user, plain_code, pw, store)
        assert consumed is True

    @pytest.mark.asyncio
    async def test_backup_code_single_use(self, store, config, pw, notif):
        await _create_active_user("bcs@x.com", "strongpass", store, config, pw, notif)
        user = await store.get_by_email("bcs@x.com")
        result = await setup_mfa_flow(user.id, store=store, config=config, password_handler=pw)
        plain_code = result.backup_codes[0]
        user = await store.get_by_id(user.id)
        await consume_backup_code(user, plain_code, pw, store)
        user = await store.get_by_id(user.id)
        consumed_again = await consume_backup_code(user, plain_code, pw, store)
        assert consumed_again is False

    @pytest.mark.asyncio
    async def test_backup_code_wrong_code(self, store, config, pw, notif):
        await _create_active_user("bcw@x.com", "strongpass", store, config, pw, notif)
        user = await store.get_by_email("bcw@x.com")
        await setup_mfa_flow(user.id, store=store, config=config, password_handler=pw)
        user = await store.get_by_id(user.id)
        consumed = await consume_backup_code(user, "WRONGCOD", pw, store)
        assert consumed is False

    @pytest.mark.asyncio
    async def test_backup_code_removes_only_used(self, store, config, pw, notif):
        await _create_active_user("bcr@x.com", "strongpass", store, config, pw, notif)
        user = await store.get_by_email("bcr@x.com")
        result = await setup_mfa_flow(user.id, store=store, config=config, password_handler=pw)
        user = await store.get_by_id(user.id)
        await consume_backup_code(user, result.backup_codes[0], pw, store)
        user = await store.get_by_id(user.id)
        assert len(user.backup_codes) == 7  # one removed


# ══════════════════════════════════════════════════════════════════
# MFA — LOGIN WITH TOTP
# ══════════════════════════════════════════════════════════════════

class TestLoginWithMFA:

    @pytest.mark.asyncio
    async def test_login_requires_totp_when_mfa_enabled(self, store, config_mfa, pw, notif):
        jwt2 = JWTHandler(config_mfa, blacklist=MemoryTokenBlacklist())
        await _create_active_user("lm@x.com", "strongpass", store, config_mfa, pw, notif)
        user = await store.get_by_email("lm@x.com")
        result = await setup_mfa_flow(user.id, store=store, config=config_mfa, password_handler=pw)
        code = pyotp.TOTP(result.secret).now()
        await confirm_mfa_flow(user.id, code, store=store, notification_service=notif)
        with pytest.raises(MFARequired):
            await login_flow("lm@x.com", "strongpass",
                store=store, config=config_mfa, password_handler=pw, jwt_handler=jwt2)

    @pytest.mark.asyncio
    async def test_login_with_valid_totp_succeeds(self, store, config_mfa, pw, notif):
        jwt2 = JWTHandler(config_mfa, blacklist=MemoryTokenBlacklist())
        await _create_active_user("lv@x.com", "strongpass", store, config_mfa, pw, notif)
        user = await store.get_by_email("lv@x.com")
        result = await setup_mfa_flow(user.id, store=store, config=config_mfa, password_handler=pw)
        code = pyotp.TOTP(result.secret).now()
        await confirm_mfa_flow(user.id, code, store=store, notification_service=notif)
        fresh_code = pyotp.TOTP(result.secret).now()
        pair, _ = await login_flow("lv@x.com", "strongpass", totp_code=fresh_code,
            store=store, config=config_mfa, password_handler=pw, jwt_handler=jwt2)
        assert pair.access_token

    @pytest.mark.asyncio
    async def test_login_wrong_totp_rejected(self, store, config_mfa, pw, notif):
        jwt2 = JWTHandler(config_mfa, blacklist=MemoryTokenBlacklist())
        await _create_active_user("lwr@x.com", "strongpass", store, config_mfa, pw, notif)
        user = await store.get_by_email("lwr@x.com")
        result = await setup_mfa_flow(user.id, store=store, config=config_mfa, password_handler=pw)
        code = pyotp.TOTP(result.secret).now()
        await confirm_mfa_flow(user.id, code, store=store, notification_service=notif)
        with pytest.raises(InvalidMFACode):
            await login_flow("lwr@x.com", "strongpass", totp_code="000000",
                store=store, config=config_mfa, password_handler=pw, jwt_handler=jwt2)


# ══════════════════════════════════════════════════════════════════
# PERMISSIONS — ROLES
# ══════════════════════════════════════════════════════════════════

class TestRolePermissions:

    def test_has_role_match(self):
        p = make_payload(roles=["admin"])
        assert has_role(p, "admin") is True

    def test_has_role_no_match(self):
        p = make_payload(roles=["user"])
        assert has_role(p, "admin") is False

    def test_has_role_any_of(self):
        p = make_payload(roles=["moderator"])
        assert has_role(p, "admin", "moderator") is True

    def test_has_role_require_all(self):
        p = make_payload(roles=["admin", "user"])
        assert has_role(p, "admin", "user", require_all=True) is True
        assert has_role(p, "admin", "superadmin", require_all=True) is False

    def test_require_roles_raises_forbidden(self):
        p = make_payload(roles=["user"])
        with pytest.raises(ForbiddenError):
            require_roles(p, "admin")

    def test_require_roles_passes(self):
        p = make_payload(roles=["admin"])
        require_roles(p, "admin")  # no exception

    def test_has_min_role(self):
        p = make_payload(roles=["admin"])
        assert has_min_role(p, "user") is True
        assert has_min_role(p, "admin") is True
        assert has_min_role(p, "superadmin") is False

    def test_require_min_role_raises(self):
        p = make_payload(roles=["user"])
        with pytest.raises(ForbiddenError):
            require_min_role(p, "admin")

    def test_require_min_role_passes(self):
        p = make_payload(roles=["admin"])
        require_min_role(p, "user")  # no exception

    def test_empty_roles_denied(self):
        p = make_payload(roles=[])
        assert has_role(p, "user") is False
        with pytest.raises(ForbiddenError):
            require_roles(p, "user")


# ══════════════════════════════════════════════════════════════════
# PERMISSIONS — SCOPES
# ══════════════════════════════════════════════════════════════════

class TestScopePermissions:

    def test_has_scope_match(self):
        p = make_payload(scopes=["read"])
        assert has_scope(p, "read") is True

    def test_has_scope_no_match(self):
        p = make_payload(scopes=["read"])
        assert has_scope(p, "write") is False

    def test_has_scope_any_of(self):
        p = make_payload(scopes=["read"])
        assert has_scope(p, "write", "read") is True

    def test_has_scope_require_all(self):
        p = make_payload(scopes=["read", "write"])
        assert has_scope(p, "read", "write", require_all=True) is True
        assert has_scope(p, "read", "delete", require_all=True) is False

    def test_require_scopes_raises_forbidden(self):
        p = make_payload(scopes=["read"])
        with pytest.raises(ForbiddenError):
            require_scopes(p, "write")

    def test_require_scopes_passes(self):
        p = make_payload(scopes=["write"])
        require_scopes(p, "write")  # no exception

    def test_read_only_token_rejected_for_write(self):
        p = make_payload(roles=["admin"], scopes=["read"])
        with pytest.raises(ForbiddenError):
            require_scopes(p, "write")

    def test_empty_scopes_denied(self):
        p = make_payload(scopes=[])
        with pytest.raises(ForbiddenError):
            require_scopes(p, "read")