"""Phase 5 tests — OAuth 2.0 / Social login."""
from __future__ import annotations
import time
import pytest
import httpx
import respx

from authwarden.authentication.encryption import encrypt_token, decrypt_token
from authwarden.authentication.jwt import JWTHandler, MemoryTokenBlacklist
from authwarden.authentication.oauth import (
    AppleOAuthProvider, DiscordOAuthProvider, FacebookOAuthProvider,
    GitHubOAuthProvider, GoogleOAuthProvider, LinkedInOAuthProvider,
    MicrosoftOAuthProvider, TwitterOAuthProvider, build_oauth_provider,
    generate_pkce_pair,
)
from authwarden.authentication.oauth_state import MemoryOAuthStateStore, OAuthStateData
from authwarden.core.config import OAuthProviderConfig, WardenConfig
from authwarden.exceptions import (
    EmailAlreadyRegistered, LastLoginMethod, OAuthAccountNotFound,
    OAuthProviderNotConfigured, OAuthStateMismatch, PasswordAlreadySet,
    ProviderAlreadyLinked, UserNotFound,
)
from authwarden.flows.oauth_accounts import list_oauth_accounts_flow
from authwarden.flows.oauth_authorize import oauth_authorize_flow
from authwarden.flows.oauth_callback import oauth_callback_flow
from authwarden.flows.oauth_connect import oauth_connect_flow
from authwarden.flows.oauth_disconnect import oauth_disconnect_flow
from authwarden.flows.set_password import set_password_flow
from authwarden.models.user import UserInDB
from authwarden.notifications.service import NotificationService
from authwarden.storage.memory import MemoryUserStore


class MockNotificationService:
    def __init__(self): self.calls: list[str] = []
    async def send_verification_link(self, u, link): self.calls.append("link")
    async def send_verification_otp(self, u, otp): self.calls.append("v_otp")
    async def send_welcome(self, u): self.calls.append("welcome")
    async def send_password_reset_link(self, u, link): self.calls.append("reset_link")
    async def send_password_reset_otp(self, u, otp): self.calls.append("reset_otp")
    async def send_password_changed(self, u): self.calls.append("pw_changed")
    async def send_mfa_enabled(self, u): self.calls.append("mfa_enabled")
    async def send_mfa_disabled(self, u): self.calls.append("mfa_disabled")


@pytest.fixture
def config():
    return WardenConfig(
        secret_key="phase5-secret",
        oauth_providers={
            "google": OAuthProviderConfig(client_id="g-cid", client_secret="g-secret", redirect_uri="https://app.com/cb/google"),
            "github": OAuthProviderConfig(client_id="gh-cid", client_secret="gh-secret", redirect_uri="https://app.com/cb/github"),
            "facebook": OAuthProviderConfig(client_id="fb-cid", client_secret="fb-secret", redirect_uri="https://app.com/cb/facebook"),
            "twitter": OAuthProviderConfig(client_id="tw-cid", client_secret="tw-secret", redirect_uri="https://app.com/cb/twitter"),
        },
    )

@pytest.fixture
def config_no_autolink():
    return WardenConfig(
        secret_key="phase5-secret", auto_link_by_email=False,
        oauth_providers={
            "facebook": OAuthProviderConfig(client_id="fb-cid", client_secret="fb-secret", redirect_uri="https://app.com/cb/facebook"),
        },
    )

@pytest.fixture
def store(): return MemoryUserStore()
@pytest.fixture
def notif(): return MockNotificationService()
@pytest.fixture
def jwt(config): return JWTHandler(config, blacklist=MemoryTokenBlacklist())
@pytest.fixture
def state_store(): return MemoryOAuthStateStore()

@pytest.fixture
def providers():
    return {
        "google": GoogleOAuthProvider(OAuthProviderConfig(client_id="g-cid", client_secret="g-secret", redirect_uri="https://app.com/cb/google")),
        "github": GitHubOAuthProvider(OAuthProviderConfig(client_id="gh-cid", client_secret="gh-secret", redirect_uri="https://app.com/cb/github")),
        "facebook": FacebookOAuthProvider(OAuthProviderConfig(client_id="fb-cid", client_secret="fb-secret", redirect_uri="https://app.com/cb/facebook")),
        "twitter": TwitterOAuthProvider(OAuthProviderConfig(client_id="tw-cid", client_secret="tw-secret", redirect_uri="https://app.com/cb/twitter")),
    }


def mock_google_success(email="newuser@gmail.com", sub="google-uid-1"):
    respx.post("https://oauth2.googleapis.com/token").mock(
        return_value=httpx.Response(200, json={"access_token": "gtok", "token_type": "bearer", "expires_in": 3600})
    )
    respx.get("https://openidconnect.googleapis.com/v1/userinfo").mock(
        return_value=httpx.Response(200, json={"sub": sub, "email": email, "email_verified": True, "name": "New User"})
    )

def mock_facebook_success(email="fbuser@example.com", fid="fb-uid-1"):
    respx.post("https://graph.facebook.com/v19.0/oauth/access_token").mock(
        return_value=httpx.Response(200, json={"access_token": "fbtok", "token_type": "bearer", "expires_in": 3600})
    )
    respx.get("https://graph.facebook.com/me").mock(
        return_value=httpx.Response(200, json={"id": fid, "name": "FB User", "email": email})
    )

def mock_twitter_success(tid="tw-uid-1"):
    respx.post("https://api.twitter.com/2/oauth2/token").mock(
        return_value=httpx.Response(200, json={"access_token": "twtok", "token_type": "bearer", "expires_in": 3600})
    )
    respx.get("https://api.twitter.com/2/users/me").mock(
        return_value=httpx.Response(200, json={"data": {"id": tid, "name": "Tw User", "username": "twuser"}})
    )


# ══════════════════════════════════════════════════════════════════
# PKCE + ENCRYPTION
# ══════════════════════════════════════════════════════════════════

class TestPKCEAndEncryption:

    def test_pkce_pair_generated(self):
        verifier, challenge = generate_pkce_pair()
        assert len(verifier) >= 43
        assert len(challenge) > 0
        assert verifier != challenge

    def test_pkce_pair_unique(self):
        v1, c1 = generate_pkce_pair()
        v2, c2 = generate_pkce_pair()
        assert v1 != v2 and c1 != c2

    def test_encrypt_decrypt_roundtrip(self):
        enc = encrypt_token("my-access-token", "app-secret")
        dec = decrypt_token(enc, "app-secret")
        assert dec == "my-access-token"

    def test_encrypted_value_differs_from_plaintext(self):
        enc = encrypt_token("plain-value", "app-secret")
        assert enc != "plain-value"

    def test_decrypt_wrong_key_fails(self):
        enc = encrypt_token("secret-data", "key-a")
        with pytest.raises(Exception):
            decrypt_token(enc, "key-b")


# ══════════════════════════════════════════════════════════════════
# OAUTH STATE STORE
# ══════════════════════════════════════════════════════════════════

class TestOAuthStateStore:

    @pytest.mark.asyncio
    async def test_create_and_get(self, state_store):
        data = OAuthStateData(state="s1", code_verifier="v1", provider="google")
        await state_store.create(data)
        result = await state_store.get_and_delete("s1")
        assert result is not None
        assert result.code_verifier == "v1"

    @pytest.mark.asyncio
    async def test_single_use(self, state_store):
        data = OAuthStateData(state="s2", code_verifier="v2", provider="google")
        await state_store.create(data)
        await state_store.get_and_delete("s2")
        second = await state_store.get_and_delete("s2")
        assert second is None

    @pytest.mark.asyncio
    async def test_unknown_state_returns_none(self, state_store):
        result = await state_store.get_and_delete("never-existed")
        assert result is None

    @pytest.mark.asyncio
    async def test_expired_state_returns_none(self, state_store):
        data = OAuthStateData(state="s3", code_verifier="v3", provider="google")
        await state_store.create(data, ttl_seconds=0)
        time.sleep(0.05)
        result = await state_store.get_and_delete("s3")
        assert result is None


# ══════════════════════════════════════════════════════════════════
# PROVIDER URL BUILDING
# ══════════════════════════════════════════════════════════════════

class TestProviderAuthorizationURLs:

    def test_google_authorization_url(self):
        cfg = OAuthProviderConfig(client_id="cid", client_secret="sec", redirect_uri="https://app.com/cb")
        provider = GoogleOAuthProvider(cfg)
        url = provider.build_authorization_url("mystate", "mychallenge")
        assert "accounts.google.com" in url
        assert "state=mystate" in url
        assert "code_challenge=mychallenge" in url
        assert "code_challenge_method=S256" in url

    def test_github_authorization_url(self):
        cfg = OAuthProviderConfig(client_id="cid", client_secret="sec", redirect_uri="https://app.com/cb")
        provider = GitHubOAuthProvider(cfg)
        url = provider.build_authorization_url("s", "c")
        assert "github.com/login/oauth/authorize" in url

    def test_custom_scopes_override_defaults(self):
        cfg = OAuthProviderConfig(client_id="cid", client_secret="sec", redirect_uri="https://app.com/cb", scopes=["custom_scope"])
        provider = GoogleOAuthProvider(cfg)
        assert provider._scopes() == "custom_scope"

    def test_default_scopes_used_when_empty(self):
        cfg = OAuthProviderConfig(client_id="cid", client_secret="sec", redirect_uri="https://app.com/cb")
        provider = GoogleOAuthProvider(cfg)
        assert "openid" in provider._scopes()

    def test_build_oauth_provider_factory(self):
        cfg = OAuthProviderConfig(client_id="cid", client_secret="sec", redirect_uri="https://app.com/cb")
        provider = build_oauth_provider("github", cfg)
        assert isinstance(provider, GitHubOAuthProvider)

    def test_build_oauth_provider_unknown_raises(self):
        cfg = OAuthProviderConfig(client_id="cid", client_secret="sec", redirect_uri="https://app.com/cb")
        with pytest.raises(ValueError):
            build_oauth_provider("unknown_provider", cfg)

    def test_build_apple_without_credentials_raises(self):
        cfg = OAuthProviderConfig(client_id="cid", client_secret="", redirect_uri="https://app.com/cb")
        with pytest.raises(ValueError):
            build_oauth_provider("apple", cfg)


# ══════════════════════════════════════════════════════════════════
# OAUTH AUTHORIZE FLOW
# ══════════════════════════════════════════════════════════════════

class TestOAuthAuthorizeFlow:

    @pytest.mark.asyncio
    async def test_returns_authorization_url(self, config, providers, state_store):
        url = await oauth_authorize_flow("google", config=config, providers=providers, state_store=state_store)
        assert "accounts.google.com" in url

    @pytest.mark.asyncio
    async def test_persists_state(self, config, providers, state_store):
        url = await oauth_authorize_flow("google", config=config, providers=providers, state_store=state_store)
        assert state_store.size == 1

    @pytest.mark.asyncio
    async def test_unconfigured_provider_raises(self, config, providers, state_store):
        with pytest.raises(OAuthProviderNotConfigured):
            await oauth_authorize_flow("linkedin", config=config, providers=providers, state_store=state_store)

    @pytest.mark.asyncio
    async def test_disabled_provider_raises(self, providers, state_store):
        cfg = WardenConfig(secret_key="s", oauth_providers={
            "google": OAuthProviderConfig(client_id="c", client_secret="s", redirect_uri="https://a.com/cb", enabled=False)
        })
        with pytest.raises(OAuthProviderNotConfigured):
            await oauth_authorize_flow("google", config=cfg, providers=providers, state_store=state_store)


# ══════════════════════════════════════════════════════════════════
# OAUTH CALLBACK — ACCOUNT LINKING
# ══════════════════════════════════════════════════════════════════

class TestOAuthCallbackFlow:

    @respx.mock
    @pytest.mark.asyncio
    async def test_new_user_created(self, store, config, jwt, notif, providers, state_store):
        mock_google_success(email="brand_new@gmail.com", sub="google-uid-100")
        url = await oauth_authorize_flow("google", config=config, providers=providers, state_store=state_store)
        state = url.split("state=")[1].split("&")[0]

        result = await oauth_callback_flow(
            "google", "auth-code", state,
            store=store, config=config, jwt_handler=jwt,
            notification_service=notif, providers=providers, state_store=state_store,
        )
        assert result.is_new_user is True
        assert result.user.email == "brand_new@gmail.com"
        assert result.token_pair.access_token

    @respx.mock
    @pytest.mark.asyncio
    async def test_existing_oauth_account_logs_in(self, store, config, jwt, notif, providers, state_store):
        mock_google_success(email="repeat@gmail.com", sub="google-uid-200")
        url = await oauth_authorize_flow("google", config=config, providers=providers, state_store=state_store)
        state = url.split("state=")[1].split("&")[0]
        r1 = await oauth_callback_flow("google", "code1", state,
            store=store, config=config, jwt_handler=jwt, notification_service=notif,
            providers=providers, state_store=state_store)
        assert r1.is_new_user is True

        # second login — same provider_user_id
        url2 = await oauth_authorize_flow("google", config=config, providers=providers, state_store=state_store)
        state2 = url2.split("state=")[1].split("&")[0]
        r2 = await oauth_callback_flow("google", "code2", state2,
            store=store, config=config, jwt_handler=jwt, notification_service=notif,
            providers=providers, state_store=state_store)
        assert r2.is_new_user is False
        assert r2.user.id == r1.user.id

    @respx.mock
    @pytest.mark.asyncio
    async def test_email_match_auto_links(self, store, config, jwt, notif, providers, state_store):
        """Case 2 — existing local user with matching email gets auto-linked."""
        existing = UserInDB(email="local@example.com", hashed_password="hashed", is_active=True, is_verified=True)
        await store.create(existing)

        mock_google_success(email="local@example.com", sub="google-uid-300")
        url = await oauth_authorize_flow("google", config=config, providers=providers, state_store=state_store)
        state = url.split("state=")[1].split("&")[0]
        result = await oauth_callback_flow("google", "code", state,
            store=store, config=config, jwt_handler=jwt, notification_service=notif,
            providers=providers, state_store=state_store)
        assert result.is_new_user is False
        assert result.user.id == existing.id

    @respx.mock
    @pytest.mark.asyncio
    async def test_email_match_no_autolink_raises(self, store, config_no_autolink, jwt, notif, providers, state_store):
        """auto_link_by_email=False raises EmailAlreadyRegistered on email collision."""
        existing = UserInDB(email="collide@example.com", hashed_password="hashed", is_active=True, is_verified=True)
        await store.create(existing)
        jwt2 = JWTHandler(config_no_autolink, blacklist=MemoryTokenBlacklist())

        mock_facebook_success(email="collide@example.com", fid="fb-uid-collide")
        url = await oauth_authorize_flow("facebook", config=config_no_autolink, providers=providers, state_store=state_store)
        state = url.split("state=")[1].split("&")[0]
        with pytest.raises(EmailAlreadyRegistered):
            await oauth_callback_flow("facebook", "code", state,
                store=store, config=config_no_autolink, jwt_handler=jwt2, notification_service=notif,
                providers=providers, state_store=state_store)

    @respx.mock
    @pytest.mark.asyncio
    async def test_twitter_no_email_registers_anyway(self, store, config, jwt, notif, providers, state_store):
        """Case 4 — Twitter provides no email, user still registers successfully."""
        mock_twitter_success(tid="tw-uid-999")
        url = await oauth_authorize_flow("twitter", config=config, providers=providers, state_store=state_store)
        state = url.split("state=")[1].split("&")[0]
        result = await oauth_callback_flow("twitter", "code", state,
            store=store, config=config, jwt_handler=jwt, notification_service=notif,
            providers=providers, state_store=state_store)
        assert result.is_new_user is True
        # synthetic placeholder email assigned, real linked email stays None
        account = await store.get_oauth_account("twitter", "tw-uid-999")
        assert account.email is None

    @pytest.mark.asyncio
    async def test_state_mismatch_raises(self, store, config, jwt, notif, providers, state_store):
        with pytest.raises(OAuthStateMismatch):
            await oauth_callback_flow("google", "code", "never-existed-state",
                store=store, config=config, jwt_handler=jwt, notification_service=notif,
                providers=providers, state_store=state_store)

    @pytest.mark.asyncio
    async def test_expired_state_raises(self, store, config, jwt, notif, providers, state_store):
        await state_store.create(
            OAuthStateData(state="expired-state", code_verifier="v", provider="google"),
            ttl_seconds=0,
        )
        time.sleep(0.05)
        with pytest.raises(OAuthStateMismatch):
            await oauth_callback_flow("google", "code", "expired-state",
                store=store, config=config, jwt_handler=jwt, notification_service=notif,
                providers=providers, state_store=state_store)

    @respx.mock
    @pytest.mark.asyncio
    async def test_new_user_sends_welcome_email(self, store, config, jwt, notif, providers, state_store):
        mock_google_success(email="welcome_test@gmail.com", sub="google-uid-welcome")
        url = await oauth_authorize_flow("google", config=config, providers=providers, state_store=state_store)
        state = url.split("state=")[1].split("&")[0]
        await oauth_callback_flow("google", "code", state,
            store=store, config=config, jwt_handler=jwt, notification_service=notif,
            providers=providers, state_store=state_store)
        assert "welcome" in notif.calls


# ══════════════════════════════════════════════════════════════════
# OAUTH CONNECT / DISCONNECT / ACCOUNTS
# ══════════════════════════════════════════════════════════════════

class TestOAuthConnectDisconnect:

    @respx.mock
    @pytest.mark.asyncio
    async def test_connect_links_provider(self, store, config, providers, state_store):
        user = UserInDB(email="connect@example.com", hashed_password="hashed", is_active=True, is_verified=True)
        await store.create(user)

        mock_github_resp()
        url = await oauth_authorize_flow("github", config=config, providers=providers,
            state_store=state_store, purpose="connect", user_id=user.id)
        state = url.split("state=")[1].split("&")[0]

        result = await oauth_connect_flow("github", "code", state,
            current_user_id=user.id, store=store, config=config,
            providers=providers, state_store=state_store)
        assert result.provider == "github"

    @respx.mock
    @pytest.mark.asyncio
    async def test_connect_twice_raises_already_linked(self, store, config, providers, state_store):
        user = UserInDB(email="dup@example.com", hashed_password="hashed", is_active=True, is_verified=True)
        await store.create(user)

        mock_github_resp(uid="gh-dup-1")
        url = await oauth_authorize_flow("github", config=config, providers=providers,
            state_store=state_store, purpose="connect", user_id=user.id)
        state = url.split("state=")[1].split("&")[0]
        await oauth_connect_flow("github", "code", state,
            current_user_id=user.id, store=store, config=config,
            providers=providers, state_store=state_store)

        mock_github_resp(uid="gh-dup-1")
        url2 = await oauth_authorize_flow("github", config=config, providers=providers,
            state_store=state_store, purpose="connect", user_id=user.id)
        state2 = url2.split("state=")[1].split("&")[0]
        with pytest.raises(ProviderAlreadyLinked):
            await oauth_connect_flow("github", "code2", state2,
                current_user_id=user.id, store=store, config=config,
                providers=providers, state_store=state_store)

    @pytest.mark.asyncio
    async def test_connect_wrong_user_state_raises(self, store, config, providers, state_store):
        await state_store.create(OAuthStateData(
            state="s1", code_verifier="v1", provider="github", purpose="connect", user_id="user-A",
        ))
        with pytest.raises(OAuthStateMismatch):
            await oauth_connect_flow("github", "code", "s1",
                current_user_id="user-B", store=store, config=config,
                providers=providers, state_store=state_store)

    @pytest.mark.asyncio
    async def test_disconnect_removes_link(self, store):
        from authwarden.models.user import OAuthAccount
        user = UserInDB(email="d@example.com", hashed_password="hashed", is_active=True, is_verified=True)
        await store.create(user)
        await store.create_oauth_account(OAuthAccount(user_id=user.id, provider="google", provider_user_id="gid"))
        await oauth_disconnect_flow("google", current_user_id=user.id, store=store)
        result = await store.get_oauth_account("google", "gid")
        assert result is None

    @pytest.mark.asyncio
    async def test_disconnect_last_method_raises(self, store):
        """OAuth-only account with single provider cannot disconnect it."""
        from authwarden.models.user import OAuthAccount
        user = UserInDB(email="oauth_only@example.com", hashed_password=None, is_active=True, is_verified=True)
        await store.create(user)
        await store.create_oauth_account(OAuthAccount(user_id=user.id, provider="google", provider_user_id="gid"))
        with pytest.raises(LastLoginMethod):
            await oauth_disconnect_flow("google", current_user_id=user.id, store=store)

    @pytest.mark.asyncio
    async def test_disconnect_allowed_with_password(self, store):
        """User with a password CAN disconnect their only OAuth provider."""
        from authwarden.models.user import OAuthAccount
        user = UserInDB(email="haspass@example.com", hashed_password="hashed", is_active=True, is_verified=True)
        await store.create(user)
        await store.create_oauth_account(OAuthAccount(user_id=user.id, provider="google", provider_user_id="gid"))
        await oauth_disconnect_flow("google", current_user_id=user.id, store=store)  # no exception

    @pytest.mark.asyncio
    async def test_disconnect_allowed_with_other_provider(self, store):
        """User with another linked provider CAN disconnect one of them."""
        from authwarden.models.user import OAuthAccount
        user = UserInDB(email="twoproviders@example.com", hashed_password=None, is_active=True, is_verified=True)
        await store.create(user)
        await store.create_oauth_account(OAuthAccount(user_id=user.id, provider="google", provider_user_id="gid"))
        await store.create_oauth_account(OAuthAccount(user_id=user.id, provider="github", provider_user_id="ghid"))
        await oauth_disconnect_flow("google", current_user_id=user.id, store=store)  # no exception
        remaining = await store.get_oauth_accounts_for_user(user.id)
        assert len(remaining) == 1
        assert remaining[0].provider == "github"

    @pytest.mark.asyncio
    async def test_disconnect_unlinked_provider_raises(self, store):
        user = UserInDB(email="nl@example.com", hashed_password="hashed", is_active=True, is_verified=True)
        await store.create(user)
        with pytest.raises(OAuthAccountNotFound):
            await oauth_disconnect_flow("google", current_user_id=user.id, store=store)

    @pytest.mark.asyncio
    async def test_disconnect_user_not_found(self, store):
        with pytest.raises(UserNotFound):
            await oauth_disconnect_flow("google", current_user_id="ghost-id", store=store)

    @pytest.mark.asyncio
    async def test_list_accounts_excludes_tokens(self, store):
        from authwarden.models.user import OAuthAccount
        user = UserInDB(email="list@example.com", hashed_password="hashed", is_active=True, is_verified=True)
        await store.create(user)
        await store.create_oauth_account(OAuthAccount(
            user_id=user.id, provider="google", provider_user_id="gid",
            access_token="should-not-appear", email="g@example.com",
        ))
        accounts = await list_oauth_accounts_flow(user.id, store=store)
        assert len(accounts) == 1
        assert accounts[0].provider == "google"
        assert not hasattr(accounts[0], "access_token")

    @pytest.mark.asyncio
    async def test_list_accounts_empty(self, store):
        user = UserInDB(email="empty@example.com", hashed_password="hashed", is_active=True, is_verified=True)
        await store.create(user)
        accounts = await list_oauth_accounts_flow(user.id, store=store)
        assert accounts == []


def mock_github_resp(uid="gh-uid-1"):
    respx.post("https://github.com/login/oauth/access_token").mock(
        return_value=httpx.Response(200, json={"access_token": "ghtok", "token_type": "bearer"})
    )
    respx.get("https://api.github.com/user").mock(
        return_value=httpx.Response(200, json={"id": uid, "login": "ghuser", "name": "GH User", "email": "gh@example.com"})
    )


# ══════════════════════════════════════════════════════════════════
# SET PASSWORD (OAuth-only accounts)
# ══════════════════════════════════════════════════════════════════

class TestSetPasswordFlow:

    @pytest.mark.asyncio
    async def test_set_password_success(self, store, config, notif):
        from authwarden.authentication.password import PasswordHandler
        pw = PasswordHandler(config)
        user = UserInDB(email="oauthonly@example.com", hashed_password=None, is_active=True, is_verified=True)
        await store.create(user)
        await set_password_flow(user.id, "newstrongpass",
            store=store, config=config, password_handler=pw, notification_service=notif)
        updated = await store.get_by_id(user.id)
        assert updated.hashed_password is not None
        assert pw.verify_password("newstrongpass", updated.hashed_password)

    @pytest.mark.asyncio
    async def test_set_password_already_set_raises(self, store, config, notif):
        from authwarden.authentication.password import PasswordHandler
        pw = PasswordHandler(config)
        user = UserInDB(email="haspass2@example.com", hashed_password=pw.hash_password("existing"), is_active=True, is_verified=True)
        await store.create(user)
        with pytest.raises(PasswordAlreadySet):
            await set_password_flow(user.id, "newpass",
                store=store, config=config, password_handler=pw, notification_service=notif)

    @pytest.mark.asyncio
    async def test_set_password_user_not_found(self, store, config, notif):
        from authwarden.authentication.password import PasswordHandler
        pw = PasswordHandler(config)
        with pytest.raises(UserNotFound):
            await set_password_flow("ghost", "newpass",
                store=store, config=config, password_handler=pw, notification_service=notif)

    @pytest.mark.asyncio
    async def test_set_password_sends_confirmation(self, store, config, notif):
        from authwarden.authentication.password import PasswordHandler
        pw = PasswordHandler(config)
        user = UserInDB(email="confirm@example.com", hashed_password=None, is_active=True, is_verified=True)
        await store.create(user)
        await set_password_flow(user.id, "newstrongpass",
            store=store, config=config, password_handler=pw, notification_service=notif)
        assert "pw_changed" in notif.calls


# ══════════════════════════════════════════════════════════════════
# APPLE — SPECIAL HANDLING
# ══════════════════════════════════════════════════════════════════

class TestAppleProvider:

    APPLE_TEAM_ID = "TEAM123"
    APPLE_KEY_ID = "KEY123"
    APPLE_PRIVATE_KEY_PEM = None  # generated in fixture below

    @pytest.fixture
    def apple_keys(self):
        """Generate an ephemeral ES256 keypair for testing client_secret signing."""
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import serialization
        private_key = ec.generate_private_key(ec.SECP256R1())
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()
        return private_key, pem

    def test_apple_client_secret_is_valid_jwt(self, apple_keys):
        import jwt as pyjwt
        private_key, pem = apple_keys
        cfg = OAuthProviderConfig(client_id="com.myapp.service", client_secret="", redirect_uri="https://app.com/cb/apple")
        provider = AppleOAuthProvider(cfg, team_id=self.APPLE_TEAM_ID, key_id=self.APPLE_KEY_ID, private_key_pem=pem)
        secret = provider._generate_client_secret()

        # Decode using the public key to verify it's correctly signed
        public_key = private_key.public_key()
        claims = pyjwt.decode(secret, public_key, algorithms=["ES256"], audience="https://appleid.apple.com")
        assert claims["iss"] == self.APPLE_TEAM_ID
        assert claims["sub"] == "com.myapp.service"

    def test_apple_client_secret_has_kid_header(self, apple_keys):
        import jwt as pyjwt
        private_key, pem = apple_keys
        cfg = OAuthProviderConfig(client_id="com.myapp.service", client_secret="", redirect_uri="https://app.com/cb/apple")
        provider = AppleOAuthProvider(cfg, team_id=self.APPLE_TEAM_ID, key_id=self.APPLE_KEY_ID, private_key_pem=pem)
        secret = provider._generate_client_secret()
        header = pyjwt.get_unverified_header(secret)
        assert header["kid"] == self.APPLE_KEY_ID
        assert header["alg"] == "ES256"

    def test_apple_client_secret_expires_in_5_minutes(self, apple_keys):
        import jwt as pyjwt
        private_key, pem = apple_keys
        cfg = OAuthProviderConfig(client_id="com.myapp.service", client_secret="", redirect_uri="https://app.com/cb/apple")
        provider = AppleOAuthProvider(cfg, team_id=self.APPLE_TEAM_ID, key_id=self.APPLE_KEY_ID, private_key_pem=pem)
        secret = provider._generate_client_secret()
        public_key = private_key.public_key()
        claims = pyjwt.decode(secret, public_key, algorithms=["ES256"], audience="https://appleid.apple.com")
        assert claims["exp"] - claims["iat"] == 300

    @pytest.mark.asyncio
    async def test_apple_extracts_name_from_post_body(self, apple_keys, monkeypatch):
        """First-login name extraction from POST body — Apple never resends it."""
        private_key, pem = apple_keys
        cfg = OAuthProviderConfig(client_id="com.myapp.service", client_secret="", redirect_uri="https://app.com/cb/apple")
        provider = AppleOAuthProvider(cfg, team_id=self.APPLE_TEAM_ID, key_id=self.APPLE_KEY_ID, private_key_pem=pem)

        # Mock the JWKS-based id_token decode by monkeypatching fetch_userinfo internals
        import jwt as pyjwt
        from jwt import PyJWKClient

        fake_claims = {"sub": "apple-uid-1", "email": "private@privaterelay.appleid.com"}

        class FakeSigningKey:
            key = "fake"

        def fake_get_signing_key(self_client, token):
            return FakeSigningKey()

        def fake_decode(token, key, algorithms, audience, issuer):
            return fake_claims

        monkeypatch.setattr(PyJWKClient, "get_signing_key_from_jwt", fake_get_signing_key)
        monkeypatch.setattr(pyjwt, "decode", fake_decode)

        post_body = {"user": {"name": {"firstName": "John", "lastName": "Appleseed"}}}
        userinfo = await provider.fetch_userinfo({"id_token": "fake.id.token"}, post_body=post_body)
        assert userinfo.full_name == "John Appleseed"
        assert userinfo.provider_user_id == "apple-uid-1"
        assert userinfo.email == "private@privaterelay.appleid.com"

    @pytest.mark.asyncio
    async def test_apple_no_post_body_no_name(self, apple_keys, monkeypatch):
        """Repeat logins have no POST body — full_name should be None."""
        private_key, pem = apple_keys
        cfg = OAuthProviderConfig(client_id="com.myapp.service", client_secret="", redirect_uri="https://app.com/cb/apple")
        provider = AppleOAuthProvider(cfg, team_id=self.APPLE_TEAM_ID, key_id=self.APPLE_KEY_ID, private_key_pem=pem)

        import jwt as pyjwt
        from jwt import PyJWKClient
        fake_claims = {"sub": "apple-uid-2", "email": "repeat@privaterelay.appleid.com"}

        class FakeSigningKey:
            key = "fake"
        monkeypatch.setattr(PyJWKClient, "get_signing_key_from_jwt", lambda self, token: FakeSigningKey())
        monkeypatch.setattr(pyjwt, "decode", lambda token, key, algorithms, audience, issuer: fake_claims)

        userinfo = await provider.fetch_userinfo({"id_token": "fake.id.token"}, post_body=None)
        assert userinfo.full_name is None

    def test_apple_factory_requires_credentials(self):
        cfg = OAuthProviderConfig(client_id="cid", client_secret="", redirect_uri="https://app.com/cb")
        with pytest.raises(ValueError):
            build_oauth_provider("apple", cfg, apple_team_id=None, apple_key_id=None, apple_private_key_pem=None)

    def test_apple_factory_with_credentials_succeeds(self, apple_keys):
        _, pem = apple_keys
        cfg = OAuthProviderConfig(client_id="cid", client_secret="", redirect_uri="https://app.com/cb")
        provider = build_oauth_provider("apple", cfg, apple_team_id="T1", apple_key_id="K1", apple_private_key_pem=pem)
        assert isinstance(provider, AppleOAuthProvider)


# ══════════════════════════════════════════════════════════════════
# REMAINING PROVIDERS — USERINFO MAPPING
# ══════════════════════════════════════════════════════════════════

class TestProviderUserinfoMapping:

    @respx.mock
    @pytest.mark.asyncio
    async def test_microsoft_userinfo(self):
        cfg = OAuthProviderConfig(client_id="c", client_secret="s", redirect_uri="https://a.com/cb")
        provider = MicrosoftOAuthProvider(cfg)
        respx.get("https://graph.microsoft.com/oidc/userinfo").mock(
            return_value=httpx.Response(200, json={"sub": "ms-1", "email": "ms@example.com", "name": "MS User"})
        )
        userinfo = await provider.fetch_userinfo({"access_token": "tok"})
        assert userinfo.provider == "microsoft"
        assert userinfo.provider_user_id == "ms-1"
        assert userinfo.email == "ms@example.com"

    @respx.mock
    @pytest.mark.asyncio
    async def test_linkedin_userinfo(self):
        cfg = OAuthProviderConfig(client_id="c", client_secret="s", redirect_uri="https://a.com/cb")
        provider = LinkedInOAuthProvider(cfg)
        respx.get("https://api.linkedin.com/v2/userinfo").mock(
            return_value=httpx.Response(200, json={"sub": "li-1", "email": "li@example.com", "email_verified": True, "name": "LI User", "given_name": "LI", "family_name": "User"})
        )
        userinfo = await provider.fetch_userinfo({"access_token": "tok"})
        assert userinfo.provider == "linkedin"
        assert userinfo.email_verified is True
        assert userinfo.first_name == "LI"

    @respx.mock
    @pytest.mark.asyncio
    async def test_discord_userinfo_with_avatar(self):
        cfg = OAuthProviderConfig(client_id="c", client_secret="s", redirect_uri="https://a.com/cb")
        provider = DiscordOAuthProvider(cfg)
        respx.get("https://discord.com/api/users/@me").mock(
            return_value=httpx.Response(200, json={"id": "dc-1", "username": "dcuser", "email": "dc@example.com", "verified": True, "avatar": "abc123"})
        )
        userinfo = await provider.fetch_userinfo({"access_token": "tok"})
        assert userinfo.provider == "discord"
        assert "dc-1" in userinfo.avatar_url
        assert "abc123" in userinfo.avatar_url

    @respx.mock
    @pytest.mark.asyncio
    async def test_discord_userinfo_no_avatar(self):
        cfg = OAuthProviderConfig(client_id="c", client_secret="s", redirect_uri="https://a.com/cb")
        provider = DiscordOAuthProvider(cfg)
        respx.get("https://discord.com/api/users/@me").mock(
            return_value=httpx.Response(200, json={"id": "dc-2", "username": "dcuser2", "email": None, "verified": False, "avatar": None})
        )
        userinfo = await provider.fetch_userinfo({"access_token": "tok"})
        assert userinfo.avatar_url is None

    @respx.mock
    @pytest.mark.asyncio
    async def test_github_falls_back_to_emails_endpoint(self):
        """When /user has no public email, GitHub provider checks /user/emails."""
        cfg = OAuthProviderConfig(client_id="c", client_secret="s", redirect_uri="https://a.com/cb")
        provider = GitHubOAuthProvider(cfg)
        respx.get("https://api.github.com/user").mock(
            return_value=httpx.Response(200, json={"id": 555, "login": "ghnoemail", "name": "No Email", "email": None})
        )
        respx.get("https://api.github.com/user/emails").mock(
            return_value=httpx.Response(200, json=[
                {"email": "secondary@example.com", "primary": False},
                {"email": "primary@example.com", "primary": True},
            ])
        )
        userinfo = await provider.fetch_userinfo({"access_token": "tok"})
        assert userinfo.email == "primary@example.com"

    @respx.mock
    @pytest.mark.asyncio
    async def test_facebook_userinfo_with_picture(self):
        cfg = OAuthProviderConfig(client_id="c", client_secret="s", redirect_uri="https://a.com/cb")
        provider = FacebookOAuthProvider(cfg)
        respx.get("https://graph.facebook.com/me").mock(
            return_value=httpx.Response(200, json={
                "id": "fb-9", "name": "FB Name", "email": "fb9@example.com",
                "picture": {"data": {"url": "https://fb.com/pic.jpg"}},
            })
        )
        userinfo = await provider.fetch_userinfo({"access_token": "tok"})
        assert userinfo.avatar_url == "https://fb.com/pic.jpg"

    @respx.mock
    @pytest.mark.asyncio
    async def test_twitter_no_email(self):
        cfg = OAuthProviderConfig(client_id="c", client_secret="s", redirect_uri="https://a.com/cb")
        provider = TwitterOAuthProvider(cfg)
        respx.get("https://api.twitter.com/2/users/me").mock(
            return_value=httpx.Response(200, json={"data": {"id": "tw-9", "name": "TW User"}})
        )
        userinfo = await provider.fetch_userinfo({"access_token": "tok"})
        assert userinfo.email is None
        assert userinfo.provider == "twitter"