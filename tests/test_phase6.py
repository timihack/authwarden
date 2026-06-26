"""Phase 6 tests — AuthWarden facade, router assembly, dependency injection.

These test the WIRING (facade builds correctly, routes are registered,
dependencies inject properly) via real HTTP requests through TestClient.
Exhaustive flow-level edge cases are already covered by tests in
Phases 1-5; full end-to-end coverage is Phase 7's job.
"""
from __future__ import annotations

from urllib.parse import urlparse

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from authwarden import AuthWarden, WardenConfig, MemoryUserStore
from authwarden.core.config import OAuthProviderConfig
from authwarden.models.user import UserInDB


@pytest.fixture
def warden():
    config = WardenConfig(secret_key="phase6-secret", require_email_verification=False)
    store = MemoryUserStore()
    return AuthWarden(config=config, user_store=store)


@pytest.fixture
def warden_mfa():
    config = WardenConfig(secret_key="phase6-secret", require_email_verification=False, enable_mfa=True)
    store = MemoryUserStore()
    return AuthWarden(config=config, user_store=store)


@pytest.fixture
def warden_oauth():
    config = WardenConfig(
        secret_key="phase6-secret", require_email_verification=False,
        oauth_providers={"google": OAuthProviderConfig(
            client_id="cid", client_secret="sec", redirect_uri="https://app.com/cb",
        )},
    )
    store = MemoryUserStore()
    return AuthWarden(config=config, user_store=store)


def make_app(warden: AuthWarden) -> FastAPI:
    app = FastAPI()
    app.include_router(warden.router, prefix="/auth")

    @app.get("/protected")
    async def protected(user: UserInDB = Depends(warden.current_user)):
        return {"id": user.id, "email": user.email}

    @app.get("/admin-only")
    async def admin_only(_payload=Depends(warden.require_roles("admin"))):
        return {"ok": True}

    @app.get("/write-scope")
    async def write_scope(_payload=Depends(warden.require_scopes("write"))):
        return {"ok": True}

    return app


class TestRouterAssembly:

    def test_router_builds_with_20_routes(self, warden):
        def count(router):
            total = 0
            for r in router.routes:
                if hasattr(r, "original_router"):
                    total += count(r.original_router)
                elif hasattr(r, "path"):
                    total += 1
            return total
        assert count(warden.router) == 20

    def test_app_mounts_without_error(self, warden):
        app = make_app(warden)
        client = TestClient(app)
        # Mounted successfully if any request resolves without a startup error
        r = client.post("/auth/login", json={"identifier": "x@x.com", "password": "x"})
        assert r.status_code in (401, 422)


class TestRegisterLoginFlow:

    def test_register_returns_201(self, warden):
        client = TestClient(make_app(warden))
        r = client.post("/auth/register", json={"email": "a@x.com", "password": "strongpass123"})
        assert r.status_code == 201
        assert r.json()["email"] == "a@x.com"
        assert "hashed_password" not in r.json()  # response_model excludes it

    def test_login_returns_tokens(self, warden):
        client = TestClient(make_app(warden))
        client.post("/auth/register", json={"email": "b@x.com", "password": "strongpass123"})
        r = client.post("/auth/login", json={"identifier": "b@x.com", "password": "strongpass123"})
        assert r.status_code == 200
        body = r.json()
        assert body["access_token"] and body["refresh_token"]
        assert body["user"]["email"] == "b@x.com"

    def test_login_wrong_password_401(self, warden):
        client = TestClient(make_app(warden))
        client.post("/auth/register", json={"email": "c@x.com", "password": "correctpass"})
        r = client.post("/auth/login", json={"identifier": "c@x.com", "password": "wrongpass"})
        assert r.status_code == 401

    def test_duplicate_email_409(self, warden):
        client = TestClient(make_app(warden))
        client.post("/auth/register", json={"email": "d@x.com", "password": "strongpass123"})
        r = client.post("/auth/register", json={"email": "d@x.com", "password": "anotherpass"})
        assert r.status_code == 409

    def test_weak_password_422(self, warden):
        client = TestClient(make_app(warden))
        r = client.post("/auth/register", json={"email": "e@x.com", "password": "x"})
        assert r.status_code == 422


class TestProtectedRoutes:

    def test_current_user_dependency_works(self, warden):
        client = TestClient(make_app(warden))
        client.post("/auth/register", json={"email": "f@x.com", "password": "strongpass123"})
        login = client.post("/auth/login", json={"identifier": "f@x.com", "password": "strongpass123"})
        token = login.json()["access_token"]
        r = client.get("/protected", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        assert r.json()["email"] == "f@x.com"

    def test_protected_route_no_token_401(self, warden):
        client = TestClient(make_app(warden))
        r = client.get("/protected")
        assert r.status_code == 401  # HTTPBearer auto_error=True, missing credentials

    def test_protected_route_invalid_token_401(self, warden):
        client = TestClient(make_app(warden))
        r = client.get("/protected", headers={"Authorization": "Bearer garbage"})
        assert r.status_code in (400, 401)

    def test_deactivated_user_loses_access(self, warden):
        client = TestClient(make_app(warden))
        client.post("/auth/register", json={"email": "g@x.com", "password": "strongpass123"})
        login = client.post("/auth/login", json={"identifier": "g@x.com", "password": "strongpass123"})
        token = login.json()["access_token"]

        import asyncio
        user = asyncio.run(warden.store.get_by_email("g@x.com"))
        user.is_active = False
        asyncio.run(warden.store.update(user))

        r = client.get("/protected", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 403  # still-valid token, but account now inactive


class TestRolesAndScopes:

    def _make_token_with(self, warden, roles=None, scopes=None):
        pair = warden.jwt_handler.create_token_pair("fake-user-id", roles=roles or [], scopes=scopes or [])
        return pair.access_token

    def test_require_roles_admin_passes(self, warden):
        client = TestClient(make_app(warden))
        token = self._make_token_with(warden, roles=["admin"])
        r = client.get("/admin-only", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200

    def test_require_roles_non_admin_rejected(self, warden):
        client = TestClient(make_app(warden))
        token = self._make_token_with(warden, roles=["user"])
        r = client.get("/admin-only", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 403

    def test_require_scopes_write_passes(self, warden):
        client = TestClient(make_app(warden))
        token = self._make_token_with(warden, scopes=["write"])
        r = client.get("/write-scope", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200

    def test_require_scopes_missing_rejected(self, warden):
        client = TestClient(make_app(warden))
        token = self._make_token_with(warden, scopes=["read"])
        r = client.get("/write-scope", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 403


class TestLogoutRefresh:

    def test_logout_returns_204(self, warden):
        client = TestClient(make_app(warden))
        client.post("/auth/register", json={"email": "h@x.com", "password": "strongpass123"})
        login = client.post("/auth/login", json={"identifier": "h@x.com", "password": "strongpass123"})
        token = login.json()["access_token"]
        r = client.post("/auth/logout", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 204

    def test_logout_blacklists_token(self, warden):
        client = TestClient(make_app(warden))
        client.post("/auth/register", json={"email": "i@x.com", "password": "strongpass123"})
        login = client.post("/auth/login", json={"identifier": "i@x.com", "password": "strongpass123"})
        token = login.json()["access_token"]
        client.post("/auth/logout", headers={"Authorization": f"Bearer {token}"})
        r = client.get("/protected", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 401

    def test_refresh_returns_new_pair(self, warden):
        client = TestClient(make_app(warden))
        client.post("/auth/register", json={"email": "j@x.com", "password": "strongpass123"})
        login = client.post("/auth/login", json={"identifier": "j@x.com", "password": "strongpass123"})
        refresh_token = login.json()["refresh_token"]
        r = client.post("/auth/refresh", json={"refresh_token": refresh_token})
        assert r.status_code == 200
        assert r.json()["access_token"] != login.json()["access_token"]


class TestChangePassword:

    def test_change_password_authenticated(self, warden):
        client = TestClient(make_app(warden))
        client.post("/auth/register", json={"email": "k@x.com", "password": "oldpassword"})
        login = client.post("/auth/login", json={"identifier": "k@x.com", "password": "oldpassword"})
        token = login.json()["access_token"]
        r = client.post(
            "/auth/change-password",
            json={"current_password": "oldpassword", "new_password": "newstrongpassword"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 200
        # New password works
        r2 = client.post("/auth/login", json={"identifier": "k@x.com", "password": "newstrongpassword"})
        assert r2.status_code == 200

    def test_change_password_no_auth_401(self, warden):
        client = TestClient(make_app(warden))
        r = client.post("/auth/change-password", json={"current_password": "x", "new_password": "y"})
        assert r.status_code == 401


class TestMFAEndpoints:

    def _register_login(self, client, email="mfa@x.com", password="strongpass123"):
        client.post("/auth/register", json={"email": email, "password": password})
        login = client.post("/auth/login", json={"identifier": email, "password": password})
        return login.json()["access_token"]

    def test_mfa_setup_returns_secret_and_codes(self, warden_mfa):
        client = TestClient(make_app(warden_mfa))
        token = self._register_login(client)
        r = client.post("/auth/mfa/setup", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        body = r.json()
        assert body["secret"]
        assert len(body["backup_codes"]) == 8

    def test_mfa_confirm_activates(self, warden_mfa):
        client = TestClient(make_app(warden_mfa))
        token = self._register_login(client)
        setup = client.post("/auth/mfa/setup", headers={"Authorization": f"Bearer {token}"})
        secret = setup.json()["secret"]

        import pyotp
        code = pyotp.TOTP(secret).now()
        r = client.post(
            "/auth/mfa/confirm", json={"totp_code": code},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 200

    def test_login_requires_totp_after_mfa_enabled(self, warden_mfa):
        client = TestClient(make_app(warden_mfa))
        token = self._register_login(client, email="mfa2@x.com")
        setup = client.post("/auth/mfa/setup", headers={"Authorization": f"Bearer {token}"})
        secret = setup.json()["secret"]
        import pyotp
        code = pyotp.TOTP(secret).now()
        client.post("/auth/mfa/confirm", json={"totp_code": code}, headers={"Authorization": f"Bearer {token}"})

        r = client.post("/auth/login", json={"identifier": "mfa2@x.com", "password": "strongpass123"})
        assert r.status_code == 403  # MFARequired

    def test_mfa_setup_no_auth_401(self, warden_mfa):
        client = TestClient(make_app(warden_mfa))
        r = client.post("/auth/mfa/setup")
        assert r.status_code == 401


class TestOAuthEndpoints:

    def test_authorize_returns_url(self, warden_oauth):
        client = TestClient(make_app(warden_oauth))
        r = client.get("/auth/oauth/google/authorize")
        assert r.status_code == 200
        parsed = urlparse(r.json()["authorization_url"])
        assert parsed.scheme == "https"
        assert parsed.hostname == "accounts.google.com"

    def test_authorize_unknown_provider_404(self, warden_oauth):
        client = TestClient(make_app(warden_oauth))
        r = client.get("/auth/oauth/unknownprovider/authorize")
        assert r.status_code == 404

    def test_authorize_with_auth_header_builds_connect_state(self, warden_oauth):
        client = TestClient(make_app(warden_oauth))
        client.post("/auth/register", json={"email": "oa@x.com", "password": "strongpass123"})
        login = client.post("/auth/login", json={"identifier": "oa@x.com", "password": "strongpass123"})
        token = login.json()["access_token"]

        r = client.get("/auth/oauth/google/authorize", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        # one state entry created, purpose=connect (verified indirectly via no error)
        assert warden_oauth.oauth_state_store.size == 1

    def test_accounts_list_requires_auth_401(self, warden_oauth):
        client = TestClient(make_app(warden_oauth))
        r = client.get("/auth/oauth/accounts")
        assert r.status_code == 401

    def test_accounts_list_empty_for_new_user(self, warden_oauth):
        client = TestClient(make_app(warden_oauth))
        client.post("/auth/register", json={"email": "oa2@x.com", "password": "strongpass123"})
        login = client.post("/auth/login", json={"identifier": "oa2@x.com", "password": "strongpass123"})
        token = login.json()["access_token"]
        r = client.get("/auth/oauth/accounts", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        assert r.json() == []