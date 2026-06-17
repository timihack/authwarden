"""OAuth 2.0 / OIDC provider implementations for authwarden.
 
Wraps Authlib's AsyncOAuth2Client for the authorization code exchange and
httpx for userinfo fetching. Each provider normalizes its response into
the shared OAuthUserInfo schema.
 
PKCE (S256) is used for every provider's authorization flow.
"""
from __future__ import annotations

import secrets, time
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
import jwt as pyjwt
from authlib.integrations.httpx_client import AsyncOAuth2Client
from authlib.oauth2.rfc7636 import create_s256_code_challenge
from jwt import PyJWKClient

from authwarden.core.config import OAuthProviderConfig
from authwarden.models.user import OAuthUserInfo


def generate_pkce_pair() -> tuple[str, str]:
  """Generate a PKCE code_verifier and ts S256 code_challenge.
  
  Returns:
      Tuple of (code_verifier, code_challange).
  """
  verifier = secrets.token_urlsafe(64)[:128]
  challenge = create_s256_code_challenge(verifier)
  return verifier, challenge


def _token_expiry(token: dict[str, Any]) -> datetime | None:
  """Extract token expiry as a datetime from an OAuth token reponse."""
  if "expires_at" in token and token["expires_at"]:
    return datetime.fromtimestamp(token["expires_at"], tz=timezone.utc)
  if "expires_in" in token and token["expires_in"]:
    return datetime.now(timezone.utc) + timedelta(seconds=token["expires_in"])
  return None


class OAuthProviderBase:
  """Base class for all OAuth 2.0 / OIDC providers.
 
  Subclasses set ``name``, ``authorize_url``, ``access_token_url``,
  ``userinfo_url``, and ``default_scopes``, and implement ``fetch_userinfo``.
  """

  name: str = ""
  authorize_url: str = ""
  access_token_url: str = ""
  userinfo_url: str | None = None
  default_scopes: list[str] = []

  def __init__(self, config: OAuthProviderConfig) -> None:
    self.config = config

  def _scopes(self) -> str:
    return " ".join(self.config.scopes or self.default_scopes)
  
  def build_authorization_url(self, state:str, code_challenge: str) -> None:
    """Build the provider's authorization URL with PKCE and state.
    
    Args:
        state:          CSRF-protection state value.
        code_challenge: S256 PKCE code challenge.

    Returns:
        The full authorization URL the user should be redirected to.
    """
    client = AsyncOAuth2Client(
      client_id=self.config.client_id,
      redirect_uri=self.config.redirect_uri,
      scope=self._scopes(),
    )
    url, _ =  client.create_authorization_url(
      self.authorize_url, state=state, code_challenge=code_challenge,
      code_challenge_method="S256"
    )
    return url
  
  async def exchange_code(self,code: str, code_verifier: str) -> dict[str, Any]:
    """Exchange an authorization code for an access token.

    Args:
        code:          The authorization code from the callback.
        code_verifier: The PKCE verifier generated at authorize time.

    Return:
        The raw toekn response dict (access_token, refresh_token, etc).

    Raises:
        Exception: Any HTTP or OAuth2 error from Authlib - callers should
                   catch broadly and raise OAuthCodeExchangeFailed.
    """
    client = AsyncOAuth2Client(
      client_id=self.config.client_id,
      client_secret=self.config.client_secret,
      redirect_uri=self.config.redirect_uri,
    )
    return await client.fetch_token(
      self.access_token_url, code=code, code_verifier=code_verifier,
    )

  async def fetch_userinfo(self, token: dict[str, Any]) -> OAuthUserInfo:
    """Fetch and normalize user info from the provider.
    
    Must be implemented by each subclass.

    Args:
        token: The token response dict from exchange_code().

    Returns:
        Normalized OAuthUserInfo.
    """
    raise NotImplementedError

  
class GoogleOAuthProvider(OAuthProviderBase):
  """Gogle OIDC provider - id_token + userinfo endpoint."""
  name             = "google"
  authorize_url    = "https://accounts.google.com/o/oauth2/v2/auth"
  access_token_url = "https://oauth2.googleapis.com/token"
  userinfo_url     = "https://openidconnect.googleapis.com/v1/userinfo"
  default_scopes   = ["openid", "email", "profile"]

  async def fetch_userinfo(self, token: dict[str, Any]) -> OAuthUserInfo:
    async with httpx.AsyncClient() as client:
      resp = await client.get(
        self.userinfo_url,
        headers={"Authorization": f"Bearer {token['access_token']}"},
      )
      resp.raise_for_status()
      data = resp.json()
    return OAuthUserInfo(
      provider=self.name,
      provider_user_id=data["sub"],
      email=data.get("email"),
      email_verified=data.get("email_verified", False),
      full_name=data.get("name"),
      first_name=data.get("given_name"),
      last_name=data.get("family_name"),
      avatar_url=data.get("picture"),
      raw=data,
    )
  

class FacebookOAuthProvider(OAuthProviderBase):
  """Fasebook OAuth2 provider - /me endpoint field selection"""
  name = "facebook"
  authorize_url = "https://www.facebook.com/v19.0/dialog/oauth"
  access_token_url = "https://graph.facebook.com/v19.0/oauth/access_token"
  userinfo_url = "https://graph.facebook.com/me"
  default_scopes = ["email", "public_profile"]

  async def fetch_userinfo(self, token: dict[str, Any]) -> OAuthUserInfo:
    async with httpx.AsyncClient() as client:
        resp = await client.get(
            self.userinfo_url,
            params={
                "fields": "id,name,email,first_name,last_name,picture",
                "access_token": token["access_token"],
            },
        )
        resp.raise_for_status()
        data = resp.json()
    picture = data.get("picture", {}).get("data", {}).get("url")
    return OAuthUserInfo(
        provider=self.name,
        provider_user_id=data["id"],
        email=data.get("email"),
        email_verified=bool(data.get("email")),
        full_name=data.get("name"),
        first_name=data.get("first_name"),
        last_name=data.get("last_name"),
        avatar_url=picture,
        raw=data,
    )
  

class GitHubOAuthProvider(OAuthProviderBase):
  """GitHub OAuth2 provider — /user endpoint, falls back to /user/emails."""

  name = "github"
  authorize_url = "https://github.com/login/oauth/authorize"
  access_token_url = "https://github.com/login/oauth/access_token"
  userinfo_url = "https://api.github.com/user"
  default_scopes = ["read:user", "user:email"]

  async def fetch_userinfo(self, token: dict[str, Any]) -> OAuthUserInfo:
    headers = {
        "Authorization": f"Bearer {token['access_token']}",
        "Accept": "application/vnd.github+json",
    }
    async with httpx.AsyncClient() as client:
      resp = await client.get(self.userinfo_url, headers=headers)
      resp.raise_for_status()
      data = resp.json()

      email = data.get("email")
      if not email:
          email_resp = await client.get(
              "https://api.github.com/user/emails", headers=headers
          )
          if email_resp.status_code == 200:
              emails = email_resp.json()
              primary = next((e for e in emails if e.get("primary")), None)
              if primary:
                  email = primary["email"]

    return OAuthUserInfo(
      provider=self.name,
      provider_user_id=str(data["id"]),
      email=email,
      email_verified=bool(email),
      full_name=data.get("name"),
      avatar_url=data.get("avatar_url"),
      raw=data,
    )

class MicrosoftOAuthProvider(OAuthProviderBase):
  """Microsoft OIDC provider — Azure AD / personal accounts."""

  name = "microsoft"
  authorize_url = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
  access_token_url = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
  userinfo_url = "https://graph.microsoft.com/oidc/userinfo"
  default_scopes = ["openid", "email", "profile"]

  async def fetch_userinfo(self, token: dict[str, Any]) -> OAuthUserInfo:
    async with httpx.AsyncClient() as client:
        resp = await client.get(
            self.userinfo_url,
            headers={"Authorization": f"Bearer {token['access_token']}"},
        )
        resp.raise_for_status()
        data = resp.json()
    return OAuthUserInfo(
        provider=self.name,
        provider_user_id=data["sub"],
        email=data.get("email"),
        email_verified=bool(data.get("email")),
        full_name=data.get("name"),
        avatar_url=None,
        raw=data,
    )


class LinkedInOAuthProvider(OAuthProviderBase):
  """LinkedIn OAuth2 provider — OIDC-compliant /userinfo endpoint."""

  name = "linkedin"
  authorize_url = "https://www.linkedin.com/oauth/v2/authorization"
  access_token_url = "https://www.linkedin.com/oauth/v2/accessToken"
  userinfo_url = "https://api.linkedin.com/v2/userinfo"
  default_scopes = ["openid", "email", "profile"]

  async def fetch_userinfo(self, token: dict[str, Any]) -> OAuthUserInfo:
    async with httpx.AsyncClient() as client:
        resp = await client.get(
            self.userinfo_url,
            headers={"Authorization": f"Bearer {token['access_token']}"},
        )
        resp.raise_for_status()
        data = resp.json()
    return OAuthUserInfo(
        provider=self.name,
        provider_user_id=data["sub"],
        email=data.get("email"),
        email_verified=data.get("email_verified", False),
        full_name=data.get("name"),
        first_name=data.get("given_name"),
        last_name=data.get("family_name"),
        avatar_url=data.get("picture"),
        raw=data,
    )


class DiscordOAuthProvider(OAuthProviderBase):
  """Discord OAuth2 provider — /users/@me endpoint."""

  name = "discord"
  authorize_url = "https://discord.com/api/oauth2/authorize"
  access_token_url = "https://discord.com/api/oauth2/token"
  userinfo_url = "https://discord.com/api/users/@me"
  default_scopes = ["identify", "email"]

  async def fetch_userinfo(self, token: dict[str, Any]) -> OAuthUserInfo:
    async with httpx.AsyncClient() as client:
        resp = await client.get(
            self.userinfo_url,
            headers={"Authorization": f"Bearer {token['access_token']}"},
        )
        resp.raise_for_status()
        data = resp.json()
    avatar_url = None
    if data.get("avatar"):
        avatar_url = f"https://cdn.discordapp.com/avatars/{data['id']}/{data['avatar']}.png"
    return OAuthUserInfo(
        provider=self.name,
        provider_user_id=data["id"],
        email=data.get("email"),
        email_verified=data.get("verified", False),
        full_name=data.get("username"),
        avatar_url=avatar_url,
        raw=data,
    )


class TwitterOAuthProvider(OAuthProviderBase):
  """X (Twitter) OAuth2 PKCE provider.

  Email is generally NOT available via standard OAuth2 scopes —
  requires special Twitter API approval. email will be None in
  most integrations; account linking handles this gracefully.
  """

  name = "twitter"
  authorize_url = "https://twitter.com/i/oauth2/authorize"
  access_token_url = "https://api.twitter.com/2/oauth2/token"
  userinfo_url = "https://api.twitter.com/2/users/me"
  default_scopes = ["tweet.read", "users.read", "offline.access"]

  async def fetch_userinfo(self, token: dict[str, Any]) -> OAuthUserInfo:
    async with httpx.AsyncClient() as client:
        resp = await client.get(
            self.userinfo_url,
            headers={"Authorization": f"Bearer {token['access_token']}"},
            params={"user.fields": "profile_image_url,verified"},
        )
        resp.raise_for_status()
        data = resp.json()["data"]
    return OAuthUserInfo(
        provider=self.name,
        provider_user_id=data["id"],
        email=None,  # not available via standard OAuth2 scopes
        email_verified=False,
        full_name=data.get("name"),
        avatar_url=data.get("profile_image_url"),
        raw=data,
    )
 

class AppleOAuthProvider(OAuthProviderBase):
  """Apple Sign In provider — OIDC with id_token only, no userinfo endpoint.

  Apple deviates significantly from standard OAuth2:

  - client_secret is a signed ES256 JWT, regenerated on every token exchange
    (5 minute TTL), never a static string.
  - name and email are ONLY provided on the FIRST login, via the POST body
    (form_post response_mode) — never again on subsequent logins. Pass
    ``post_body`` to ``fetch_userinfo`` to capture this on first login.
  - Private-relay emails (e.g. ``xyz@privaterelay.appleid.com``) are accepted
    and stored as-is.
  - JWKS is cached internally by PyJWKClient with a 1 hour lifespan —
    never fetched on every request.
  """

  name = "apple"
  authorize_url = "https://appleid.apple.com/auth/authorize"
  access_token_url = "https://appleid.apple.com/auth/token"
  userinfo_url = None
  default_scopes = ["name", "email"]
  jwks_url = "https://appleid.apple.com/auth/keys"

  _jwk_client: PyJWKClient | None = None  # class-level cache, shared across instances

  def __init__(
      self,
      config: OAuthProviderConfig,
      team_id: str,
      key_id: str,
      private_key_pem: str,
  ) -> None:
      super().__init__(config)
      self.team_id = team_id
      self.key_id = key_id
      self.private_key_pem = private_key_pem

  def _generate_client_secret(self) -> str:
    """Generate a fresh ES256-signed JWT client_secret (5 min TTL).

    Apple requires this in place of a static client_secret string.
    """
    now = int(time.time())
    payload = {
        "iss": self.team_id,
        "iat": now,
        "exp": now + 300,
        "aud": "https://appleid.apple.com",
        "sub": self.config.client_id,
    }
    return pyjwt.encode(
        payload, self.private_key_pem, algorithm="ES256",
        headers={"kid": self.key_id},
    )

  async def exchange_code(self, code: str, code_verifier: str) -> dict[str, Any]:
    """Exchange code for token, generating a fresh client_secret JWT first."""
    client_secret = self._generate_client_secret()
    client = AsyncOAuth2Client(
        client_id=self.config.client_id,
        client_secret=client_secret,
        redirect_uri=self.config.redirect_uri,
    )
    return await client.fetch_token(
        self.access_token_url, code=code, code_verifier=code_verifier,
    )

  def _get_jwk_client(self) -> PyJWKClient:
    """Return the cached PyJWKClient, creating it on first use.

    PyJWKClient caches fetched keys internally with a 1 hour lifespan —
    JWKS is never fetched on every request.
    """
    if AppleOAuthProvider._jwk_client is None:
        AppleOAuthProvider._jwk_client = PyJWKClient(self.jwks_url, lifespan=3600)
    return AppleOAuthProvider._jwk_client

  async def fetch_userinfo(
      self, token: dict[str, Any], post_body: dict[str, Any] | None = None
  ) -> OAuthUserInfo:
    """Decode and verify the id_token; extract name from POST body if present.

    Args:
        token:     Token response containing ``id_token``.
        post_body: Raw form POST body from the callback. Only present on
                    the user's FIRST authorization — contains ``user`` field
                    with name data. Pass this through on first login only.

    Returns:
        Normalized OAuthUserInfo. full_name is None on repeat logins
        since Apple does not resend it.
    """
    id_token = token["id_token"]
    jwk_client = self._get_jwk_client()
    signing_key = jwk_client.get_signing_key_from_jwt(id_token)
    claims = pyjwt.decode(
        id_token, signing_key.key, algorithms=["RS256"],
        audience=self.config.client_id, issuer="https://appleid.apple.com",
    )

    full_name = None
    if post_body and "user" in post_body:
        user_data = post_body["user"]
        if isinstance(user_data, str):
            import json
            user_data = json.loads(user_data)
        name = user_data.get("name", {})
        given = name.get("firstName", "")
        family = name.get("lastName", "")
        combined = f"{given} {family}".strip()
        full_name = combined or None

    return OAuthUserInfo(
        provider=self.name,
        provider_user_id=claims["sub"],
        email=claims.get("email"),
        email_verified=True,
        full_name=full_name,
        raw=dict(claims),
    )
 

def build_oauth_provider(
    name: str,
    config: OAuthProviderConfig,
    *,
    apple_team_id: str | None = None,
    apple_key_id: str | None = None,
    apple_private_key_pem: str | None = None,
) -> OAuthProviderBase:
    """Factory for constructing an OAuth provider instance by name.
 
    Args:
        name:   Provider key — "google", "facebook", "twitter", "apple",
                "github", "microsoft", "linkedin", "discord".
        config: Provider-specific OAuthProviderConfig.
        apple_team_id, apple_key_id, apple_private_key_pem:
                Required only when name == "apple".
 
    Returns:
        An instantiated provider.
 
    Raises:
        ValueError: If the provider name is unrecognized, or Apple's
                    extra credentials are missing.
    """
    if name == "apple":
        if not (apple_team_id and apple_key_id and apple_private_key_pem):
            raise ValueError(
                "Apple provider requires apple_team_id, apple_key_id, "
                "and apple_private_key_pem"
            )
        return AppleOAuthProvider(
            config, team_id=apple_team_id, key_id=apple_key_id,
            private_key_pem=apple_private_key_pem,
        )
 
    providers_map: dict[str, type[OAuthProviderBase]] = {
        "google": GoogleOAuthProvider,
        "facebook": FacebookOAuthProvider,
        "twitter": TwitterOAuthProvider,
        "github": GitHubOAuthProvider,
        "microsoft": MicrosoftOAuthProvider,
        "linkedin": LinkedInOAuthProvider,
        "discord": DiscordOAuthProvider,
    }
    cls = providers_map.get(name)
    if cls is None:
        raise ValueError(f"Unknown OAuth provider: {name}")
    return cls(config)
