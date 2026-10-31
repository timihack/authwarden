"""Replays the Phase 7 HTTP suite with Redis tokens instead of JWTs."""
import os

import pytest
import redis.asyncio as redis

from authwarden import AuthWarden
from authwarden.authentication.redis_strategy import RedisTokenStrategy
from tests import test_phase7 as phase7
from tests.test_phase7 import *  # noqa: F401,F403

REDIS_URL = os.environ.get("AUTHWARDEN_TEST_REDIS_URL")

pytestmark = pytest.mark.skipif(not REDIS_URL, reason="AUTHWARDEN_TEST_REDIS_URL is not set")


@pytest.fixture(autouse=True)
async def use_redis_tokens(monkeypatch):
    client = redis.from_url(REDIS_URL)
    await client.flushdb()

    def build(config, user_store, **kwargs):
        return AuthWarden(
            config=config,
            user_store=user_store,
            token_strategy=RedisTokenStrategy(config, client),
            **kwargs,
        )

    monkeypatch.setattr(phase7, "AuthWarden", build)
    yield
    await client.flushdb()
    await client.aclose()