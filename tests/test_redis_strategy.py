import asyncio
import os

import pytest
import pytest_asyncio
import redis.asyncio as redis

from authwarden import AuthWarden, MemoryUserStore, WardenConfig
from authwarden.authentication.jwt import JWTHandler, MemoryTokenBlacklist
from authwarden.authentication.redis_strategy import RedisTokenStrategy
from authwarden.authentication.strategy import TokenStrategy
from authwarden.exceptions import InvalidToken, TokenRevoked

REDIS_URL = os.environ.get("AUTHWARDEN_TEST_REDIS_URL")

pytestmark = pytest.mark.skipif(not REDIS_URL, reason="AUTHWARDEN_TEST_REDIS_URL is not set")


def make_config(**overrides) -> WardenConfig:
    return WardenConfig(secret_key="redis-strategy-secret-key-32-byte", **overrides)


@pytest_asyncio.fixture
async def client():
    connection = redis.from_url(REDIS_URL)
    await connection.flushdb()
    yield connection
    await connection.flushdb()
    await connection.aclose()


@pytest.fixture
def strategy(client):
    return RedisTokenStrategy(make_config(), client)


async def test_issued_tokens_verify_with_their_claims(strategy):
    pair = await strategy.issue_token_pair("user-1", roles=["admin"], scopes=["posts:write"])

    access = await strategy.verify_token(pair.access_token)
    refresh = await strategy.verify_token(pair.refresh_token, expected_type="refresh")

    assert (access.sub, access.type, access.roles, access.scopes) == ("user-1", "access", ["admin"], ["posts:write"])
    assert refresh.type == "refresh"
    assert pair.access_token != pair.refresh_token


async def test_token_type_is_enforced(strategy):
    pair = await strategy.issue_token_pair("user-1")

    with pytest.raises(InvalidToken):
        await strategy.verify_token(pair.refresh_token)
    with pytest.raises(InvalidToken):
        await strategy.verify_token(pair.access_token, expected_type="refresh")


async def test_unknown_token_is_invalid(strategy):
    with pytest.raises(InvalidToken):
        await strategy.verify_token("not-a-real-token")


async def test_revoked_token_is_reported_as_revoked(strategy):
    pair = await strategy.issue_token_pair("user-1")

    await strategy.blacklist_token(pair.access_token)

    with pytest.raises(TokenRevoked):
        await strategy.verify_token(pair.access_token)
    assert (await strategy.verify_token(pair.refresh_token, expected_type="refresh")).sub == "user-1"


async def test_revoking_an_unknown_or_already_revoked_token_fails(strategy):
    pair = await strategy.issue_token_pair("user-1")
    await strategy.blacklist_token(pair.access_token)

    with pytest.raises(InvalidToken):
        await strategy.blacklist_token(pair.access_token)
    with pytest.raises(InvalidToken):
        await strategy.blacklist_token("not-a-real-token")


async def test_revoking_with_the_wrong_type_leaves_the_token_valid(strategy):
    pair = await strategy.issue_token_pair("user-1")

    with pytest.raises(InvalidToken):
        await strategy.blacklist_token(pair.access_token, expected_type="refresh")

    assert (await strategy.verify_token(pair.access_token)).sub == "user-1"


async def test_tokens_expire_with_the_redis_ttl(client):
    strategy = RedisTokenStrategy(make_config(access_token_ttl=1), client)
    pair = await strategy.issue_token_pair("user-1")

    await asyncio.sleep(1.5)

    with pytest.raises(InvalidToken):
        await strategy.verify_token(pair.access_token)


async def test_keys_expire_and_never_contain_the_raw_token(strategy, client):
    pair = await strategy.issue_token_pair("user-1")

    keys = [key async for key in client.scan_iter("authwarden:*")]

    assert len(keys) == 2
    for key in keys:
        assert await client.ttl(key) > 0
        stored = key.decode() + (await client.get(key)).decode()
        assert pair.access_token not in stored
        assert pair.refresh_token not in stored


async def test_revoked_marker_expires_with_the_token(strategy, client):
    pair = await strategy.issue_token_pair("user-1")
    await strategy.blacklist_token(pair.access_token)

    revoked = [key async for key in client.scan_iter("authwarden:revoked:*")]

    assert len(revoked) == 1
    assert 0 < await client.ttl(revoked[0]) <= strategy._config.access_token_ttl


async def test_both_strategies_satisfy_the_protocol(client):
    assert isinstance(JWTHandler(make_config()), TokenStrategy)
    assert isinstance(RedisTokenStrategy(make_config(), client), TokenStrategy)


async def test_the_facade_uses_the_given_strategy(strategy):
    warden = AuthWarden(config=make_config(), user_store=MemoryUserStore(), token_strategy=strategy)

    assert warden.token_strategy is strategy
    assert warden.jwt_handler is strategy


async def test_a_blacklist_cannot_be_combined_with_a_strategy(strategy):
    with pytest.raises(ValueError, match="token_blacklist"):
        AuthWarden(
            config=make_config(),
            user_store=MemoryUserStore(),
            token_strategy=strategy,
            token_blacklist=MemoryTokenBlacklist(),
        )


async def test_from_url_builds_a_working_strategy(client):
    strategy = RedisTokenStrategy.from_url(make_config(), REDIS_URL)

    pair = await strategy.issue_token_pair("user-1")

    assert (await strategy.verify_token(pair.access_token)).sub == "user-1"
    await strategy._redis.aclose()