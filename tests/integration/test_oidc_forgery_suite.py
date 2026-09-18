"""Token forgery suite (Ch. 60) against the verifier, with real Redis for the JWKS cache and replay."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import threading
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
import pytest
import redis
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from keystone.db.ids import uuid7
from keystone.db.redis import DependencyUnavailable, make_redis
from keystone.identity.jwks import (
    JwksCache,
    JwksUnavailable,
    KidUnknown,
    parse_jwks,
)
from keystone.identity.oidc import GitHubOidcVerifier, TokenRejected
from keystone.identity.replay import RedisReplayStore

pytestmark = pytest.mark.integration

ISSUER = "https://token.actions.githubusercontent.com"
AUDIENCE = "keystone-acme-prod-7f3a"
T0 = datetime(2026, 9, 19, 12, 0, 0, tzinfo=UTC)


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


class KeyPair:
    def __init__(self, kid: str, bits: int = 2048) -> None:
        self.kid = kid
        self.private = rsa.generate_private_key(public_exponent=65537, key_size=bits)
        self.public_pem = self.private.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def jwk(self) -> dict[str, Any]:
        entry: dict[str, Any] = json.loads(
            jwt.algorithms.RSAAlgorithm.to_jwk(self.private.public_key())
        )
        entry.update({"kid": self.kid, "use": "sig", "alg": "RS256"})
        return entry


class FakeOrigin:
    def __init__(self, *pairs: KeyPair) -> None:
        self.keys = [p.jwk() for p in pairs]
        self.fetches = 0
        self.fail = False
        self.body: bytes | None = None

    def fetch(self) -> bytes:
        self.fetches += 1
        if self.fail:
            raise JwksUnavailable("origin down")
        if self.body is not None:
            return self.body
        return json.dumps({"keys": self.keys}).encode()


class Clock:
    def __init__(self, start: datetime = T0) -> None:
        self.now = start

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += timedelta(seconds=seconds)


def good_claims(now: datetime, **overrides: Any) -> dict[str, Any]:
    ts = int(now.timestamp())
    claims: dict[str, Any] = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": "repo:acme/app:ref:refs/heads/main",
        "repository": "acme/app",
        "repository_owner": "acme",
        "repository_id": "42",
        "ref": "refs/heads/main",
        "sha": "0123abcd",
        "workflow_ref": "acme/app/.github/workflows/deploy.yml@refs/heads/main",
        "job_workflow_ref": "acme/app/.github/workflows/deploy.yml@refs/heads/main",
        "run_id": "1234",
        "run_attempt": "1",
        "actor": "octocat",
        "event_name": "push",
        "jti": "jti-" + uuid7().hex,
        "iat": ts - 10,
        "nbf": ts - 10,
        "exp": ts + 300,
    }
    claims.update(overrides)
    return {k: v for k, v in claims.items() if v is not None}


def sign(pair: KeyPair, claims: dict[str, Any], **headers: Any) -> str:
    return jwt.encode(claims, pair.private, algorithm="RS256", headers={"kid": pair.kid, **headers})


def craft(header: dict[str, Any], claims: dict[str, Any], signature: bytes) -> str:
    return ".".join(
        [
            _b64(json.dumps(header, separators=(",", ":")).encode()),
            _b64(json.dumps(claims, separators=(",", ":")).encode()),
            _b64(signature),
        ]
    )


@pytest.fixture
def setup(
    redis_client: redis.Redis,
) -> tuple[GitHubOidcVerifier, KeyPair, FakeOrigin, Clock, JwksCache]:
    pair = KeyPair("kid-1")
    origin = FakeOrigin(pair)
    clock = Clock()
    cache = JwksCache(redis_client, origin, clock=clock, sleep=lambda _: None)
    verifier = GitHubOidcVerifier(
        issuer=ISSUER,
        audience=AUDIENCE,
        jwks=cache,
        replay=RedisReplayStore(redis_client),
        clock=clock,
    )
    return verifier, pair, origin, clock, cache


def test_golden_token_yields_verified_identity(setup: Any) -> None:
    verifier, pair, origin, clock, _ = setup
    identity = verifier.verify(sign(pair, good_claims(clock.now)), decision_id=uuid7())
    assert identity.repository == "acme/app" and identity.repository_id == "42"
    assert identity.kid == "kid-1" and identity.verified_at == clock.now
    assert len(identity.jti_hash) == 32 and identity.claims["sub"].startswith("repo:acme/app")
    assert origin.fetches == 1


@pytest.mark.parametrize(
    ("mutate", "code"),
    [
        (lambda p, c: "not.a.jwt.at.all", "TOKEN_MALFORMED"),
        (lambda p, c: "", "TOKEN_MALFORMED"),
        (lambda p, c: "a." * 9000, "TOKEN_MALFORMED"),
        (lambda p, c: craft({"alg": "none", "kid": p.kid}, c, b""), "TOKEN_ALG_REJECTED"),
        (
            lambda p, c: craft({"alg": "none", "kid": p.kid, "typ": "JWT"}, c, b"x"),
            "TOKEN_ALG_REJECTED",
        ),
        (lambda p, c: sign(p, c, crit=["exp"]), "TOKEN_ALG_REJECTED"),
        (lambda p, c: sign(p, {**c, "iss": "https://evil.example"}), "TOKEN_ISSUER_REJECTED"),
        (lambda p, c: sign(p, {**c, "iss": ISSUER + "/"}), "TOKEN_ISSUER_REJECTED"),
        (
            lambda p, c: jwt.encode(c, p.private, algorithm="RS256", headers={"kid": "kid-999"}),
            "TOKEN_KID_UNKNOWN",
        ),
        (lambda p, c: jwt.encode(c, p.private, algorithm="RS256"), "TOKEN_KID_UNKNOWN"),
        (lambda p, c: sign(p, c)[:-6] + "AAAAAA", "TOKEN_SIGNATURE_INVALID"),
        (lambda p, c: ".".join(sign(p, c).split(".")[:2]) + ".", "TOKEN_SIGNATURE_INVALID"),
        (lambda p, c: sign(KeyPair("kid-1"), c), "TOKEN_SIGNATURE_INVALID"),  # same kid, other key
        (lambda p, c: sign(p, {**c, "exp": c["iat"] - 100}), "TOKEN_EXPIRED"),
        (lambda p, c: sign(p, {**c, "aud": "someone-else"}), "TOKEN_AUDIENCE_REJECTED"),
        (
            lambda p, c: sign(p, {**c, "aud": ["someone-else", "another"]}),
            "TOKEN_AUDIENCE_REJECTED",
        ),
        (
            lambda p, c: sign(p, {k: v for k, v in c.items() if k != "repository_id"}),
            "TOKEN_CLAIMS_INCOMPLETE",
        ),
        (lambda p, c: sign(p, {**c, "run_id": 1234}), "TOKEN_CLAIMS_INCOMPLETE"),
        (lambda p, c: sign(p, {**c, "actor": ""}), "TOKEN_CLAIMS_INCOMPLETE"),
        (
            lambda p, c: sign(p, {k: v for k, v in c.items() if k != "jti"}),
            "TOKEN_CLAIMS_INCOMPLETE",
        ),
        (lambda p, c: sign(p, {**c, "exp": "soon"}), "TOKEN_CLAIMS_INCOMPLETE"),
        (lambda p, c: sign(p, {**c, "exp": True}), "TOKEN_CLAIMS_INCOMPLETE"),
    ],
)
def test_forgeries_are_rejected_with_the_spec_code(setup: Any, mutate: Any, code: str) -> None:
    verifier, pair, _, clock, _ = setup
    with pytest.raises(TokenRejected) as info:
        verifier.verify(mutate(pair, good_claims(clock.now)), decision_id=uuid7())
    assert info.value.code == code
    assert info.value.http_status == 401


def test_hs256_key_confusion_is_rejected_before_any_key_is_touched(setup: Any) -> None:
    verifier, pair, origin, clock, _ = setup
    claims = good_claims(clock.now)
    header = {"alg": "HS256", "kid": pair.kid, "typ": "JWT"}
    signing_input = ".".join(
        [
            _b64(json.dumps(header, separators=(",", ":")).encode()),
            _b64(json.dumps(claims, separators=(",", ":")).encode()),
        ]
    )
    mac = hmac.new(pair.public_pem, signing_input.encode(), hashlib.sha256).digest()
    with pytest.raises(TokenRejected) as info:
        verifier.verify(signing_input + "." + _b64(mac), decision_id=uuid7())
    assert info.value.code == "TOKEN_ALG_REJECTED"
    assert origin.fetches == 0  # rejected pre-crypto, no JWKS lookup


def test_payload_mutation_after_signing_is_detected(setup: Any) -> None:
    verifier, pair, _, clock, _ = setup
    token = sign(pair, good_claims(clock.now))
    header, _, signature = token.split(".")
    forged = json.dumps(
        {**good_claims(clock.now), "repository": "acme/other"}, separators=(",", ":")
    )
    with pytest.raises(TokenRejected, match="TOKEN_SIGNATURE_INVALID"):
        verifier.verify(".".join([header, _b64(forged.encode()), signature]), decision_id=uuid7())


@pytest.mark.parametrize(
    ("shift", "field", "ok"),
    [
        (-59, "exp", True),  # expired 59 s ago: inside skew
        (-61, "exp", False),
        (+59, "nbf", True),
        (+61, "nbf", False),
        (+59, "iat", True),
        (+61, "iat", False),
        (-899, "iat", True),
        (-901, "iat", False),  # iat sanity floor (Ch. 31)
    ],
)
def test_skew_boundaries(setup: Any, shift: int, field: str, ok: bool) -> None:
    verifier, pair, _, clock, _ = setup
    ts = int(clock.now.timestamp())
    claims = good_claims(clock.now)
    claims[field] = ts + shift
    if field == "iat" and shift < 0:
        claims["nbf"] = claims["iat"]
    token = sign(pair, claims)
    if ok:
        verifier.verify(token, decision_id=uuid7())
    else:
        with pytest.raises(TokenRejected) as info:
            verifier.verify(token, decision_id=uuid7())
        assert info.value.code in {"TOKEN_EXPIRED", "TOKEN_NOT_YET_VALID", "TOKEN_IAT_INVALID"}


def test_audience_list_containing_ours_is_accepted(setup: Any) -> None:
    verifier, pair, _, clock, _ = setup
    verifier.verify(
        sign(pair, good_claims(clock.now, aud=["other", AUDIENCE])), decision_id=uuid7()
    )


def test_replay_is_409_and_only_after_everything_else_passed(setup: Any) -> None:
    verifier, pair, _, clock, _ = setup
    token = sign(pair, good_claims(clock.now))
    verifier.verify(token, decision_id=uuid7())
    with pytest.raises(TokenRejected) as info:
        verifier.verify(token, decision_id=uuid7())
    assert (info.value.code, info.value.http_status) == ("TOKEN_REPLAYED", 409)


def test_raw_token_never_appears_in_errors(setup: Any) -> None:
    verifier, pair, _, clock, _ = setup
    token = sign(pair, good_claims(clock.now, aud="wrong"))
    with pytest.raises(TokenRejected) as info:
        verifier.verify(token, decision_id=uuid7())
    assert token.split(".")[1] not in repr(info.value) and "wrong" not in str(info.value)


# ---------------------------------------------------------------- JWKS cache behaviour


def test_key_rotation_triggers_one_forced_refresh_then_rate_limits(setup: Any) -> None:
    verifier, pair, origin, clock, _ = setup
    verifier.verify(sign(pair, good_claims(clock.now)), decision_id=uuid7())
    assert origin.fetches == 1
    new_pair = KeyPair("kid-2")
    origin.keys.append(new_pair.jwk())
    verifier.verify(
        sign(new_pair, good_claims(clock.now)), decision_id=uuid7()
    )  # unknown kid -> refresh
    assert origin.fetches == 2
    with pytest.raises(TokenRejected, match="TOKEN_KID_UNKNOWN"):  # gate closed for 60 s
        verifier.verify(sign(KeyPair("kid-3"), good_claims(clock.now)), decision_id=uuid7())
    assert origin.fetches == 2


def test_tiers_and_stale_serving(setup: Any, redis_client: redis.Redis) -> None:
    verifier, pair, origin, clock, cache = setup
    verifier.verify(sign(pair, good_claims(clock.now)), decision_id=uuid7())
    cache._local = None  # drop the in-process tier: Redis tier must serve without an origin fetch
    verifier.verify(sign(pair, good_claims(clock.now)), decision_id=uuid7())
    assert origin.fetches == 1

    clock.advance(16 * 60)  # Redis freshness (15 min) elapsed, origin down: serve stale
    origin.fail = True
    cache._local = None
    verifier.verify(sign(pair, good_claims(clock.now)), decision_id=uuid7())
    assert cache.served_stale is True

    redis_client.delete("jwks:raw", "jwks:fresh_until")  # beyond the 6 h ceiling: cache gone
    cache._local = None
    with pytest.raises(JwksUnavailable):
        verifier.verify(sign(pair, good_claims(clock.now)), decision_id=uuid7())


def test_origin_poison_never_overwrites_a_valid_cache(setup: Any) -> None:
    verifier, pair, origin, clock, cache = setup
    verifier.verify(sign(pair, good_claims(clock.now)), decision_id=uuid7())
    for body in (b"{not json", b'{"keys": []}', b"x" * (64 * 1024 + 1)):
        origin.body = body
        clock.advance(16 * 60)
        cache._local = None
        verifier.verify(
            sign(pair, good_claims(clock.now)), decision_id=uuid7()
        )  # still the good keys
    origin.body = None


def test_jwks_parser_only_accepts_strong_rsa_signing_keys() -> None:
    weak = KeyPair("weak", bits=1024)
    strong = KeyPair("strong")
    ec_key = ec.generate_private_key(ec.SECP256R1()).public_key()
    ec_jwk = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(ec_key))
    ec_jwk["kid"] = "ec"
    enc = {**strong.jwk(), "kid": "enc", "use": "enc"}
    doc = json.dumps(
        {"keys": [weak.jwk(), strong.jwk(), ec_jwk, enc, "junk", {"kty": "RSA"}]}
    ).encode()
    keys = parse_jwks(doc)
    assert list(keys) == ["strong"]
    with pytest.raises(ValueError):
        parse_jwks(json.dumps({"keys": [weak.jwk()]}).encode())
    with pytest.raises(ValueError):
        parse_jwks(b"[]")


def test_concurrent_cold_start_fetches_origin_once(redis_client: redis.Redis) -> None:
    pair = KeyPair("kid-1")
    origin = FakeOrigin(pair)
    caches = [JwksCache(redis_client, origin, clock=Clock()) for _ in range(8)]
    results: list[Any] = []

    def resolve(cache: JwksCache) -> None:
        results.append(cache.resolve("kid-1"))

    threads = [threading.Thread(target=resolve, args=(c,)) for c in caches]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(results) == 8 and origin.fetches == 1


def test_redis_down_is_503_for_the_whole_path() -> None:
    pair = KeyPair("kid-1")
    dead = make_redis("redis://127.0.0.1:1/0", timeout_seconds=0.2)
    cache = JwksCache(dead, FakeOrigin(pair), clock=Clock())
    with pytest.raises(DependencyUnavailable):
        cache.resolve("kid-1")
    with pytest.raises(KidUnknown):
        JwksCache(make_redis("redis://localhost:56379/0"), FakeOrigin(pair), clock=Clock()).resolve(
            "nope"
        )
