# SPDX-FileCopyrightText: 2026 Epic Games, Inc.
# SPDX-License-Identifier: MIT
"""PocketID fixture for the e2e suite.

Talks to the `pocket-id` service in `lore-integration-tests/compose.yaml`; unlike
`lore_server.py` it never spawns anything, because compose owns the container's
lifecycle. Bring it up with:

    docker compose --file lore-integration-tests/compose.yaml up --detach pocket-id

PocketID's only interactive login is a passkey ceremony, which pytest cannot drive.
Everything here goes around it using documented endpoints only: the container is
started with `STATIC_API_KEY`, which provisions an admin on first boot (so there is
no setup wizard), and a user is logged in by minting a one-time access token as that
admin and exchanging it for the session cookie a passkey login would have produced.
With the cookie, `POST /api/oidc/authorize` returns an authorization code without
rendering any HTML.

Every token handed out here is minted and signed by PocketID. Nothing is faked.
"""

import base64
import hashlib
import http.cookies
import json
import logging
import os
import secrets
import urllib.error
import urllib.parse
import urllib.request
from time import sleep

import pytest

logger = logging.getLogger(__name__)

# Must match the port published for `pocket-id` in lore-integration-tests/compose.yaml.
POCKET_ID_URL = os.getenv("LORE_TEST_POCKET_ID_URL", "http://127.0.0.1:1411")

# NOTE: this is just hardcoded in lore-integration-tests/compose.yaml as STATIC_API_KEY.
STATIC_API_KEY = "lorelocaltestapikeylorelocaltestapikey"

# PocketID accepts a caller-chosen client id, so this stays stable across runs and
# across `docker compose down -v` — a server config can name it without a lookup.
TEST_CLIENT_ID = "lore-integration-tests"

# PocketID validates redirects against the client's registered callbacks, but nothing
# listens here: the code comes back in the authorize response, not via a redirect.
TEST_REDIRECT_URI = "http://127.0.0.1:19999/callback"

SCOPE = "openid profile email"


class PocketIdError(Exception):
    """A PocketID request failed."""


class PocketIdClient:
    """Provisions users and issues real OIDC tokens against a running PocketID."""

    def __init__(self, base_url: str = POCKET_ID_URL, api_key: str = STATIC_API_KEY):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key

    # -----------------------------------------------------------------------
    # Transport
    # -----------------------------------------------------------------------

    def _request(
        self,
        method: str,
        path: str,
        body=None,
        headers: dict | None = None,
        form: bool = False,
        admin: bool = False,
    ) -> tuple[int, dict, dict]:
        request_headers = dict(headers or {})
        if admin:
            request_headers["X-API-KEY"] = self.api_key

        data = None
        if body is not None:
            if form:
                data = urllib.parse.urlencode(body).encode()
                request_headers["Content-Type"] = "application/x-www-form-urlencoded"
            else:
                data = json.dumps(body).encode()
                request_headers["Content-Type"] = "application/json"

        request = urllib.request.Request(
            self.base_url + path, data=data, headers=request_headers, method=method
        )
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                payload = response.read()
                return (
                    response.status,
                    dict(response.headers),
                    json.loads(payload) if payload else {},
                )
        except urllib.error.HTTPError as e:
            # PocketID explains validation failures in the body and nowhere else.
            detail = e.read().decode(errors="replace")
            raise PocketIdError(
                f"{method} {path} failed with {e.code}: {detail}"
            ) from e

    # -----------------------------------------------------------------------
    # Readiness and provisioning
    # -----------------------------------------------------------------------

    def wait_until_ready(self, retries: int = 30, delay: float = 1.0) -> None:
        """Poll /healthz until the container serves. Compose's healthcheck already
        gates startup, but a manually started container has nothing waiting on it."""
        for attempt in range(1, retries + 1):
            try:
                self._request("GET", "/healthz")
                logger.info("PocketID ready on attempt %d", attempt)
                return
            except (PocketIdError, OSError, json.JSONDecodeError) as e:
                # /healthz answers 204 with no body, so a JSON decode error means
                # it answered — that is ready, not a failure.
                if isinstance(e, json.JSONDecodeError):
                    return
                logger.debug("PocketID not ready on attempt %d: %s", attempt, e)
            sleep(delay)

        raise PocketIdError(
            f"PocketID at {self.base_url} did not become healthy. Start it with: "
            "docker compose --file lore-integration-tests/compose.yaml up --detach pocket-id"
        )

    @property
    def issuer(self) -> str:
        """The issuer PocketID signs tokens with, for a server's OIDC config."""
        return self.base_url

    def discovery(self) -> dict:
        _, _, document = self._request("GET", "/.well-known/openid-configuration")
        return document

    def ensure_client(
        self, client_id: str = TEST_CLIENT_ID, callback_urls: list[str] | None = None
    ) -> str:
        """Register a public PKCE client, tolerating one that is already there.

        The container outlives a single test session, and xdist workers race each
        other, so an existing client is the normal case rather than a failure.
        """
        try:
            self._request(
                "POST",
                "/api/oidc/clients",
                {
                    "id": client_id,
                    "name": client_id,
                    "callbackURLs": callback_urls or [TEST_REDIRECT_URI],
                    # Public + PKCE is what a CLI is: no client secret to ship.
                    "isPublic": True,
                    "pkceEnabled": True,
                },
                admin=True,
            )
        except PocketIdError as e:
            if "already in use" not in str(e):
                raise
        return client_id

    def create_user(self, prefix: str = "loretest") -> dict:
        """Provision a user. The random suffix keeps parallel workers from colliding
        on the username and email, both of which PocketID requires to be unique."""
        username = f"{prefix}{secrets.token_hex(6)}"
        _, _, user = self._request(
            "POST",
            "/api/users",
            {
                "username": username,
                "email": f"{username}@example.invalid",
                "emailVerified": True,
                "firstName": "Lore",
                "lastName": "Test",
                "isAdmin": False,
            },
            admin=True,
        )
        logger.info("Provisioned PocketID user %s (%s)", username, user["id"])
        return user

    # -----------------------------------------------------------------------
    # Login and token issuance
    # -----------------------------------------------------------------------

    def login(self, user: dict) -> str:
        """Log `user` in without a passkey and return the session cookie header value.

        The cookie is passed around by hand rather than kept in a cookie jar because
        PocketID marks it Secure even when serving plain HTTP, which a conforming
        cookie store drops on an http:// origin.
        """
        _, _, token = self._request(
            "POST",
            f"/api/users/{user['id']}/one-time-access-token",
            {"ttl": "1h"},
            admin=True,
        )

        # Unauthenticated by design: holding the one-time token *is* the credential.
        _, headers, _ = self._request(
            "POST", f"/api/one-time-access-token/{token['token']}"
        )
        jar = http.cookies.SimpleCookie()
        jar.load(headers.get("Set-Cookie", ""))
        for name in ("access_token", "__Host-access_token"):
            # The name depends on APP_URL's scheme: the __Host- prefix is https only.
            if name in jar:
                return f"{name}={jar[name].value}"

        raise PocketIdError(
            f"Exchanging the one-time access token set no session cookie "
            f"(got {list(jar.keys())})"
        )

    def issue_token(self, user: dict, client_id: str = TEST_CLIENT_ID) -> dict:
        """Complete an authorization-code + PKCE exchange as `user`.

        Returns PocketID's token response: access_token, id_token, refresh_token.
        """
        session_cookie = self.login(user)

        verifier = _b64url(secrets.token_bytes(32))
        challenge = _b64url(hashlib.sha256(verifier.encode()).digest())
        nonce = secrets.token_hex(16)

        # The endpoint PocketID's own web UI calls once a user approves the client.
        # With a session cookie it needs no browser and renders no HTML.
        _, _, authorization = self._request(
            "POST",
            "/api/oidc/authorize",
            {
                "clientID": client_id,
                "scope": SCOPE,
                "callbackURL": TEST_REDIRECT_URI,
                "nonce": nonce,
                "codeChallenge": challenge,
                "codeChallengeMethod": "S256",
            },
            headers={"Cookie": session_cookie},
        )
        if "code" not in authorization:
            raise PocketIdError(f"Authorize returned no code: {authorization}")

        _, _, tokens = self._request(
            "POST",
            "/api/oidc/token",
            {
                "grant_type": "authorization_code",
                "code": authorization["code"],
                "redirect_uri": TEST_REDIRECT_URI,
                "client_id": client_id,
                "code_verifier": verifier,
            },
            form=True,
        )
        tokens["nonce"] = nonce
        return tokens

    def start_device_authorization(self, client_id: str = TEST_CLIENT_ID) -> dict:
        """Begin an RFC 8628 device authorization, as a headless client would."""
        _, _, response = self._request(
            "POST",
            "/api/oidc/device/authorize",
            {"client_id": client_id, "scope": SCOPE},
            form=True,
        )
        return response

    def approve_user_code(self, user: dict, user_code: str) -> None:
        """Approve a device user code as `user`.

        This is the half of `lore login --no-browser` a human would otherwise do:
        the CLI prints a user code, and this approves it. Poll the token endpoint
        with the matching device_code afterwards to collect the tokens.
        """
        session_cookie = self.login(user)
        self._request(
            "POST",
            "/api/oidc/device/verify?code=" + urllib.parse.quote(user_code),
            headers={"Cookie": session_cookie},
        )

    # -----------------------------------------------------------------------
    # Verification
    # -----------------------------------------------------------------------

    def validate_token(self, token: str, audience: str = TEST_CLIENT_ID) -> dict:
        """Verify a token's RS256 signature against the issuer's published JWKS and
        return its claims, the way a server would.

        The JWKS URL is followed from the discovery document rather than assumed, so
        a token that passes here passes through the path the Lore server uses. The
        RSA check is done by hand to keep the e2e suite free of a crypto dependency.
        """
        discovery = self.discovery()
        _, _, jwks = self._request(
            "GET", urllib.parse.urlparse(discovery["jwks_uri"]).path
        )

        header_b64, claims_b64, signature_b64 = token.split(".")
        header = json.loads(_b64url_decode(header_b64))
        claims = json.loads(_b64url_decode(claims_b64))

        if header.get("alg") != "RS256":
            raise PocketIdError(f"Unexpected signing algorithm: {header.get('alg')}")

        key = next((k for k in jwks["keys"] if k["kid"] == header["kid"]), None)
        if key is None:
            raise PocketIdError(f"JWKS has no key for kid {header['kid']}")

        modulus = int.from_bytes(_b64url_decode(key["n"]), "big")
        exponent = int.from_bytes(_b64url_decode(key["e"]), "big")
        signature = int.from_bytes(_b64url_decode(signature_b64), "big")

        size = (modulus.bit_length() + 7) // 8
        recovered = pow(signature, exponent, modulus).to_bytes(size, "big")
        digest = hashlib.sha256(f"{header_b64}.{claims_b64}".encode()).digest()
        # PKCS#1 v1.5: 0x00 0x01 <0xff padding> 0x00 <SHA-256 DigestInfo> <digest>
        digest_info = bytes.fromhex("3031300d060960864801650304020105000420")
        padding_len = size - 3 - len(digest_info) - len(digest)
        expected = b"\x00\x01" + b"\xff" * padding_len + b"\x00" + digest_info + digest
        if recovered != expected:
            raise PocketIdError("Token signature did not verify against the JWKS")

        if claims["iss"] != discovery["issuer"]:
            raise PocketIdError(
                f"Token issuer {claims['iss']} is not {discovery['issuer']}"
            )
        # PocketID sends aud as an array, so a string compare would always fail.
        if audience not in claims["aud"]:
            raise PocketIdError(
                f"Token audience {claims['aud']} does not include {audience}"
            )

        return claims


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


@pytest.fixture(scope="session")
def pocket_id():
    """A ready PocketID with the shared OIDC client registered.

    Skips rather than fails when the container is not up, so the rest of the suite
    still runs on a machine without the compose stack.
    """
    client = PocketIdClient()
    try:
        client.wait_until_ready(retries=5)
    except PocketIdError as e:
        pytest.skip(str(e))

    client.ensure_client()
    return client


@pytest.fixture(scope="function")
def pocket_id_user(pocket_id):
    """A freshly provisioned PocketID user, unique per test."""
    return pocket_id.create_user()
