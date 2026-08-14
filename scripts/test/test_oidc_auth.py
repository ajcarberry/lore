# SPDX-FileCopyrightText: 2026 Epic Games, Inc.
# SPDX-License-Identifier: MIT
"""End-to-end coverage for OIDC-secured Lore servers.

Spawns a dedicated `loreserver` configured with `[server.auth.oidc]` against
the shared PocketID fixture (`pocket_id.py`) on its own ports, then drives the
real `lore` CLI through both login flows and a repository operation. This
proves the whole chain end to end, including `exchange_for_repository` in
`lore-transport/src/auth/exchange.rs`:
`test_authenticated_repository_operation_succeeds` below is the first op
after login to call it, rather than the login path.

The PKCE browser flow opens a real browser, which this suite cannot drive.
Its live-provider coverage lives in
`lore-integration-tests/src/oidc_client_test.rs`
(`pkce_login_yields_a_verifiable_id_token`). Only the device flow
(`--no-browser`), which the CLI can complete headlessly by printing a URL a
fixture can approve in place of a human, is driven from here.

Local macOS caveat: the credential store falls back to the OS keychain
(`lore-credential`'s `keyring::Entry`), and on an unattended macOS session
with no one able to answer the resulting Keychain access prompt, that call
blocks with no timeout of its own. `_login_no_browser`'s watchdog thread
below kills the CLI after `DEVICE_LOGIN_TIMEOUT` regardless, so a login-
dependent test fails cleanly rather than hanging -- it is not a product bug
(this is not the mechanism CI runs under, and an attended run, or one with
Keychain access already granted to the built binary, passes normally).
"""

import json
import logging
import os
import subprocess
import threading
import urllib.parse

import pytest
from error_types import NotAuthenticatedError

from lore import Lore
from lore_server import (
    _kill_server_by_pid,
    allocate_free_port,
    generate_server_config,
    launch_lore_server,
)
from pocket_id import PocketIdClient

logger = logging.getLogger(__name__)

# The CLI's own ceiling is ~150s (lore-revision/src/auth/login.rs
# POLLING_INTERVAL_SECS / POLLING_MAX_RETRIES); this leaves room to land within
# one poll interval of approval without waiting that ceiling out on a hang.
DEVICE_LOGIN_TIMEOUT = 60


@pytest.fixture(scope="module")
def oidc_lore_server(request, tmp_path_factory, pocket_id, lore_server_executable_path):
    """A dedicated loreserver secured with `[server.auth.oidc]` against the
    shared PocketID fixture, on its own ports so it doesn't disturb the
    autouse authless server the rest of the suite relies on. Yields the
    server's `lore://` remote URL."""
    # QUIC and GRPC share one port by convention (UDP vs TCP; no collision) --
    # `lore://` URLs resolve to this shared port number.
    shared_port = allocate_free_port()
    ports = {
        "quic": shared_port,
        "grpc": shared_port,
        "http": allocate_free_port(),
        "internal": allocate_free_port(),
    }
    server_root, server_env = generate_server_config(request, tmp_path_factory, ports)
    server_env["LORE__SERVER__AUTH__OIDC__ISSUER"] = pocket_id.issuer
    server_env["LORE__SERVER__AUTH__OIDC__CLIENT_ID"] = pocket_id.ensure_client()
    server_env["LORE__SERVER__AUTH__OIDC__AUTHORIZE_ALL_REPOSITORIES"] = "true"

    server_proc, server_log_path, server_log_fd = launch_lore_server(
        server_root, server_env, lore_server_executable_path
    )

    yield f"lore://127.0.0.1:{ports['quic']}/"

    _kill_server_by_pid(server_proc.pid, server_log_path, label="OIDC test server")
    server_log_fd.close()


def _login_no_browser(
    repo: Lore,
    pocket_id: PocketIdClient,
    user: dict,
    timeout: int = DEVICE_LOGIN_TIMEOUT,
) -> tuple[str, int]:
    """Drive `lore auth login --no-browser` to completion against a live
    PocketID, approving the device user code as `user` in place of the human
    who would otherwise read it off the printed URL.

    Runs the CLI directly via `Popen` rather than `Lore.run()`: the URL the
    device flow prints only exists for the few seconds before a human (or
    this fixture) approves it, so the test has to read the CLI's stdout while
    it is still running rather than waiting for the whole command to exit.
    Returns the combined output and exit code.
    """
    command_args = [
        repo.lore_executable_path,
        "--repository",
        repo.path,
        "--json",
        "auth",
        "login",
        repo.remote_path,
        "--no-browser",
    ]
    env = dict(repo.environment_vars)
    env.setdefault("LORE_GLOBAL_PATH", repo.global_dir)
    env.setdefault("LORE_AUTH_PATH", repo.global_dir)

    process = subprocess.Popen(
        command_args,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        env={**os.environ, **env},
    )
    # `for line in process.stdout` blocks on the next read, so an elapsed-time
    # check inside the loop never fires once the CLI stops producing output. A
    # watchdog thread that kills the process closes the pipe, bounding the loop.
    finished = threading.Event()
    timed_out = threading.Event()

    def _watchdog() -> None:
        if not finished.wait(timeout):
            timed_out.set()
            process.kill()

    watchdog = threading.Thread(target=_watchdog, daemon=True)
    watchdog.start()

    collected = ""
    approved = False
    try:
        for line in process.stdout:
            collected += line
            if not approved and '"tagName":"authUrl"' in line:
                login_url = json.loads(line)["data"]["url"]
                query = dict(
                    urllib.parse.parse_qsl(urllib.parse.urlparse(login_url).query)
                )
                user_code = query.get("code") or query.get("user_code")
                assert user_code, f"No user code in device login URL: {login_url}"
                pocket_id.approve_user_code(user, user_code)
                approved = True
        process.wait(timeout=5)
    finally:
        finished.set()
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()

    assert approved, f"Device login URL never appeared in output: {collected}"
    assert not timed_out.is_set(), (
        f"CLI did not finish within {timeout}s after the device code was "
        f"approved -- output so far: {collected}"
    )
    return collected, process.returncode


@pytest.mark.smoke
class TestOidcAuth:
    def test_repository_operation_fails_without_authentication(
        self, new_lore_repo, oidc_lore_server
    ):
        """A repository operation against an OIDC-secured server with no
        cached token must fail cleanly, not hang or crash."""
        repo: Lore = new_lore_repo(create_repo=False, remote_url=oidc_lore_server)

        with pytest.raises(NotAuthenticatedError):
            repo.repository_create()

    def test_no_browser_login_completes_the_device_flow(
        self, new_lore_repo, oidc_lore_server, pocket_id, pocket_id_user
    ):
        repo: Lore = new_lore_repo(create_repo=False, remote_url=oidc_lore_server)

        output, returncode = _login_no_browser(repo, pocket_id, pocket_id_user)

        assert returncode == 0, output
        assert "Authentication successful" in output or '"tagName":"complete"' in output

    def test_authenticated_repository_operation_succeeds(
        self, new_lore_repo, oidc_lore_server, pocket_id, pocket_id_user
    ):
        """The test that proves the exchange-path fix: login stores an
        OIDC-shaped `AuthenticationToken`, and `repository create` is the
        first operation to exercise `exchange_for_repository` ->
        `verify_jwt_usage_for_remote` on that stored token. Before the fix in
        `lore-transport/src/auth/exchange.rs`, this failed even though login
        (the previous test) succeeded."""
        repo: Lore = new_lore_repo(create_repo=False, remote_url=oidc_lore_server)
        _, returncode = _login_no_browser(repo, pocket_id, pocket_id_user)
        assert returncode == 0

        repo.repository_create()  # must not raise

    def test_auth_info_then_logout_revokes_access(
        self, new_lore_repo, oidc_lore_server, pocket_id, pocket_id_user
    ):
        """`auth info` reports the logged-in identity, and after `logout` the
        same repository operation that just succeeded fails again."""
        repo: Lore = new_lore_repo(create_repo=False, remote_url=oidc_lore_server)
        _, returncode = _login_no_browser(repo, pocket_id, pocket_id_user)
        assert returncode == 0
        # `auth info`/`logout` resolve their auth endpoint from the local repo's
        # stored config, not from LORE_REMOTE_URL, so the repo needs to exist.
        repo.repository_create()

        info = repo.run(urc_args=["auth", "info"])
        assert pocket_id_user["id"] in info

        repo.run(urc_args=["auth", "logout"])

        # Not `repository_create()` again: the repo the earlier call created
        # still exists locally, and that check runs before any network call.
        # `repository_info` re-queries the server every time.
        with pytest.raises(NotAuthenticatedError):
            repo.repository_info()

    def test_creator_can_delete_their_own_repository(
        self, new_lore_repo, oidc_lore_server, pocket_id, pocket_id_user
    ):
        """`repository delete` never dials the ReBAC service under OIDC (see
        lore-server/src/grpc/handlers/repository_delete.rs): it falls back to
        the same creator-ownership check an unconfigured server uses. This is
        the coverage for that fallback -- proving it completes cleanly rather
        than protocol-erroring the way an unguarded ReBAC dial would."""
        repo: Lore = new_lore_repo(create_repo=False, remote_url=oidc_lore_server)
        _, returncode = _login_no_browser(repo, pocket_id, pocket_id_user)
        assert returncode == 0
        repo.repository_create()

        repo.repository_delete()  # must not raise
