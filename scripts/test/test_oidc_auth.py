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

import dataclasses
import json
import logging
import os
import subprocess
import threading
import urllib.parse
import urllib.request

import pytest
from error_types import LoreException, NotAuthenticatedError

from lore import Lore
from lore_server import (
    _kill_server_by_pid,
    allocate_free_port,
    generate_server_config,
    launch_lore_server,
)
from pocket_id import PocketIdClient

logger = logging.getLogger(__name__)

# The CLI's own no-browser ceiling is ~550s (lore-revision/src/auth/login.rs
# NO_BROWSER_POLLING_MAX_RETRIES); this leaves room to land within one poll
# interval of approval without waiting that ceiling out on a hang.
DEVICE_LOGIN_TIMEOUT = 60

# The provider group the OIDC test server maps to elevated permissions in its
# `local.toml` (see `oidc_lore_server`).
ADMIN_GROUP = "lore-smoke-admins"


@dataclasses.dataclass(frozen=True)
class OidcServer:
    """The OIDC-secured test server: its `lore://` remote plus the HTTP port,
    for the one test that checks the unauthenticated health endpoint."""

    remote_url: str
    http_port: int

    def __str__(self) -> str:  # keeps `_oidc_repo(...)`-style call sites simple
        return self.remote_url


def _oidc_repo(new_lore_repo, remote_url, isolated_store: bool = False) -> Lore:
    """A repo pointed at the OIDC server, with the credential store kept in the
    test's own directory: the key encrypting the token file defaults to the OS
    keyring, which on macOS blocks a CLI login behind a GUI prompt no test can
    answer.

    `isolated_store` gives the repo its own credential store rather than the
    module-shared one -- how a test embodies a *second user*, whose login must
    not be visible to the first user's repos."""
    repo: Lore = new_lore_repo(create_repo=False, remote_url=str(remote_url))
    repo.environment_vars.setdefault("LORE_AUTH_STORE", "fallback")
    if isolated_store:
        repo.environment_vars["LORE_AUTH_PATH"] = os.path.join(repo.path, ".auth-store")
    return repo


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

    # The permission mapping is a TOML table, which the LORE__ env overrides
    # cannot express (scalars only), so it rides the `local.toml` layer.
    local_toml = server_root / "lore-server" / "config" / "local.toml"
    local_toml.write_text(
        "[server.auth.oidc]\n"
        'groups_claim = "groups"\n'
        "\n"
        "[server.auth.oidc.permission_groups]\n"
        f'"{ADMIN_GROUP}" = ["obliterate", "migrate"]\n'
    )

    server_proc, server_log_path, server_log_fd = launch_lore_server(
        server_root, server_env, lore_server_executable_path
    )

    yield OidcServer(
        remote_url=f"lore://127.0.0.1:{ports['quic']}/",
        http_port=ports["http"],
    )

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
        repo = _oidc_repo(new_lore_repo, oidc_lore_server)

        with pytest.raises(NotAuthenticatedError):
            repo.repository_create()

    def test_no_browser_login_completes_the_device_flow(
        self, new_lore_repo, oidc_lore_server, pocket_id, pocket_id_user
    ):
        repo = _oidc_repo(new_lore_repo, oidc_lore_server)

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
        repo = _oidc_repo(new_lore_repo, oidc_lore_server)
        _, returncode = _login_no_browser(repo, pocket_id, pocket_id_user)
        assert returncode == 0

        repo.repository_create()  # must not raise

    def test_auth_info_then_logout_removes_the_local_credential(
        self, new_lore_repo, oidc_lore_server, pocket_id, pocket_id_user
    ):
        """`auth info` reports the logged-in identity, and after `logout` the
        same repository operation that just succeeded fails again."""
        repo = _oidc_repo(new_lore_repo, oidc_lore_server)
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
        lore-server/src/grpc/repository/v1/repository_delete.rs): it falls back to
        the same creator-ownership check an unconfigured server uses. This is
        the coverage for that fallback -- proving it completes cleanly rather
        than protocol-erroring the way an unguarded ReBAC dial would."""
        repo = _oidc_repo(new_lore_repo, oidc_lore_server)
        _, returncode = _login_no_browser(repo, pocket_id, pocket_id_user)
        assert returncode == 0
        repo.repository_create()

        repo.repository_delete()

        # A delete that silently did nothing also "does not raise", so the
        # server has to stop answering for the repository afterwards.
        with pytest.raises(LoreException):
            repo.repository_info()


@pytest.fixture(scope="module")
def pocket_id_admin(pocket_id):
    """A user in the admin group the OIDC test server maps to
    `obliterate` and `migrate` (see the `local.toml` in `oidc_lore_server`)."""
    user = pocket_id.create_user("loreadmin")
    pocket_id.add_user_to_group(user, pocket_id.ensure_group(ADMIN_GROUP))
    return user


def _logged_in_repo(new_lore_repo, server, pocket_id, user, isolated_store=False):
    """A repo whose credential store holds `user`'s login."""
    repo = _oidc_repo(new_lore_repo, server, isolated_store=isolated_store)
    _, returncode = _login_no_browser(repo, pocket_id, user)
    assert returncode == 0, f"login as {user['username']} failed"
    return repo


def _clone_repository_as(user_repo: Lore, source: Lore) -> Lore:
    """Clone `source`'s repository as `user_repo`'s user, keeping that user's
    credential store: how a *second user* obtains a working copy of a
    repository somebody else created."""
    user_repo.remote_path = source.remote_path
    cloned = user_repo.clone()
    # `clone()` does not carry environment overrides onto the new instance,
    # and the credential store is exactly what must not be shared here.
    cloned.environment_vars = dict(user_repo.environment_vars)
    return cloned


def _commit_file(repo: Lore, name: str, content: str) -> str:
    """Write, stage, and commit one file; returns its path within the repo."""
    file_path = os.path.join(repo.path, name)
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(content)
    repo.stage(name)
    repo.commit(f"add {name}")
    repo.push()
    return name


@pytest.mark.smoke
class TestOidcAuthorizationBoundaries:
    """The operations that run *narrower* than the all-repositories grant.

    `authorize_all_repositories = true` deliberately lets every authenticated
    identity read and write every repository, so most owner/non-owner
    distinctions do not exist. These tests pin the ones that do: repository
    delete (creator only), obliterate and admin locking (mapped groups only),
    and releasing another user's lock (owner only)."""

    def test_non_creator_cannot_delete_repository(
        self, new_lore_repo, oidc_lore_server, pocket_id, pocket_id_user
    ):
        creator = _logged_in_repo(
            new_lore_repo, oidc_lore_server, pocket_id, pocket_id_user
        )
        creator.repository_create()

        other_user = pocket_id.create_user("loreother")
        other = _logged_in_repo(
            new_lore_repo, oidc_lore_server, pocket_id, other_user, isolated_store=True
        )
        other.repository_create()

        with pytest.raises(LoreException):
            other.repository_delete(creator.name)

        # The refusal must have left the repository standing.
        creator.repository_info()
        creator.repository_delete()

    def test_obliterate_is_denied_without_a_mapped_group(
        self, new_lore_repo, oidc_lore_server, pocket_id, pocket_id_user
    ):
        """The all-repositories wildcard carries no `obliterate` permission, so
        even a repository's own creator cannot rewrite history without a
        mapped group."""
        repo = _logged_in_repo(new_lore_repo, oidc_lore_server, pocket_id, pocket_id_user)
        repo.repository_create()
        name = _commit_file(repo, "history.txt", "do not rewrite me")

        with pytest.raises(LoreException):
            repo.file_obliterate(path=name)

    def test_admin_group_member_can_obliterate(
        self, new_lore_repo, oidc_lore_server, pocket_id, pocket_id_admin
    ):
        """Membership in the mapped provider group grants `obliterate` end to
        end: PocketID puts the group in the ID token (via the scope the server
        advertises), and the server maps it to the permission the admin
        service checks."""
        repo = _logged_in_repo(
            new_lore_repo, oidc_lore_server, pocket_id, pocket_id_admin
        )
        repo.repository_create()
        name = _commit_file(repo, "regrettable.txt", "rewrite me")

        repo.file_obliterate(path=name)  # must not raise

    def test_lock_held_by_another_user_cannot_be_released(
        self, new_lore_repo, oidc_lore_server, pocket_id, pocket_id_user
    ):
        """Lock ownership is enforced between OIDC identities: without the
        `owner`/`admin` permission, releasing somebody else's lock is refused."""
        creator = _logged_in_repo(
            new_lore_repo, oidc_lore_server, pocket_id, pocket_id_user
        )
        creator.repository_create()
        name = _commit_file(creator, "locked.txt", "mine")
        creator.lock_acquire(paths=[name])

        other_user = pocket_id.create_user("lorelock")
        other_base = _logged_in_repo(
            new_lore_repo, oidc_lore_server, pocket_id, other_user, isolated_store=True
        )
        other = _clone_repository_as(other_base, creator)

        with pytest.raises(LoreException):
            other.lock_release(paths=[name])

        # The lock survives the refused release, and its owner can release it.
        creator.lock_release(paths=[name])


@pytest.mark.smoke
class TestOidcUserJourney:
    """The full workflow a real user runs, end to end against the secured
    server: create, commit, push, and a second user pulling the result. This
    is the only place the QUIC storage path runs under OIDC."""

    def test_full_workflow_two_users(
        self, new_lore_repo, oidc_lore_server, pocket_id, pocket_id_user
    ):
        first = _logged_in_repo(
            new_lore_repo, oidc_lore_server, pocket_id, pocket_id_user
        )
        first.repository_create()
        _commit_file(first, "hello.txt", "from the first user")

        # A second identity clones the repository -- under the coarse grant,
        # every authenticated identity may -- and sees the content.
        second_user = pocket_id.create_user("lorepeer")
        second_base = _logged_in_repo(
            new_lore_repo, oidc_lore_server, pocket_id, second_user, isolated_store=True
        )
        second = _clone_repository_as(second_base, first)
        cloned_file = os.path.join(second.path, "hello.txt")
        with open(cloned_file, encoding="utf-8") as f:
            assert f.read() == "from the first user"

        # And writes back, which the first user can sync.
        _commit_file(second, "reply.txt", "from the second user")
        first.sync()
        replied = os.path.join(first.path, "reply.txt")
        with open(replied, encoding="utf-8") as f:
            assert f.read() == "from the second user"

    def test_repository_creator_is_the_login_identity(
        self, new_lore_repo, oidc_lore_server, pocket_id, pocket_id_user
    ):
        """The server records the authenticated `sub` as the repository's
        creator -- the value the delete check compares against."""
        repo = _logged_in_repo(new_lore_repo, oidc_lore_server, pocket_id, pocket_id_user)
        repo.repository_create()

        info = repo.repository_info()
        assert pocket_id_user["id"] in info, (
            f"repository info does not attribute the creator to the login "
            f"identity: {info}"
        )


@pytest.mark.smoke
class TestOidcSessionLifecycle:
    def test_relogin_replaces_the_credential(
        self, new_lore_repo, oidc_lore_server, pocket_id, pocket_id_user
    ):
        """A second login over an existing credential works cleanly -- the
        stored bucket is replaced, not corrupted."""
        repo = _logged_in_repo(new_lore_repo, oidc_lore_server, pocket_id, pocket_id_user)
        repo.repository_create()

        _, returncode = _login_no_browser(repo, pocket_id, pocket_id_user)
        assert returncode == 0

        repo.repository_info()  # the replacing credential works

    def test_auth_clear_removes_the_credential(
        self, new_lore_repo, oidc_lore_server, pocket_id, pocket_id_user
    ):
        """`auth clear` wipes the store: operations fail afterwards and no
        stored refresh token resurrects the session."""
        repo = _logged_in_repo(new_lore_repo, oidc_lore_server, pocket_id, pocket_id_user)
        repo.repository_create()

        repo.run(urc_args=["auth", "clear"])

        with pytest.raises(NotAuthenticatedError):
            repo.repository_info()


@pytest.mark.smoke
class TestOidcFailureModes:
    def test_health_check_stays_open_when_secured(self, oidc_lore_server):
        """The one endpoint the how-to promises stays unauthenticated."""
        response = urllib.request.urlopen(
            f"http://127.0.0.1:{oidc_lore_server.http_port}/health_check", timeout=10
        )
        assert response.status == 200
