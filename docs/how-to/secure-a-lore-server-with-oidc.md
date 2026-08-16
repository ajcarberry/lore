# Secure a Lore Server with OpenID Connect

A Lore Server with no authentication serves anyone who can reach the port: every identity is anonymous, and every repository is readable and writable. Point the server at an OpenID Connect provider to replace that with the directory you already run, so only your provider's users get in. Any conformant provider works; the examples use [PocketID](https://github.com/pocket-id/pocket-id), which is self-hosted and quick to stand up alongside Lore.

## Prerequisites

- A running `loreserver` you can restart and reconfigure. See [Deploy a local Lore Server](deploy-local-lore-server.md).
- The `lore` CLI on your PATH. See [Install the Lore CLI](install-lore-cli.md).
- An OpenID Connect provider reachable from the server and your workstation, with admin access to register a client.

## Steps

1. **Register a public client for Lore.**

    Lore is a native CLI, not a web app, so it registers as a public client with PKCE — no client secret to store or leak. In your provider, create an OIDC client with:

    - **Public client** enabled, with no client secret.
    - **PKCE** enabled.
    - A callback address of `http://127.0.0.1:*/callback`, where the browser login's loopback listener receives the redirect. Use the IP literal, not `localhost`, and allow **any port**: the CLI listens on a kernel-assigned port (RFC 8252 §7.3), so a fixed-port registration will not match. PocketID accepts the wildcard-port form; a provider that requires exact redirect-URI matches needs its loopback handling consulted.

    Set the ID-token lifetime in minutes, not hours. Lore presents that token and holds no revocation list, so a verified token works until it expires — a short lifetime bounds how long a revoked user keeps access. Clients refresh without prompting, so it costs users nothing.

    Note the client id and the provider's issuer address for the next step.

2. **Turn on authentication in the server config.**

    Add a `[server.auth.oidc]` block to the server's `local.toml`:

    ```toml
    [server.auth.oidc]
    issuer = "https://id.example.com"
    client_id = "lore"
    authorize_all_repositories = true
    ```

    `issuer` must match the value your provider publishes in its tokens' `iss` claim, byte for byte. The server checks it against the provider's discovery document at startup and refuses to start on a mismatch (unless an explicit `[server.auth.jwk].endpoint` skips the discovery fetch).

    > [!IMPORTANT]
    > `authorize_all_repositories = true` is the entire authorization model this mode offers: any identity your provider admits can read and write **every** repository on the server — no per-repository distinction, no read-only identity, no administrative separation. Run one server per trust boundary. The setting must be written down: omitting it (or setting it `false`) fails startup rather than deciding for you.

    > [!NOTE]
    > A token's `aud` claim names the client id, which identifies the application rather than the server. Two deployments that share an issuer and a client id share a credential-store bucket and accept each other's tokens — logging in to one evicts the other's token. Register a distinct client id per deployment.

3. **Restart the server and confirm it requires a token.**

    ```bash
    ~/.local/bin/loreserver --config /opt/loreserver/config
    ```

    From another terminal, any operation against the server should now fail with an authentication error:

    ```bash
    lore repository list lore://your-server.example.com:41337
    ```

    If it succeeds instead, the server isn't picking up the config change — check the config path and restart.

4. **Log in.**

    On a machine with a browser, `lore login` opens your provider's login page:

    ```bash
    lore login lore://your-server.example.com:41337/
    ```

    On a headless host, print a code to approve from another device instead:

    ```bash
    lore login lore://your-server.example.com:41337/ --no-browser
    ```

    > [!WARNING]
    > Only approve a code you retrieved yourself from a `lore login --no-browser` you ran yourself, and check that it matches the code on your provider's approval page.

    Lore stores the token in the encrypted credential store and refreshes it as it expires, so day-to-day commands don't ask you to log in again until the provider revokes the session.

5. **Confirm who you're logged in as.**

    ```bash
    lore auth info
    ```

    This prints the identity your provider's token carries. `lore auth logout` and `lore auth clear` remove stored tokens.

## Grant elevated permissions (optional)

A few operations require more than the all-repositories grant: obliterating history, locking as
another user, and releasing another user's lock. Map your provider's groups to them:

```toml
[server.auth.oidc]
# ...
groups_claim = "groups"

[server.auth.oidc.permission_groups]
"lore-admins" = ["obliterate", "migrate"]
```

> [!WARNING]
> The mapped group names are a security boundary. The server trusts the provider's group
> assignment, so a mapped name must be one only your provider's administrators can hand out:
> disable self-service group creation or reserve the mapped names, and point `groups_claim` at a
> claim your provider derives from directory membership, never from a user-editable attribute.

Configure your provider to include the group claim in the ID token (in PocketID, enable **User
Groups** as a claim for the client); the server asks logins to request the matching scope
automatically. Members of a mapped group get the listed permissions; everyone else keeps the
ordinary grant. If your provider names the scope differently from the claim, set `groups_scope`.
The grantable permissions are listed in the
[config reference](../reference/lore-server-config.md#authentication).

## Result

Every repository operation on the server — gRPC, HTTP, and QUIC alike — now requires a valid, unexpired token from your configured issuer. The `/health_check` endpoint stays open, and a client that hasn't logged in gets a clean authentication failure.

> [!NOTE]
> Your provider owns identity resolution, and this integration reads no directory beyond what a token carries. You can only look up your own identity: passing a user id to `lore auth info` reads the local credential store only, and an id that is not logged in on this machine is echoed back rather than resolved.

## See also

- [Lore Server config reference](../reference/lore-server-config.md#authentication) — every `[server.auth]` and `[server.auth.oidc]` field.
- [Lore CLI command reference](../reference/lore-cli-commands.md) — the full `lore auth` subcommand surface.
- [OIDC authentication proposal](../proposals/2026-08-13-oidc-authentication.md) — the design and its threat model.
- [Deploy a local Lore Server](deploy-local-lore-server.md) — get a server running before securing it.
