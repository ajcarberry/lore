# Secure a Lore server with OpenID Connect

A Lore server with no authentication configured serves anyone who can reach the port: every identity is anonymous, and every repository is readable and writable. Pointing the server at an OpenID Connect provider replaces that with the directory you already run.

In this guide, you'll register Lore as a client with your provider, turn on authentication in the server config, and log in with `lore login`, so that only your provider's users can reach your repositories. Any conformant provider works; the examples use [PocketID](https://github.com/pocket-id/pocket-id), which is self-hosted and quick to stand up alongside Lore.

## Prerequisites

- A running `loreserver` you can restart and reconfigure. See [Deploy a local Lore Server](deploy-local-lore-server.md).
- The `lore` CLI on your PATH. See [Install the Lore CLI](install-lore-cli.md).
- An OpenID Connect provider reachable from both the server and your workstation, with admin access to register a client.

## Steps

1. **Register a public client for Lore.**

    Lore is a native CLI, not a web app, so it registers as a public client using PKCE — there's no client secret to store or leak. In PocketID's admin UI, create an OIDC client with:

    - **Public client** enabled, with no client secret.
    - **PKCE** enabled.
    - A callback address of `http://127.0.0.1:*/callback`, where the browser login flow's loopback listener receives the redirect. PocketID accepts a wildcard port; other providers may need a fixed port or a range.

    Set the ID-token lifetime in minutes rather than hours — that's the token Lore presents by default. Lore holds no revocation list — a verified token works until it expires — so a short lifetime bounds how long a revoked user keeps access. Clients refresh without prompting, so it costs users nothing. If you bind tokens to a resource (step 3), shorten the access-token lifetime too, since that becomes the credential.

    Note the client id and your provider's issuer address for the next step.

2. **Turn on authentication in the server config.**

    Add a `[server.auth.oidc]` block to the server's `local.toml`:

    ```toml
    [server.auth.oidc]
    issuer = "https://id.example.com"
    client_id = "lore"
    authorize_all_repositories = true
    ```

    `issuer` must match the value your provider publishes in its own tokens' `iss` claim, byte for byte. The server checks it against the provider's discovery document at startup and refuses to start on a mismatch.

    > [!IMPORTANT]
    > `authorize_all_repositories = true` is the whole authorization model this mode offers: any identity your provider admits can read and write **every** repository on the server — no per-repository distinction, no read-only identity, no administrative separation. Run one server per trust boundary when repositories need different audiences. The setting has no default, so omitting it or setting it to `false` fails startup rather than deciding for you.

3. **Bind tokens to this deployment.**

    By default the token's `aud` claim names the client id, which identifies the application rather than the server: every deployment behind the same issuer and client id accepts every other one's tokens, and they share one credential-store bucket, so logging in to one evicts the other's token. Setting `resource` to this deployment's own address ends both. The server then requires an [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068) access token whose `aud` names that value, and the client asks the provider for one using [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707) resource indicators:

    ```toml
    [server.auth.oidc]
    issuer = "https://id.example.com"
    client_id = "lore"
    authorize_all_repositories = true
    resource = "https://lore-prod.example.com"
    ```

    Use it wherever your provider supports it, and treat it as required where a deployment shares an issuer with another Lore server. The value must be an absolute URI with no fragment — a bare hostname such as `lore-prod.example.com` is rejected at startup — and it's an identifier, so the server never dials it.

    > [!IMPORTANT]
    > Your provider must implement both RFCs, and one that doesn't won't tell you so — it accepts the request and mints an ordinary token whose `aud` names the client id. Lore checks the token it gets back and fails the login with a message naming what the provider didn't do. **PocketID 2.6.2 ignores the parameter** (verified 2026-08-13): leave `resource` unset there, and register a distinct client id per deployment instead to restore the audience distinction. Keycloak, Entra ID, and Auth0 support resource indicators or an equivalent audience parameter; test a login outside production first.

    The server advertises `resource` to clients on its own. If you write `environment.endpoint.auth_url` by hand, carry the parameter yourself, or clients won't ask for a resource-bound token and every request is refused. See the [server config reference](../reference/lore-server-config.md#authentication) for the encoded form.

4. **Restart the server and confirm it now requires a token.**

    ```bash
    ~/.local/bin/loreserver --config /opt/loreserver/config
    ```

    From another terminal, any operation against the server should now fail with an authentication error:

    ```bash
    lore repository list lore://your-server.example.com:41337
    ```

    If it succeeds instead, the server isn't picking up the config change — check the config path and restart again.

5. **Log in.**

    On a machine with a browser, `lore login` opens your provider's login page:

    ```bash
    lore login lore://your-server.example.com:41337/
    ```

    On a headless host, print a code to approve from any other device instead:

    ```bash
    lore login lore://your-server.example.com:41337/ --no-browser
    ```

    > [!WARNING]
    > The device flow's weak point is the human, not the protocol: approving on one device something started on another is also what a phishing message needs. Only approve a code you retrieved yourself from a `lore login --no-browser` you ran yourself, and check that it matches the code on your provider's approval page.

    Either way, Lore stores the token in the encrypted credential store and refreshes it as it expires, so day-to-day commands don't ask you to log in again until the provider revokes the session.

6. **Confirm who you're logged in as.**

    ```bash
    lore auth info
    ```

    This prints the identity your provider's token carries. `lore auth logout` and `lore auth clear` remove stored tokens the same way they do for any other authentication scheme.

## Result

Every repository operation on the server — gRPC, HTTP, and QUIC alike — now requires a valid, unexpired token from your configured issuer. The `/health_check` endpoint stays open, and a client that hasn't logged in gets a clean authentication failure.

> [!NOTE]
> Your provider owns identity resolution, and this integration reads no directory beyond what a token carries. You can only look up your own identity: passing a user id to `lore auth info` against an OIDC-secured server reports that the provider exposes no such lookup.

## See also

- [Lore Server config reference](../reference/lore-server-config.md#authentication) — every `[server.auth]` and `[server.auth.oidc]` field.
- [Lore CLI command reference](../reference/lore-cli-commands.md) — the full `lore auth` subcommand surface.
- [OIDC authentication proposal](../proposals/2026-08-13-oidc-authentication.md) — the design, its threat model, and what resource binding does and doesn't prevent.
- [Deploy a local Lore Server](deploy-local-lore-server.md) — get a server running before securing it.
