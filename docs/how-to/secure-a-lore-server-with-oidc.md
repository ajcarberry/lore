# Secure a Lore server with OpenID Connect

Reach for this guide once you have a Lore server running and want to stop it accepting
anonymous requests. It assumes a working [local deployment](deploy-local-lore-server.md)
and access to an OpenID Connect provider — any conformant one works; this guide uses
[PocketID](https://github.com/pocket-id/pocket-id) as the worked example because it's
self-hosted, PKCE-only, and quick to stand up alongside Lore.

## Prerequisites

- A running `loreserver` you can restart and reconfigure. See
  [Deploy a local Lore Server](deploy-local-lore-server.md).
- The `lore` CLI on your PATH. See [Install the Lore CLI](install-lore-cli.md).
- An OpenID Connect provider reachable from both the server and your workstation, with
  admin access to register a client.

## Steps

1. **Register a public client for Lore with your provider.**

   Lore is a native CLI, not a web app, so it registers as a public client using PKCE —
   no client secret to store or leak. In PocketID's admin UI, create an OIDC client with:

   - **Public client** enabled (no client secret).
   - **PKCE** enabled.
   - A callback address of `http://127.0.0.1:*/callback` (PocketID accepts a wildcard
     port; other providers may need you to register a fixed port or a range) — this is
     where the browser login flow's loopback listener receives the redirect.

   Note the client id and your provider's issuer address; you'll need both in the next
   step.

2. **Add the OIDC block to the server config.**

   Add a `[server.auth.oidc]` block to your server's `local.toml`:

   ```toml
   [server.auth.oidc]
   issuer = "https://id.example.com"
   client_id = "lore"
   authorize_all_repositories = true
   ```

   `issuer` must match the value your provider publishes in its own tokens' `iss` claim,
   byte for byte — the server checks this at startup against the provider's discovery
   document and refuses to start on a mismatch.

   > [!IMPORTANT]
   > `authorize_all_repositories = true` isn't a formality — it's the whole
   > authorization model this mode offers. Any identity your provider admits can read
   > and write **every** repository on this server: there is no per-repository
   > distinction, no read-only identity, and no administrative separation. If different
   > repositories need different audiences, run one server per trust boundary, or wait
   > for per-repository authorization from provider claims (a tracked follow-up, not yet
   > implemented). Because the consequence is this broad, the setting has no default —
   > omitting it, or setting it to `false`, fails startup validation rather than granting
   > or refusing everything without saying so.

   See the [server config reference](../reference/lore-server-config.md#authentication)
   for the full field list.

3. **Restart the server and confirm it now requires a token.**

   ```bash
   ~/.local/bin/loreserver --config /opt/loreserver/config
   ```

   From another terminal, any repository operation against the server now fails until
   you log in:

   ```bash
   lore --repository ./my-repo status --remote
   ```

   This should fail with an authentication error. If it succeeds, the server isn't
   picking up the config change — check the config path and restart again.

4. **Log in.**

   On a machine with a browser, `lore login` opens your provider's login page:

   ```bash
   lore login lore://your-server.example.com:41337/
   ```

   On a headless host, print a code to approve from any other device instead:

   ```bash
   lore login lore://your-server.example.com:41337/ --no-browser
   ```

   > [!WARNING]
   > The device flow's weak point is the human, not the protocol: its whole premise —
   > approve on one device something started on another — is also what a phishing
   > message needs. Only approve a code you retrieved yourself from a `lore login
   > --no-browser` you ran yourself, and check that the code Lore prints matches what
   > your provider's approval page shows before confirming.

   Either way, Lore stores the resulting token in the encrypted credential store and
   refreshes it as it expires without prompting — day-to-day commands don't ask you to
   log in again until the provider revokes the session.

5. **Confirm who you're logged in as.**

   ```bash
   lore auth info
   ```

   Prints the identity your provider's token carries. `logout` and `clear` remove
   stored tokens the same way they do for any other authentication scheme:

   ```bash
   lore auth logout
   ```

## Result

Every repository operation on the server — gRPC, HTTP, and QUIC alike — now requires a
valid, unexpired token from your configured issuer. The `/health_check` endpoint stays
open, and any client that hasn't logged in gets a clean authentication failure instead
of a response.

## Sharing one issuer across multiple Lore deployments

If several Lore servers register clients against the same issuer, add a `resource` query
parameter when you set `environment.endpoint.auth_url` explicitly, so a client's
credential store can tell the deployments apart even though they share an issuer and
client id:

```toml
[environment.endpoint]
auth_url = "oidc+https://id.example.com?client_id=lore&resource=lore-prod.example.com"
```

Without it, the server derives `auth_url` from the OIDC block automatically and you
don't need to set this — only add `resource` once one issuer serves more than one Lore
deployment.

## A known limitation: `lore user info`

An OIDC provider owns identity resolution, and this integration reads no directory
beyond what a token itself carries. Looking up another user's display name (`lore user
info`) against an OIDC-secured server reports that the provider exposes no such lookup,
rather than resolving one — this is expected, not a bug.

## See also

- [Lore Server config reference](../reference/lore-server-config.md#authentication) —
  every `[server.auth]` and `[server.auth.oidc]` field.
- [Lore CLI command reference](../reference/lore-cli-commands.md) — the full `lore auth`
  subcommand surface.
- [Deploy a local Lore Server](deploy-local-lore-server.md) — get a server running before
  securing it.
