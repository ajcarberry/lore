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

## Bind tokens to this deployment (recommended)

By default the server pins the token's `aud` claim to the **client id**. That identifies
the application, not the server — so every Lore deployment registered behind the same
issuer and client id accepts every other one's tokens. Two consequences follow: a token
harvested from users of one deployment opens the others, and a client's credential store
keys on `(auth_url, identity)`, so deployments sharing an issuer share a bucket and
logging in to one evicts the other's token.

Setting `resource` fixes both. The server then requires an
[RFC 9068](https://www.rfc-editor.org/rfc/rfc9068) JWT access token whose `aud` names
**this deployment**, and the client asks the provider for one using
[RFC 8707](https://www.rfc-editor.org/rfc/rfc8707) resource indicators:

```toml
[server.auth.oidc]
issuer = "https://id.example.com"
client_id = "lore"
authorize_all_repositories = true
resource = "https://lore-prod.example.com"
```

**Use it whenever your provider supports it**, and treat it as required for any
deployment that shares an issuer with another Lore server. The value must be an absolute
URI with no fragment (RFC 8707 §2) — a bare hostname such as `lore-prod.example.com` is
rejected at startup. Use the deployment's own address; it's an identifier, so the server
never dials it.

The server advertises the value automatically, so clients need no configuration. If you
set `environment.endpoint.auth_url` by hand, carry the parameter yourself, or clients
won't ask for a resource-bound token and every request will be refused:

```toml
[environment.endpoint]
auth_url = "oidc+https://id.example.com?client_id=lore&resource=https%3A%2F%2Flore-prod.example.com"
```

> [!IMPORTANT]
> **Your provider must implement RFC 8707 and RFC 9068**, and a provider that doesn't
> won't tell you so. RFC 8707 obliges nobody to announce that they ignore the parameter,
> so a non-supporting provider accepts the request, returns `200`, and mints an ordinary
> client-audienced token. Lore checks the token it gets back for exactly this reason and
> fails the login with a message naming what the provider didn't do — rather than letting
> you log in successfully and then have every operation refused.
>
> **PocketID 2.6.2 doesn't support RFC 8707** (verified 2026-08-13): it silently ignores
> the parameter. Leave `resource` unset there. Keycloak, Entra ID, and Auth0 support
> resource indicators or an equivalent audience parameter; check your provider's
> documentation before turning this on, and test a login in a non-production deployment
> first.

What this does and doesn't buy you: it ends cross-deployment token interchange and
untargeted replay, because a token minted for one deployment names it and no other
server accepts it. It does **not** stop a targeted attack — someone who stands up a
server advertising *your* resource identifier and persuades a user to log in to it still
receives a token your server would accept. What bounds that one is that the user chose
the remote.

## Keep token lifetimes short

Lore holds no revocation list and no session state: a verified token is accepted until
it expires. Revoking a user at the provider therefore takes effect when their current
token runs out, not immediately.

Configure short access-token lifetimes at your provider — minutes rather than hours —
and let the refresh grant keep sessions alive. Clients refresh silently, so a short
lifetime costs users nothing and bounds how long a revoked identity keeps working. This
matters most in resource mode, where the access token is the credential being presented.

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
