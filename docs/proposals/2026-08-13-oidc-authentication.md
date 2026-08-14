---
lep: 2026-08-13-oidc-authentication
title: Direct in-server OpenID Connect authentication
authors:
  - Alex Carberry
status: Draft
created: 2026-08-13
updated: 2026-08-14
discussion: <LEP PR — to be opened>
---

# Direct in-server OpenID Connect authentication

## Summary

A Lore server verifies tokens issued by a standard OpenID Connect provider itself, and the Lore CLI
obtains those tokens from that provider with standard OAuth 2.0 flows. An operator names an issuer
URL and a client id in the server configuration; the server reads the provider's discovery document
to find its key set, and from then on every repository operation over gRPC, HTTP, and QUIC requires
an unexpired token from that issuer. A verified token authorizes every repository on the server — the
provider decides who is let in, and this proposal deliberately stops there. On the client, one new
`Authentication` implementation joins `ucs-auth` in the existing scheme registry and runs three
standard flows: authorization code with PKCE over a loopback redirect, the device authorization grant
for hosts with no browser, and the refresh grant to keep a session alive. A deployment whose provider
supports resource indicators can additionally name itself and accept only tokens bound to it. Nothing
new is deployed: no broker, no sidecar, no second token format, no Lore-minted tokens. An
unconfigured server behaves exactly as it does today.

## Motivation

**An operator who self-hosts Lore wants it behind the identity provider they already run.** PocketID,
Keycloak, Entra ID, Authentik — whichever one already holds their team's accounts, their offboarding
procedure, and their second factor. They want Lore to be one more client registered there, not a
system with its own idea of who exists. Their users want `lore login` to behave the way
[`gh auth login`](https://cli.github.com/manual/gh_auth_login) and
[kubectl's OpenID Connect support](https://kubernetes.io/docs/reference/access-authn-authz/authentication/)
behave: approve in a browser, and the CLI works until the token expires.

**No Lore deployment outside Epic can authenticate at all today.** The single client-side
authentication scheme in the tree, `ucs-auth`, speaks to an Epic-internal service, and no shipped
server configuration turns authentication on. Every self-hosted deployment therefore runs open, which
is what the [quickstart](../tutorials/quickstart.md) tells operators to do and what the
[FAQ](../faq.md) acknowledges when it lists OAuth integration among planned additions rather than
present ones.

**Operators are asking for exactly this, unprompted.** In
[issue #60](https://github.com/EpicGames/lore/issues/60) an operator points Lore at a Microsoft Entra
tenant; in [issue #161](https://github.com/EpicGames/lore/issues/161) another points it at a
self-hosted provider and then tries to log in. Neither is a bug report about a feature Lore offers —
both are operators reaching for a deployment Lore does not support.
[Issue #59](https://github.com/EpicGames/lore/issues/59) asks for the headless half of the same
story, credentials on a machine with no browser.

**Why now.** GOVERNANCE.md requires an accepted LEP, after a two-week discussion period, before any
change to authentication flows — and [PR #22](https://github.com/EpicGames/lore/pull/22) already
proposes a different answer to the same demand, a standalone service minting Lore's own tokens. The
design space is being settled now, and this proposal argues the self-hosted case wants the smaller
answer.

## Goals / Non-Goals

### Goals

1. **An operator secures a Lore server with any conformant provider by naming an issuer and a client
   id** — no other configuration, and nothing new to deploy or operate.
2. **The server carries no provider-specific code.** Every endpoint and every key comes from the
   provider's own discovery document, so supporting a new provider is a configuration change.
3. **A verified token from the trusted issuer authorizes every repository on the server**, and the
   configuration states the grant in terms of what it grants.
4. **All three public protocols enforce it identically.** gRPC, HTTP, and QUIC reach the same
   verifier and the same authorization decision.
5. **A user logs in from the CLI with standard flows, and stays logged in** — authorization code with
   PKCE where there is a browser, the device grant where there is not, and the refresh grant so the
   session outlives the first token.
6. **Tokens keep living in the existing credential store, and the token-recipient guard keeps
   holding.** A token obtained for one remote is never sent to another.
7. **An unconfigured server behaves exactly as it does today.** Absent settings mean no
   authentication, on every path, with no new code between a request and its handler.

### Non-Goals

- **Per-repository authorization from provider claims or groups.** No standard claim carries it, and
  mapping one is a design of its own; a follow-up LEP owns it.
- **Replacing or removing `ucs-auth`.** The two schemes coexist in the registry, and Epic's
  deployment is unaffected.
- **Server-minted tokens or token exchange.** Lore issues nothing and signs nothing.
- **SAML, LDAP, Kerberos, or a web interface.** OpenID Connect only, driven from the CLI.
- **Several issuers on one server.** A deployment federating several identity sources does that in
  the provider, which is what providers are for.

## Proposed Design

### Server configuration (Goal 1)

`AuthSettings` gains one optional block:

```toml
[server.auth.oidc]
issuer = "https://id.example.com"
client_id = "lore"
authorize_all_repositories = true
```

`issuer` is the provider's issuer identifier, exactly as the provider publishes it — the same string
it puts in the `iss` claim — and `client_id` is the public client registered for Lore. Both are
required when the block is present.

`authorize_all_repositories` has **no default**: a block that omits it, or sets it `false`, fails
start-up validation with a message saying per-repository authorization is not implemented. This
proposal offers one authorization mode and it is a coarse one, so an operator has to write down that
they want it. Both defaults would be wrong — `true` grants every repository to every authenticated
identity on the strength of an omission, and `false` starts a server that verifies every token and
then refuses every request.

The block supplies what the existing settings otherwise ask for twice: `jwt_issuer` and
`jwt_audience` derive from `issuer` and `client_id`, and `[server.auth.jwk].endpoint` from discovery.
An explicitly set value still wins, which keeps the `file://` key-set endpoint
([issue #32](https://github.com/EpicGames/lore/issues/32),
[PR #44](https://github.com/EpicGames/lore/pull/44)) reachable as an offline escape hatch.

### Discovery (Goal 2)

At start-up the server fetches `{issuer}/.well-known/openid-configuration`
([OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html) §4) and
reads exactly two members: `issuer`, which must equal the configured issuer byte for byte (§4.3), and
`jwks_uri`, which becomes the endpoint the existing key-set service already fetches, caches,
throttles, and rotates keys under. Nothing else. The endpoints a login flow uses are the client's
business, and the client fetches the same document for itself, so the server never relays a
provider's endpoints and cannot serve them stale. The issuer equality check is what makes fetching a
discovery URL safe: without it, a redirect or a compromised well-known path could point the server at
somebody else's key set, and the server would verify forged tokens against it.

This is the whole answer to PR #22's coupling objection. The server holds one provider-specific
string and it is configuration — no per-provider code path, no per-provider claim policy, no release
coupled to a provider's behavior. The two provider quirks the tree has already met, Entra omitting
the OPTIONAL `alg` member (issue #60, [PR #65](https://github.com/EpicGames/lore/pull/65)) and key
rotation under an unchanged key id ([issue #78](https://github.com/EpicGames/lore/issues/78),
[PR #99](https://github.com/EpicGames/lore/pull/99)), were both fixed as conformance to
[RFC 7517](https://www.rfc-editor.org/rfc/rfc7517) rather than as provider special cases.

### The token the server verifies

The client presents the **ID token**
([OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html) §2), because it is
the only token OpenID Connect guarantees: guaranteed to exist, to be a signed JWT, and to carry the
client id in `aud`, which is the value the server pins. Access tokens may be opaque
([RFC 6749](https://www.rfc-editor.org/rfc/rfc6749) §1.4), so requiring a verifiable access token
would reintroduce exactly the provider coupling this proposal exists to avoid. **Drawbacks** records
the cost; **Binding tokens to one deployment** is the standards-track route out of it.

Verification therefore needs a claim shape a conformant ID token satisfies. The verifier today tries
two claim structs, both demanding the Lore-specific `env`, `name`, and `preferred_username`, so a
correctly signed token naming the right audience is refused at deserialization before authorization
is reached. A third and final decode reads only what
[RFC 7519](https://www.rfc-editor.org/rfc/rfc7519) and Core guarantee — `iss`, `sub`, `aud`, `exp`,
`iat` — treats `name`, `preferred_username`, and `email` as optional, and falls back to `sub` for
display. It tests `aud` for membership rather than equality, because Core §2 defines it as an array
and providers differ over collapsing a single-element one to a bare string. This is additive rather
than a widening for two reasons: the new decode runs only once both existing decodes have failed,
which today is an outright rejection, and it is gated on the OIDC block, so a `ucs-auth` deployment
accepts exactly what it accepts today.

The algorithm allowlist tightens in the same mode. The key-set loader already refuses to *infer* a
symmetric algorithm and already refuses a key whose declared algorithm belongs to another key type —
the algorithm-confusion forgery. What it still honors is a provider *declaring* `HS256` on an `oct`
key in its published key set, which is a signing key for anyone who can read it. OIDC mode refuses
symmetric algorithms outright, leaving `RS*`, `PS*`, `ES*`, and `EdDSA`. `alg: none` needs no
separate narrowing: the decoder has no such variant in any mode.

### One authorization mode, named for what it grants (Goal 3)

When `authorize_all_repositories` is on and a token verifies against the pinned issuer, the verifier
populates the resulting in-process `AuthorizationToken` with the wildcard resource the authorization
model already carries, `urc-*`. `ResourcePermission` already treats that value as matching every
repository, and `verify_authorization` already returns `Ok(())` for it under an existing test, so
`verify_authorization` needs no new argument and no change.

**Why the grant belongs on the token.** `verify_authorization` has seven callers, and only four are
places the verifier or the server settings can reach: the gRPC interceptors, the HTTP middleware, and
the two QUIC entry points. The other three hold only an `AuthorizationToken` recovered from request
extensions or a connection's attribute map — both `copy` handlers, which authorize a *source*
repository other than the connected one, and the link-read authorizer, which decides which linked
repositories a read may traverse. A mode threaded as a per-call argument would have to reach those
three through layers that have no business knowing about authentication settings, and a missed site
would fail closed for `copy` and silently narrow link traversal. On the token, every consumer,
present and future, is correct by construction.

The wildcard exists only in the in-process token, for the duration of the request: nothing
re-serializes it, nothing signs it, nothing returns it to a client, and no Lore signing key exists
anywhere in this design. This is a degenerate case of the third option
[ADR-00003](../developing/decisions/00003-auth-tokens-for-sub-repos.md) considered and rejected — one
token that only identifies the user, with the server resolving authorization — which ADR-00003
rejected because the server would perform authorization work per connection, possibly involving
external I/O. That objection does not reach a constant read from configuration, but it does reach the
per-repository follow-up, which is why that is a separate LEP replacing one function rather than
revisiting seven call sites.

**Repository delete is the one operation this mode does not reach.** It is the only repository
operation whose authorization does not run through `verify_authorization`: it asks the
relationship-based authorization service when `auth_url` names one, and otherwise checks that the
caller is the repository's recorded creator. Under OIDC it takes that second path, so delete runs
*narrower* than the grant — the safer of two answers rather than a designed one, since dialing the
identity provider as though it were the authorization service is not an option, and letting any
identity delete any repository as a side effect of a scheme check is wider than this proposal argues
for anywhere else. **Unresolved Questions** asks which it should settle into.

### The enforcement points (Goal 4)

Every plug point that admits a request already holds a verifier, and this proposal adds and moves
none. Three protocols, four entry points, because the QUIC storage protocol has two versions in
service: the gRPC tonic interceptors, installed only when a verifier exists; the HTTP middleware; and
QUIC's `Connect::handle_auth` and v4 `AuthorizeStart`, each verifying once per connection or session,
following ADR-00003's one-token-per-connection shape. Because the grant travels on the token, all
four admit a request identically and every downstream check reaches the same verdict from the same
value. The same mechanism completes the `JWTAuthnInterceptor` placeholder, so the repository service
stops being a hole in the model.

The environment service stays unauthenticated, as its own documentation states: a client has to be
able to ask how to authenticate before it can authenticate. The health check stays open.

### Advertising the provider (Goal 2, and the shape of issue #161)

The server advertises the provider through the existing `EnvironmentGet` `auth_url` string:

```text
oidc+https://id.example.com?client_id=lore
oidc+https://id.example.com/realms/studio?client_id=lore&resource=https://lore.example.com
```

When the OIDC block is configured and `environment.endpoint.auth_url` is empty, the server derives
this string rather than making the operator write the issuer down twice; an explicitly configured
`auth_url` still wins. Verification and advertisement stop being two independent settings that can
disagree, which is the trap issue #161 fell into: a server can verify tokens perfectly while telling
every client it has no authentication.

The scheme is the dispatch key. `authentication::find` splits on the first `://` and looks the prefix
up in the registry, so `oidc+https` registers as one entry and `oidc+http` as another the
implementation accepts only for a loopback issuer. The `+` composition follows Git's convention for
transport-qualified remotes (`git+https`, `svn+ssh`), and stripping the prefix yields the issuer
unchanged, which matters because issuer validation is a byte comparison. Query parameters are safe to
append, an issuer identifier being forbidden a query or fragment component (Discovery §2):
`client_id` is not a secret, this being a public client using PKCE, and `resource` appears exactly
when configured, doing two jobs — advertisement is the only channel by which a client learns to ask
for a resource-bound token, and distinct resources give two deployments sharing an issuer distinct
auth URLs, which the credential store keys on.

**The server reads this field too, in six places**, and every one of them wants a dial target for
Epic's relationship-based authorization service, so advertising an `oidc+https://…` URL unguarded
would point all six at the identity provider and fail repository create, delete, query, list, and
metadata alike. Two mechanisms keep advertisement and dialing apart, and the design needs both. The
derived URL never reaches an internal consumer, because the server derives the advertisement into a
clone: the configured environment stays what internal consumers read, leaving their dial target
`None` for a deployment configuring OIDC and nothing else. And each consumer gates on the scheme as
well, because an operator may still set `auth_url` by hand. `is_auth_client_scheme` is that single
predicate, written as an exclusion rather than an allowlist: an `oidc+` scheme gives up the
authorization check and **every other scheme keeps it**. An allowlist would silently drop the check
for any deployment spelling its auth URL differently — plain `http` to a service behind a mesh being
the obvious one — and a dropped authorization check is the failure nobody notices from outside,
because every operation still succeeds. That the prefix makes these two cases distinguishable at all
is the strongest argument against putting a bare issuer URL in the field.

### The client implementation (Goal 5)

One `Authentication` implementation registers for `oidc+https` and `oidc+http` beside `ucs-auth`. It
parses the issuer and parameters out of the auth URL, fetches the same discovery document the server
did — it needs `authorization_endpoint`, `token_endpoint`, and `device_authorization_endpoint`, none
of which the server has reason to relay — and fits three standard flows onto the trait's existing
start-and-poll shape, on the net runtime the
[runtime-split LEP](2026-07-24-tokio-runtime-split-and-async-io.md) established. Those endpoints are
remote input, held to the rule the auth URL is held to: https, or http only to a loopback host. The
authorization endpoint in particular becomes the URL handed to `open::that`, which asks the desktop
to launch whatever URI it names, so a `javascript:` or `file:` endpoint in a compromised provider's
document would be a local-execution primitive rather than a failed login.

**Browser login** is the authorization code flow with PKCE
([RFC 7636](https://www.rfc-editor.org/rfc/rfc7636)) over a loopback redirect. `start_auth_session`
binds a listener on `127.0.0.1:0`, generates the verifier, `state`, and `nonce`, and returns the
provider's authorization URL; `poll_auth_session` waits for the redirect, checks `state`, exchanges
the code, and validates the `nonce`. Redirecting to a kernel-assigned loopback port is the mechanism
[RFC 8252](https://www.rfc-editor.org/rfc/rfc8252) §7.3 specifies for native applications, and the
reason a native client needs no client secret and no registered public callback host.

**Headless login** is the device authorization grant
([RFC 8628](https://www.rfc-editor.org/rfc/rfc8628)), which `lore login --no-browser` is already
shaped for: it emits the login URL as an event instead of opening a browser. PocketID 2.6.2, the
provider this work validates against, completes the grant, so the headless path is proven rather than
deferred; a provider advertising no device endpoint gets a typed `NotSupported` naming the missing
capability, because the alternative — printing the authorization URL to open elsewhere — cannot
complete when that flow's redirect goes to a loopback listener on *this* host. Selecting between the
two ceremonies is the one trait change: `start_auth_session` gains a `LoginFlow` argument, whose
value comes from the existing `--no-browser` flag, and `ucs-auth` ignores it.

**Staying logged in** is the refresh grant, requested with the `offline_access` scope.
`AuthenticationToken.refresh_token` and the credential store's refresh-token slot already exist and
already treat refresh tokens as separately stored and rotated, so this fills in an implementation
rather than extending a mechanism. A refreshed response need not carry an ID token (Core §12.2), so
the client treats it as optional there and refuses with a message naming what the provider omitted;
at login it is never optional, because it is what the `nonce` travels on. The grant is consumed where
an expired stored token would otherwise dead-end, in the authorization exchange, and it is
best-effort in the strict sense: a revoked token, a provider that is down, and `ucs-auth`'s
`NotSupported` all leave the caller holding exactly the expired token, so refreshing can spare a user
a re-login but can never fail an operation that would otherwise have succeeded. One attempt per
operation, single-flighted across concurrent callers, because the grant spends a single-use token.

**What the implementation declines.** `exchange_for_repository` and `exchange_for_custom_resource`
return the authentication token unchanged, because there is nothing to exchange it with and nothing
to mint; ADR-00003's call shape survives, and this is the seam the per-repository follow-up works at.
`exchange_external_token`, `get_user_info`, and `get_user_id` return `NotSupported`, because the
provider owns identity resolution and this proposal reads no directory. One claim relaxes on the
client to match the server's: `JWTUserInfo.name` becomes `Option<String>` falling back to `sub`,
because `name` is an optional claim delivered with the `profile` scope, and requiring it makes a
login fail after having succeeded, while rendering who logged in.

The flows are implemented on `reqwest`, `jsonwebtoken`, `ring`, and `url`, all already workspace
dependencies; **Alternatives Considered** states the trade-off against the `openidconnect` crate
rather than dismissing it.

### Keeping the token-recipient guard (Goal 6)

The threat the guard exists for is written down in `lore-revision/src/auth.rs`: an attacker stands up
a server whose environment names a trusted auth service, a user clones from it, and the CLI dutifully
sends that service's token to the attacker. The defense is an acceptable-root-domain set stored
beside each token and filtered on load.

The orchestration layer derives that set today by decoding the token and concatenating `iss` and
`aud`, which works for `ucs-auth`, where the auth service issues `aud` as a list of root domains. It
cannot work for OpenID Connect, where `aud` carries a client id and `iss` is a URL rather than a bare
host: both fail the domain comparison against any remote, so every OIDC login would refuse its own
token. `AuthenticationToken` already carries an `acceptable_root_domains` field that `ucs_auth.rs`
leaves empty, with a comment saying the orchestration layer fills it in from the JWT. This proposal
makes that field authoritative when non-empty: the implementation knows its own tokens' audience
semantics, and the orchestration layer stops guessing. `ucs-auth` returns an empty vector and keeps
today's behavior exactly; the OIDC implementation returns the issuer's **host**, because a token can
always go back to the party that issued it, and the orchestration layer adds the host of the remote
the login was performed against, the only layer that knows it. An OIDC token is therefore usable at
the remote you logged in to and at its issuer, nowhere else, without asking the operator to configure
their own public hostname, and refreshing keeps the set recorded at login rather than the refreshed
token's own.

**Recording the set is half the guard.** The other half is refusing to load a token for a recipient
the set does not name, and the authorization exchange has to do that itself: identity-resolving
callers already load under a recipient filter, but `exchange` is also called directly, with an
explicit identity, from the connection path. So `exchange` loads the authentication token only if it
is acceptable both for the auth service it is about to be presented to and for the remote the
resulting authorization token is destined for. Where the authorization token *is* the authentication
token — exactly the OIDC passthrough — that check is the whole distance between a stored credential
and any remote advertising the issuer it came from. Recording the recipient on the way out, rather
than checking it on the way in, would record it just as obligingly for an attacker's remote. One
consequence is visible to users: the store keys tokens by `(auth_url, identity)` and holds one per
pair, so two deployments sharing an issuer and a client id share a bucket, and logging in to one
evicts the other's token.

### Binding tokens to one deployment, where the provider allows it

`aud` names the client, so it cannot tell two Lore deployments apart: every deployment registered
behind the same issuer and client id — staging beside production, the ordinary case — accepts every
other one's tokens. **Security Considerations** states what follows.

The standards-track answer is a pair: [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707) resource
indicators, which let a client ask for a token bound to a named resource server, and
[RFC 9068](https://www.rfc-editor.org/rfc/rfc9068) JWT access tokens, which are what such a token is.
This proposal ships both as an opt-in that is strict when enabled, because mandatory would be
unshippable: a provider is obliged to implement neither, and PocketID 2.6.2 implements neither.

```toml
resource = "https://lore-prod.example.com"
```

Its value is an RFC 8707 resource indicator — an absolute URI with no fragment (§2), enforced at
start-up, because the alternative failure is the worst kind: a server pinning an audience no provider
will mint, so every login succeeds and every request is refused. It is an identifier, not an
endpoint; nothing dials it.

**What the server then requires.** `aud` pins to the resource rather than the client id, and the
accepted credential becomes an RFC 9068 JWT access token, validated by §4's list plus `sub` and `iat`
because the server reads them. It accepts a token omitting `client_id` or `jti`, following the
specification's own division of labor: §2.2 binds the authorization server issuing a token, while §4
— the resource server's list — names neither, and Lore consumes neither. ID-token acceptance is
**off** in this mode, and §4's `typ` check is what turns it off, since every ID token and every
`ucs-auth` token carries `typ: "JWT"`; leaving the weaker credential reachable would leave a way
around the stronger one, which is the reason an operator turned this on.

**What the client does.** RFC 8707 §2 puts the `resource` parameter on the authorization request and
on the token request of every grant type, so the client sends it on all five legs — authorization,
code exchange, device authorization, device poll, and refresh — and then presents the **access
token**, the ID token staying the identity assertion that carries `nonce` and the display claims. It
also checks what it got back, because a provider that does not implement RFC 8707 is under no
obligation to say so: PocketID 2.6.2 answers `200` on every leg, ignores the parameter, and mints an
ordinary client-audienced token, which unchecked would store a credential and then have every
repository operation refused with the cause two layers away. So the client verifies that the access
token is a JWT of the right media type whose `aud` names the resource, and fails the login naming
what the provider did not do — a diagnostic, not a security control, since the server verifies the
token itself and its verdict is the only one that decides anything.

Absent `resource`, no parameter is sent and the ID token is the credential, which is what makes this
an opt-in rather than a migration.

### Goal tracing

Goal 1 → **Server configuration**. Goal 2 → **Discovery** and **Advertising the provider**. Goal 3 →
**One authorization mode**. Goal 4 → **The enforcement points**. Goal 5 → **The client
implementation**. Goal 6 → **Keeping the token-recipient guard** and **Binding tokens to one
deployment**. Goal 7 → **Compatibility**, below.

## Compatibility

- **Wire format** — N/A. No message, framing, serialization, or byte layout changes. The QUIC
  `Connect` message already carries an optional token as its payload and carries the same one.

- **Client/server protocols** — No new or changed RPC, and `lore-proto` has no diff: the provider
  travels in the existing `EnvironmentEndpoint.auth_url` string. *An unconfigured server* behaves
  exactly as today on every path — no verifier exists, so the HTTP middleware inserts no identity,
  QUIC skips verification, the gRPC interceptors are never installed, the authorization mode never
  comes into existence, and the third claim decode is gated off. *An old client against a new secured
  server* reads `oidc+https://…`, finds no registered implementation, and fails immediately with an
  error naming the scheme and listing the ones it has; a repository operation returns
  `NotAuthenticated`. No path lets it reach a repository unauthenticated, because the server's
  refusal does not depend on the client understanding the scheme. *A new client against an old or
  unconfigured server* is unchanged: the advertised `auth_url` is empty or `ucs-auth://`, and the new
  registry entry is inert.

- **On-disk format** — N/A for repositories: no fragment flag, index, or schema change, and an
  upgraded and a downgraded Lore read the same repositories. The credential store gains no field —
  `acceptable_root_domains` and `refresh_token` both already exist, both `#[serde(default)]`.

- **CLI and public API** — Additive. `lore login`, `lore auth login --no-browser`, `lore auth info`,
  `list`, `logout`, and `clear` keep their syntax, exit codes, and output; against a secured server
  they now succeed instead of failing. `lore auth info <user-id>` against a secured server reports
  that the provider exposes no directory lookup, a new message on a path that does not work there
  today. No `lore-capi` or JS binding surface changes, and no existing script breaks.

- **Rust crate surfaces** — Four changes, none altering an existing behavior and none crossing the C
  or JavaScript boundary. `JWTUserInfo.name` becomes `Option<String>`, strictly widening what
  deserializes. `Authentication::start_auth_session` gains a `LoginFlow` argument whose value comes
  from the existing `--no-browser` flag. The gRPC server builder takes the advertised environment as
  a second argument, and passing the same value twice is today's behavior. `repository_authorizer`
  keeps its signature and changes its selection rule to "a scheme this server implements an
  authorization client for", identical for every deployment today.

- **Configuration** — Additive and backward-compatible. `[server.auth.oidc]` is a new optional block,
  and the three existing `AuthSettings` fields keep their meanings when set explicitly. Two new
  start-up failures, both by design: a block without `authorize_all_repositories = true` refuses to
  start, and a `resource` that is not an absolute URI without a fragment refuses to start.

## Non-Functional Considerations

- **Concurrency** — No new shared mutable state on the server. Discovery runs once at start-up, and
  key fetches go through the existing key-set service, whose refresh mutex already collapses
  concurrent misses into one outbound request and whose minimum refresh interval already bounds
  fetches however many unknown key ids arrive — both tested, and both load-bearing here, because an
  unauthenticated caller can present arbitrary key ids. Verification is a pure function of the token
  and a cached key. On the client, a pending login is one task owning one listener.

- **Memory** — Bounded and small, with nothing proportional to repository or file size. The key-set
  and discovery documents are read under the existing 1 MiB cap, by an accumulating read that does
  not trust `Content-Length`, and tokens are kilobytes. This proposal never touches a payload.

- **Statelessness** — The server gains none. It holds the key cache it already holds, and every
  authorization decision is a function of one token: no session, no nonce store, no replay cache, no
  revocation list. That is what keeps a secured server as horizontally scalable as an unsecured one —
  the property PR #22's design lists as an unresolved question for itself. On the client, pending
  login state dies with the command; only tokens outlive it, in the store that already holds them.

- **Determinism** — Unaffected, because nothing here enters repository content, addressing, or
  history: two runs of the same operation against the same revision produce the same result whether
  or not authentication is on. Token verification is not deterministic in the same sense and cannot
  be, reading the clock for `exp` and the provider's current key set for the signature.

- **Runtime placement and latency** — Discovery and key-set fetches are network I/O on the net
  runtime the [runtime-split LEP](2026-07-24-tokio-runtime-split-and-async-io.md) established. This
  proposal adds no blocking call and does not worsen the known `block_in_place` in the gRPC
  interceptor, because the all-repositories path takes the identical cached-then-fallback route the
  resource-claim path takes. The cost is one extra round trip at start-up, before the listeners open;
  steady-state latency is unchanged, verification on a warm cache being a signature check and claim
  comparisons with no I/O.

## Migration Plan

`N/A — no breaking changes, no migration required.`

Turning it on is a configuration change and a restart; turning it off is the same in reverse — remove
the block, restart, and the server is unsecured again with no state to clean up, because the design
stores none. Tokens issued in the meantime expire on their own, and a client whose token is refused
falls back to the same `NotAuthenticated` path it uses today.

## Security Considerations

**The trust model changes in one specific way: the operator's provider becomes a trust boundary.** An
identity the provider admits is an identity Lore admits. That is the point of the feature, and a
smaller change than it sounds — the server trusts the provider to *authenticate* and nothing more,
reading no groups and no roles, and it cannot be steered by any claim the provider chooses to add.

**Pinning is what keeps trusting one provider from meaning trusting any provider.** Four pins, each
on a value the operator configured or the provider published: the discovery document's `issuer` must
equal the configured issuer (Discovery §4.3), the token's `iss` must equal it too, the token's `aud`
must contain the configured client id, and `exp` must not have passed. Discovery and key-set fetches
go over TLS through the shared rustls-backed HTTP client. The verification algorithm comes from the
key, never from the token header — the existing pin, tested against a forgery that signs with the
public modulus as an HMAC secret — and OIDC mode refuses symmetric algorithms outright, closing the
case of a provider publishing a symmetric secret in its own key set.

**The all-repositories grant is the sharpest edge here, and it is stated plainly.** Every identity
the provider admits can read and write every repository on the server: no per-repository distinction,
no read-only identity, no administrative separation. Because the wildcard reaches every consumer, a
`copy` may name any repository as its source, a link traversal may read any linked repository, and
the repository service's check resolves to allow-all — each a restatement of the first sentence
rather than an inconsistency for an operator to discover, and repository delete the one exception,
running narrower. An operator whose repositories have different audiences needs the per-repository
follow-up LEP or one server per trust boundary, and `authorize_all_repositories` has no default
precisely so that nobody arrives here by omission. The grant introduces no new authorization
primitive: `urc-*` is a value the permission type already implements, and PR #22's own reference
implementation ships it as its default resource policy.

**The login flows carry the risk the standards designed them around.** For the browser flow, the
redirect goes to `127.0.0.1` on a port the kernel assigned to a listener this process holds, so the
loopback interface binds the response to the process that started the flow (RFC 8252 §7.3); PKCE S256
makes an intercepted code useless without the verifier, which never leaves the process; and `state`
is checked before the code is used and `nonce` after, so neither a cross-session response nor a
replayed token is accepted. The [OAuth 2.0 Security BCP](https://www.rfc-editor.org/rfc/rfc9700) is
the shape of all of this. The device flow's surface is the user rather than the protocol — its
premise, approving on one device something initiated on another, is the premise a phishing message
needs too — and RFC 8628 §5.1 and §5.2's mitigations are limited to printing the user code for
comparison and honoring `interval` and `slow_down`. It stays opt-in behind `--no-browser`.

**Refresh tokens are the longest-lived secret this design stores**, and they go where Lore's tokens
already go: the existing credential store, encrypted, with the OS keyring holding the key, and
rotated on use. Failures stay non-oracular: the gRPC interceptor collapses every verification failure
into a uniform `permission_denied`, and the OIDC path adds failure modes and no responses.

**Two residual risks, named rather than buried.** *Token confusion between deployments* is narrowed
by `resource`, not removed. In the default mode any deployment behind the same issuer and client id
accepts any other's tokens, a harvested token opens all of them, and a malicious server advertising a
real deployment's issuer and client id collects, from a user who points `lore login` at it, a token
the real server would also accept. The recipient guard neither prevents this nor is meant to; it
prevents the *stored* token from a different remote leaking, which it still does. Configuring
`resource` ends cross-deployment interchange and untargeted replay, but not the targeted variant: an
attacker who advertises *your* resource identifier and persuades a user to log in still receives a
token your server accepts, because the user asked their provider for a token for that resource and
got one. No audience restriction can distinguish that from a legitimate login — it is the phishing
premise, not a gap in RFC 8707 — and what bounds it is that the user chose the remote. Where the mode
is unavailable, the baseline mitigation is a distinct `client_id` per deployment. *Presenting an ID
token as a bearer credential to a resource server*, second, is a compromise the standards discourage,
recorded in **Drawbacks** rather than argued away, and configuring `resource` retires it.

## Privacy Considerations

**The server sees an identity where it previously saw none.** For a token carrying only the required
claims that is the provider's subject identifier, its issuer, and the client id — no email, no name,
no group membership, because the server reads none of those and the provider need not send them.
Where the provider does include `name`, `preferred_username`, or `email`, they are in the token the
server verifies and so are visible to the operator. That is the same category of data a Lore token
already carries, and it reaches Lore only because the operator's own provider put it there.

**What reaches logs needs care, and one existing line is the reason.** The verifier logs the whole
decoded claim set at `debug` — Lore's own claims under `ucs-auth`, but potentially an email address
or anything else a provider chose to add under an ID token — so the implementation narrows that line
to the fields Lore uses. Beyond it, `sub` is recorded as the user-id span field, which is what it is
for. Tokens, authorization codes, code verifiers, device codes, and refresh tokens are never logged.

**Deletion and expiry are unaffected, and slightly better.** The server persists no identity: no
session table, no user store, nothing to delete when a user leaves. Revoking access is revoking it at
the provider, and the next token fails to verify. On the client, `lore auth logout` and `lore auth
clear` already remove stored tokens, and refresh tokens go with them.

## Risks and Assumptions

**Assumptions**

- **Assumption:** the target provider serves a discovery document at
  `{issuer}/.well-known/openid-configuration` whose `issuer` matches, and publishes asymmetric keys —
  *invalidated if:* a deployment must use a provider with no discovery endpoint, which the explicit
  `[server.auth.jwk].endpoint` covers, or one publishing only symmetric keys, which nothing covers.
- **Assumption:** the ID token is a signed JWT whose `aud` contains the client id, per Core §2, and
  is therefore verifiable by the existing verifier — *invalidated if:* a provider encrypts ID tokens
  by default, or issues them with an `aud` the server cannot pin.
- **Assumption:** providers grant `offline_access`, or issue refresh tokens by default, to a public
  native client — *invalidated if:* a deployment's provider refuses, leaving a session that lasts one
  ID-token lifetime and a user who re-runs `lore login`, which the CLI has to say clearly rather than
  failing opaquely.
- **Assumption:** an all-repositories grant is useful to real self-hosted operators, most of whom run
  one team's repositories on one server — *invalidated if:* early feedback says the coarse grant is
  unusable, which makes the per-repository follow-up a prerequisite rather than a successor.
- **Assumption:** the larger auth overhaul the maintainers mentioned on PR #22 in June 2026, whose
  details are undisclosed, does not preclude direct in-server verification — *invalidated if:*
  maintainer feedback on this LEP reveals conflicting plans. Opening this proposal early is the
  mitigation; implementation effort ahead of that signal is at risk.

**Risks**

- **Risk:** a server restarts while the provider is unreachable and comes up with no keys, refusing
  every request — *mitigation:* the explicit `[server.auth.jwk].endpoint` accepts a `file://` key set
  (issue #32, PR #44), and within a running process the existing cache means a provider outage does
  not immediately break verification.
- **Risk:** a consumer of `auth_url` other than the client registry is missed, and an `oidc+https`
  URL reaches code expecting an authorization service, failing repository operations against a live
  provider — *materialized during implementation:* the design assumed one such consumer and there are
  six, because repository create and delete each have two independent implementations that dial the
  service themselves, and repository list dials it to enumerate what a user may see. *Mitigation, as
  shipped:* the two mechanisms in **Advertising the provider**, plus integration and end-to-end
  coverage against a live provider, which is what turned a design assumption into a caught bug.
- **Risk:** two deployments sharing an issuer and client id share one credential-store bucket, so
  logging in to one evicts the other's token — *mitigation:* distinct `resource` values give distinct
  auth URLs and distinct buckets; documented in the operator guide.
- **Risk:** an unauthenticated caller drives outbound key-set fetches by cycling unknown key ids —
  *mitigation:* already bounded and tested — the minimum refresh interval throttles fetches once any
  key is cached, the refresh mutex collapses concurrent misses, and a failure no key could rescue
  never asks for a refresh at all.
- **Risk:** hand-rolled flow code gets a security detail wrong that a maintained crate would have got
  right — *mitigation:* each mechanism is small, specified, and testable in isolation (PKCE challenge
  derivation, `state` and `nonce` comparison, discovery parsing, the polling state machine), and the
  device grant is scriptable end to end against PocketID 2.6.2, so CI covers the rejection matrix
  without a browser and only the passkey ceremony stays verified by hand.

## Drawbacks

- The server depends on an external HTTP service being reachable at start-up to obtain the keys it
  verifies with.
- Lore owns the correctness of PKCE, the device flow, discovery parsing, and refresh handling instead
  of a library maintainer.
- The all-repositories grant is too coarse for any operator needing different access to different
  repositories, and they must wait for the follow-up LEP.
- Presenting an ID token as a bearer credential to a resource server is a compromise the standards
  discourage, taken because it is the only token OpenID Connect guarantees is verifiable — and the
  deployments left on it are exactly those whose provider cannot offer the `resource` alternative.
- The resource-bound mode's requirements land entirely on the provider, and one that does not meet
  them says nothing, so the failure surfaces as a Lore-side diagnostic rather than a protocol error.
- A second authentication scheme means every `lore auth` subcommand has two implementations to behave
  consistently across, and one of them cannot answer `get_user_info`.

## Alternatives Considered

### A token-minting broker service

[PR #22](https://github.com/EpicGames/lore/pull/22) proposes `lore-auth-server`: a service that
authenticates a user against a provider and mints a Lore JWT the existing verifier accepts unchanged.
It is a good design for what it targets, a managed deployment, and one reviewer has approved it.

*Rejected because:* it is a third process to deploy, put behind a TLS-terminating proxy, rate-limit,
monitor, and upgrade, for an operator whose entire deployment today is one binary and a configuration
file. It introduces a second token format where the provider already issues a perfectly good token.
And it creates a second trust boundary the operator has to protect: the broker holds a signing key
minting tokens the server trusts without question, so key storage, rotation, and the blast radius of
a compromise all become the operator's problem — PR #22 itself lists a single key with no rotation
procedure, process-local session state preventing a second replica, and no rate limiting as known
gaps. In a managed deployment those are a team's operational backlog; in a self-hosted one they are a
burden placed on someone who wanted to put their server behind the provider they already run.

PR #22's stated objection to direct verification is that it "moves OIDC discovery, JWKS handling, and
claim policy into Lore Server and every client, and ties Lore Server's releases to provider
specifics". Key-set handling is not moved — it is already in the tree and is the actively maintained
path there. Discovery is one document and two field reads, and it makes the coupling argument run the
other way, because the server holds an issuer URL from configuration and no provider-specific code.
Claim policy is not moved either, because this proposal has none. And the two designs compose rather
than compete: to a server doing direct verification a broker is just another issuer, so a managed
deployment that wants `lore-auth-server` points `issuer` at it and gets exactly the design PR #22
describes, while a self-hosted deployment points `issuer` at its own provider and deploys nothing.

### The `openidconnect` or `oauth2` crates

Adopt `openidconnect`, or `oauth2` plus manual ID-token validation, for the client flows instead of
building on `reqwest` and `jsonwebtoken`. The trade-off is genuine: the crates are well maintained,
rustls-compatible, and license-clean, and they supply discovery, PKCE, the device flow, and refresh
with their edge cases already handled.

*Rejected because:* what Lore needs is a strict subset — one grant-type family, one client type, no
dynamic registration, no ID-token encryption, no session management — while the crates bring their
own HTTP client abstraction and type-state builders that would have to be threaded onto the net
runtime and onto the `Authentication` trait's start-and-poll shape, and every added dependency and
its tree has to clear `deny.toml` and the `notices/` requirements. This is the weakest rejection in
this list, and the decision reverses in either direction, because the flows sit behind one trait
implementation.

### The status quo — pointing the key-set endpoint at the provider by hand

Configure `jwt_issuer` and `[server.auth.jwk].endpoint` against the provider's own endpoints, which
is what issues #60 and #161 show operators already doing.

*Rejected because:* it verifies signatures and nothing else works. A conformant ID token is refused
at deserialization for lacking `env`, `name`, and `preferred_username`; past that, the authorization
check refuses it for lacking a `resources` claim; and the client is never told there is a provider to
log in to. It is not a lighter version of this proposal — it is the part of it already in the tree,
which is why the two issues exist.

### Front Lore with a reverse proxy or `oauth2-proxy`

Terminate authentication in front of the server, as `oauth2-proxy` does for HTTP applications.

*Rejected because:* Lore's primary transport is QUIC, not HTTP, so a proxy cannot cover the protocol
most traffic uses — the gRPC and HTTP paths would be secured while the QUIC path stayed open, the
worst possible split. The server would still need the identity for its span fields and for lock
ownership, so it would have to trust a header the proxy injects, a weaker boundary than a signature
it verifies itself. And it does nothing for the client, which would still have no way to obtain a
credential.

### A new proto field for provider advertisement

Add a dedicated field or message to `EnvironmentGet` describing the provider, rather than encoding it
in `auth_url`.

*Rejected because:* the scheme registry exists to dispatch on exactly this string, and `auth_url` is
already documented as stored verbatim and interpreted by the client. A new field is also worse on
compatibility: proto3 makes an old client ignore an unknown field silently, so it would report "no
authentication configured" — issue #161's confusing failure all over again — where an unknown scheme
produces an error naming the scheme and listing the ones the client knows.

## Prior Art

- **kubectl and OpenID Connect.** Kubernetes verifies provider-issued ID tokens directly in the API
  server, configured with an issuer URL and a client id and nothing provider-specific
  ([authentication reference](https://kubernetes.io/docs/reference/access-authn-authz/authentication/)),
  and pushes the flows out to the client — the same split, at a much larger scale, and the strongest
  evidence that direct verification does not couple a server to providers. Worth avoiding: the group
  and username claim mapping bolted on top, and the configuration surface that grew around it.
- **`gh`, and the device grant as the headless default.** GitHub's CLI logs in with the device
  authorization grant, printing a code to enter on another device
  ([gh auth login](https://cli.github.com/manual/gh_auth_login)) — the closest analogue to
  `lore login --no-browser`, and the reason this proposal treats that grant as the headless path
  rather than as an exotic option.
- **Git credential helpers.** Git owns no authentication code and delegates to helpers
  ([gitcredentials](https://git-scm.com/docs/gitcredentials)). Lore's scheme registry arrives at the
  same place — a dispatch point rather than a policy — which is why adding a scheme is the whole of
  the client-side change here.
- **Dex and `oauth2-proxy`.** [Dex](https://dexidp.io/) brokers upstream identity into its own
  tokens; [oauth2-proxy](https://oauth2-proxy.github.io/oauth2-proxy/) terminates authentication in
  front of an HTTP application. Both are shapes this proposal declines and composes with: Dex in
  front of a Lore server is just the configured issuer.
- **PocketID as the first validated provider.** [PocketID](https://github.com/pocket-id/pocket-id) is
  a small self-hosted provider aimed at exactly this deployment, and a provider a self-hoster would
  actually run is a better conformance test than one from a large cloud provider.

## Unresolved Questions

- Should repository delete under `authorize_all_repositories` follow the grant — any authenticated
  identity may delete any repository, consistent with every other operation — or keep the
  creator-ownership check it currently falls back to? A mode that says "every repository, every
  authenticated identity" and then makes delete the one exception is an asymmetry an operator learns
  by hitting it; against that, delete is the one irreversible operation here. What is not defensible
  is the status quo's provenance: the current behavior is what a scheme check happened to produce.
- Is `authorize_all_repositories` the right name and shape, or should the mode be an enum from the
  start, so the per-repository follow-up extends a setting instead of replacing one?
- Should a single server be able to trust more than one issuer, and if so, does anything here need to
  change now to keep that from being a breaking addition later?
- Is `jsonwebtoken`'s 60-second default clock leeway the right tolerance for provider-issued tokens,
  or should the OIDC path set it explicitly?
- Should `login::with_token` accept a provider-issued token? Its recipient domains come from the
  token's own claims, which for an ID token are a client id and an issuer URL, so the recipient guard
  refuses it and an OIDC deployment has no non-interactive credential path — which is what issue #59
  asks for. The answer is either making the implementation-supplied domains authoritative on this
  path too, as they now are at login and at exchange, or the client credentials grant.
- What should a CLI login do when the credential store's keychain blocks on a user prompt? On macOS a
  rebuilt `lore` faces an authorization prompt on the next read and the store waits with no timeout.
  This is not new, but OIDC login is the first flow putting a store read in front of ordinary
  self-hosted users, where an indefinite wait is indistinguishable from a hung login.
