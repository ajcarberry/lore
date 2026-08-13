---
lep: 2026-08-13-oidc-authentication
title: Direct in-server OpenID Connect authentication
authors:
  - Alex Carberry
status: Draft
created: 2026-08-13
updated: 2026-08-13
discussion: <LEP PR — to be opened>
---

# Direct in-server OpenID Connect authentication

## Summary

A Lore server verifies tokens issued by a standard OpenID Connect provider itself, and the Lore CLI
obtains those tokens from that provider with standard OAuth 2.0 flows. An operator names an issuer
URL and a client id in the server configuration; the server reads the provider's discovery document
to find its key set, and from then on every repository operation over all three public protocols
requires an unexpired token from that issuer. A verified token authorizes every repository on the
server — the provider decides who is let in, and this proposal deliberately stops there. On the
client, a new `Authentication` implementation joins `ucs-auth` in the existing scheme registry and
runs the authorization code flow with PKCE over a loopback redirect, the device authorization grant
for hosts with no browser, and the refresh grant to keep a session alive. A deployment whose
provider supports resource indicators can additionally name itself, and then accepts only tokens
bound to it, so two Lore servers behind one provider stop accepting each other's. Nothing new is
deployed: no broker, no sidecar, no second token format, no Lore-minted tokens. An unconfigured
server behaves exactly as it does today.

## Motivation

A Lore deployment outside Epic cannot be authenticated at all, even though most of the machinery is
already in the tree, and the part of it that verifies tokens has been hardened four times since July
2026.

**The verifier exists and nothing fills it.** `lore-server/src/auth/jwk.rs` fetches a JSON Web Key
Set, caches it, throttles repeat fetches, picks up a key rotated under an unchanged key id, and refuses
the algorithm-confusion pairings. `lore-server/src/auth/jwt.rs` pins the verification algorithm to
the one the key declares rather than the one the token claims. On the client side, the
`Authentication` trait (`lore-transport/src/traits.rs`) is scheme-dispatched through a registry
(`lore-transport/src/auth/mod.rs`) built precisely so a second implementation can be added, and it
has exactly one entry: `ucs-auth`, a gRPC client for an Epic-internal service
(`lore-transport/src/auth/ucs_auth.rs`). No shipped server configuration turns authentication on,
and the end-to-end suite asserts that `lore auth login` against the test server fails with
`NotSupported` (`scripts/test/test_auth.py`).

**Self-hosters already point the verifier at real providers, and it does not work.** In
[issue #60](https://github.com/EpicGames/lore/issues/60) an operator aimed
`[server.auth.jwk].endpoint` at a Microsoft Entra tenant's key set and the server exited during
start-up with a bare `Internal Error`, because Entra omits the OPTIONAL `alg` member that the loader
treated as required. In [issue #161](https://github.com/EpicGames/lore/issues/161) an operator
configured `jwt_issuer` and `[server.auth.jwk].endpoint` against a self-hosted provider, confirmed
from the start-up log that both loaded, confirmed that unauthenticated requests were refused — and
then `lore auth login` failed immediately with `No authentication configured on server`. That
message comes from `lore-revision/src/auth/login.rs`, which reads `auth_url` out of the server's
environment response and refuses to proceed when it is empty. The advertised auth endpoint is a
separate configuration field (`environment.endpoint.auth_url`) with no relationship to
`[server.auth]`, so a server can verify tokens perfectly while telling every client that it has no
authentication. That report is still open and its author suspects the transport instead; whichever
diagnosis holds for it, the configuration split it ran into is real and is in the tree. Both reports
are operators reaching for direct verification unprompted, and finding a path that is most of the way
there.

**Three concrete gaps stand between a verified token and a working login.** They are worth naming
because they are the whole of the work, and because none of them is a provider-specific problem:

1. **The claim shape is not standard.** `verify_authorization` (`lore-server/src/auth/jwt.rs`)
   requires a Lore-specific `resources` claim naming permitted repositories, following
   [ADR-00003](../developing/decisions/00003-auth-tokens-for-sub-repos.md), and returns
   `NotAuthorized` when it is absent. Before that, both decode attempts in `verify_token_internal`
   require `env`, `name`, and `preferred_username` as mandatory string claims. No standard provider
   issues any of those, so a token that is correctly signed and names the right audience is refused at
   deserialization, before authorization is even reached.
2. **The provider is never advertised.** `EnvironmentGet` hands the client whatever the operator put
   in `auth_url`, verbatim (`lore-server/src/grpc/environment_service.rs`), and the client dispatches
   on its scheme. Nothing derives that string from the authentication settings, which is the trap
   issue #161 fell into.
3. **No client implementation speaks the standards.** The registry has one scheme, and it talks to a
   service that does not exist outside Epic.

**The change is governed surface.** GOVERNANCE.md requires an accepted LEP, with a minimum two-week
discussion period, before implementing a change to authentication flows, and an accepted LEP binds
the implementation.

**There is a competing proposal.** [PR #22](https://github.com/EpicGames/lore/pull/22) proposes a
standalone `lore-auth-server` that authenticates through a provider and mints Lore JWTs, and lists
"verify upstream IdP tokens in Lore Server" as an alternative it rejects. That proposal targets a
managed deployment; this one targets self-hosted deployments, where an extra service to deploy,
secure, and operate is the dominant cost. **Alternatives Considered** engages it directly.

## Goals / Non-Goals

### Goals

1. **An operator secures a Lore server with any conformant provider by naming an issuer and a client
   id.** No other configuration, and nothing new to deploy or operate.
2. **The server carries no provider-specific code.** Every endpoint and every key comes from the
   provider's own discovery document, so supporting a new provider is a configuration change.
3. **A verified token from the trusted issuer authorizes every repository on the server.** The
   authorization decision is that the provider admitted this identity, and the configuration states
   it in terms of what it grants.
4. **All three public protocols enforce it identically.** gRPC, HTTP, and QUIC reach the same
   verifier and the same authorization decision.
5. **A user logs in from the CLI with standard flows, and stays logged in.** Authorization code with
   PKCE over a loopback redirect for a machine with a browser, the device authorization grant for one
   without, and the refresh grant so the session outlives the first token.
6. **Tokens keep living in the existing credential store, and the token-recipient guard keeps
   holding.** A token obtained for one remote is never sent to another.
7. **An unconfigured server behaves exactly as it does today.** Absent settings mean no
   authentication, on every path, with no new code between a request and its handler.

### Non-Goals

- **Per-repository authorization from provider claims or groups.** There is no standard claim for it,
  and mapping one is a design of its own. A follow-up LEP owns it; this proposal is written so that
  work replaces one function rather than reopening the design.
- **Replacing or removing `ucs-auth`.** The two schemes coexist in the registry; Epic's deployment is
  unaffected.
- **Server-minted tokens or token exchange.** Lore issues nothing and signs nothing. There is no
  Lore signing key anywhere in this design.
- **A web interface.** Login is a CLI operation that borrows the user's browser.
- **SAML, LDAP, or Kerberos.** OpenID Connect only.
- **Several issuers on one server.** One issuer per server. A deployment federating several identity
  sources does that in the provider, which is what providers are for.

## Proposed Design

### Server configuration (Goal 1)

`AuthSettings` (`lore-server/src/settings.rs`) gains one optional block:

```toml
[server.auth.oidc]
issuer = "https://id.example.com"
client_id = "lore"
authorize_all_repositories = true
```

`issuer` is the provider's issuer identifier, exactly as the provider publishes it — the same string
it puts in the `iss` claim. `client_id` is the public client registered for Lore. Both are required
when the block is present.

`authorize_all_repositories` has **no default**, and a configured block that omits it, or sets it to
`false`, fails configuration validation at start-up with a message saying that per-repository
authorization from provider claims is not implemented. This proposal offers exactly one
authorization mode, and it is a coarse one; an operator has to write down that they want it. Failing
to start is the right verdict because the alternative readings are both wrong: defaulting to `true`
grants every repository to every authenticated identity on the strength of an omission, and
defaulting to `false` starts a server that verifies every token and then refuses every request.

The block supplies what the existing settings otherwise ask for twice. `jwt_issuer` and
`jwt_audience` are derived from `issuer` and `client_id` when the block is present, and
`[server.auth.jwk].endpoint` is derived from discovery. Where an operator sets one explicitly it
wins, which keeps the `file://` key-set endpoint reachable
([issue #32](https://github.com/EpicGames/lore/issues/32),
[PR #44](https://github.com/EpicGames/lore/pull/44)) as an offline escape hatch for an air-gapped
deployment or a provider outage that coincides with a restart.

### Discovery, and why it answers the coupling objection (Goal 2)

At start-up the server fetches `{issuer}/.well-known/openid-configuration`
([OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html) §4) and
reads exactly two members from it: `issuer`, to check against its own configuration, and `jwks_uri`.
The `jwks_uri` becomes the `JWKService` endpoint, and every subsequent key fetch, cache, throttle, and
rotation is the code that is already there. The server needs nothing else — the endpoints a login flow
uses are the client's business, and the client fetches the same document for itself, so the server
never relays a provider's endpoints and cannot get them stale.

The document's own `issuer` member must equal the configured issuer, byte for byte (Discovery §4.3).
That check is what makes a discovery URL safe to fetch: without it, a redirect or a compromised
well-known path could point the server at a key set belonging to somebody else, and the server would
verify forged tokens against it.

This is the whole answer to PR #22's coupling objection. The server holds one provider-specific
string, and it is configuration. There is no per-provider code path, no per-provider claim policy, no
release coupled to a provider's behavior. The two provider quirks the tree has already met — Entra
omitting `alg` (issue #60, [PR #65](https://github.com/EpicGames/lore/pull/65)) and key rotation
under an unchanged key id ([issue #78](https://github.com/EpicGames/lore/issues/78),
[PR #99](https://github.com/EpicGames/lore/pull/99)) — were both fixed as conformance to
[RFC 7517](https://www.rfc-editor.org/rfc/rfc7517), not as provider special cases, and both fixes
are in `jwk.rs` today with tests naming the provider that exposed them.

### What the server accepts, and which token the client presents

The client presents the **ID token** ([OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
§2). This is a decision, and the reason is that it is the only token OpenID Connect guarantees:
guaranteed to exist, guaranteed to be a signed JWT, and guaranteed to carry the client id in `aud`,
which is the value the server pins. Access tokens are explicitly permitted to be opaque
([RFC 6749](https://www.rfc-editor.org/rfc/rfc6749) §1.4), so requiring a verifiable access token
would make the design depend on provider-specific behavior — the coupling this proposal exists to
avoid. **Drawbacks** records the cost, and **Unresolved Questions** records the standards-track route
out of it.

Verification therefore needs a claim shape that a conformant ID token satisfies.
`verify_token_internal` currently tries `AuthorizationToken`, then `JWTUserInfo`, and both demand
`env`, `name`, and `preferred_username`. A third and final attempt decodes only what
[RFC 7519](https://www.rfc-editor.org/rfc/rfc7519) and OpenID Connect Core guarantee — `iss`, `sub`,
`aud`, `exp`, `iat` — with `name`, `preferred_username`, and `email` optional, and maps the result
into `AuthorizationToken` with `idp` set to the issuer, `resources` left `None` for the authorization
mode below to fill in, and the display fields falling back to `sub`.

`aud` is a set, not a scalar. OpenID Connect Core §2 defines it as an array of audiences, and providers
differ over whether they collapse a single-element one to a bare string — PocketID 2.6.2 emits the
array form. Nothing has to be built for this: `AuthorizationToken` and `JWTUserInfo` already carry
`#[serde_as(as = "OneOrMany<_, PreferMany>")]` on `audience`, so both encodings deserialize to
`Vec<String>`, and `Validation::set_audience` tests membership rather than equality. The new claim
struct carries the same attribute, and the pin is stated throughout this proposal as `aud`
*containing* the configured client id for exactly that reason.

Two properties make this additive rather than a widening. It is reached only when both existing
decodes have already failed, which today is an outright rejection, so no token that is accepted now
takes a different path. And it is compiled in but gated on the OIDC block being configured, so a
deployment running `ucs-auth` accepts exactly the tokens it accepts today.

### Binding tokens to one deployment, where the provider allows it

The paragraph above ends at a real limit: `aud` names the client, so it cannot tell two Lore
deployments apart. Every deployment registered behind the same issuer and client id — which is the
ordinary case for an organization running staging beside production — accepts every other one's
tokens. **Security Considerations** states what follows from that.

The standards-track answer is a pair: [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707) resource
indicators, which let a client ask for a token bound to a named resource server, and
[RFC 9068](https://www.rfc-editor.org/rfc/rfc9068) JWT access tokens, which are what such a token
is. This proposal ships both as an opt-in that is strict when enabled, because mandatory would be
unshippable: a provider is under no obligation to implement either, and PocketID 2.6.2 — the
provider this work validates against — implements neither.

`[server.auth.oidc]` gains one optional field:

```toml
resource = "https://lore-prod.example.com"
```

Its value is an RFC 8707 resource indicator, which §2 defines as an absolute URI with no fragment
component; start-up validation enforces exactly that, because the alternative failure is the worst
kind — a server pinning an audience no provider will ever mint, so that every login succeeds and
every request is refused. It is an identifier, not an endpoint: nothing dials it.

**What the server then requires.** `aud` is pinned to the resource rather than the client id, and
the accepted credential becomes an RFC 9068 JWT access token. The verifier follows §4's validation
list: the `typ` header must be `at+jwt` or `application/at+jwt` (§2.1 registers the media type and
recommends omitting the prefix; §4 step 1 accepts both, and the comparison is case-insensitive
because `typ` is a media type); `iss` must equal the configured issuer; `aud` must contain the
configured resource; `exp` must not have passed; and the signature must verify under the
algorithm the key declares, which is the existing pin. Encryption is not negotiated anywhere in
this design, so §4's decryption step has nothing to do.

ID-token acceptance is **off** in this mode, and the `typ` check is what turns it off — every ID
token, and every `ucs-auth` token, carries `typ: "JWT"`. Leaving the weaker credential reachable
would leave a way around the stronger one, which is the entire reason an operator turned this on.

**Which of §2.2's required claims are enforced.** RFC 9068 §2.2 requires `iss`, `exp`, `aud`,
`sub`, `client_id`, `iat`, and `jti`. The server additionally requires `sub` and `iat`, because it
reads them — `sub` is the identity every authenticated path records. It accepts a token that omits
`client_id` or `jti`. The reason is the specification's own division of labor: §2.2 binds the
authorization server issuing a token, while §4 — the resource server's validation list — names
neither, and Lore consumes neither. There is no replay cache for `jti` to key, because this design
holds no per-request state at all (**Non-Functional Considerations**, Statelessness), and the
client id stopped being pinned the moment `aud` began naming the resource server. Refusing a token
whose security properties are complete, over claims that would then be discarded, buys nothing and
costs interoperability.

**What the client does.** RFC 8707 §2 puts the `resource` parameter on the authorization request
and on the token request of every grant type, so the client sends it on all five: the authorization
request, the authorization-code exchange, the device authorization request, the device token poll,
and the refresh grant. It then presents the **access token** rather than the ID token. The ID token
remains the identity assertion — it is what carries `nonce` and the display claims, and it is still
checked — but the credential stored, presented, and refreshed on expiry is the one the server
verifies, and its expiry is what the credential store counts down.

**The client checks what it got back, and this is the part experience forced.** A provider that
does not implement RFC 8707 is under no obligation to say so, and PocketID 2.6.2 demonstrates the
consequence: it answers `200` to the parameter on every leg, ignores it, and mints an ordinary
client-audienced token with `typ: "JWT"`. Left unchecked, `lore login` would succeed, store a
credential, print a user name — and then every repository operation would be refused, with the
cause two layers away and nothing in the login transcript pointing at it. So the client verifies
that the access token it received is a JWT of the right media type whose `aud` names the resource,
and fails the login naming what the provider did not do. This is a diagnostic, not a security
control: the server verifies the token itself and its verdict is the only one that decides
anything.

Absent `resource`, none of this happens: no parameter is sent, the ID token is the credential, and
the server behaves exactly as the section above describes. That is what makes it an opt-in rather
than a migration.

The algorithm allowlist tightens in OIDC mode. The loader already refuses to *infer* a symmetric
algorithm, and refuses a key whose declared algorithm belongs to another key type — the
algorithm-confusion forgery, tested in `jwk.rs`. What it still honors is a provider *declaring*
`HS256` on an `oct` key in its published key set, which is exactly the mistake PR #22 reports its own
prototype making: a symmetric secret published in a public key set is a signing key for anyone who
can read it. In OIDC mode the server refuses symmetric algorithms outright, leaving `RS*`, `PS*`,
`ES*`, and `EdDSA`. `alg: none` needs no narrowing to go with it: `jsonwebtoken::Algorithm` has no
such variant, so a token header naming it is refused in every mode, before a key is looked up.

### One authorization mode, named for what it grants (Goal 3)

The grant attaches to the token, at the one place that verified it, rather than being threaded through
every place that consults it. When `authorize_all_repositories` is on and a token verifies against the
pinned issuer, `JwtVerifier` populates the resulting in-process `AuthorizationToken` with the wildcard
resource the authorization model already has: `resources = [ResourcePermission { resource_id: "urc-*",
… }]`. `ResourcePermission::is_wildcard_resource` and `matches_repository` already grant every
repository for that value, `verify_authorization` already returns `Ok(())` for it, and
`verify_authorization_allows_all_repos_for_wildcard_token` in `lore-server/src/auth/jwt.rs` already
tests exactly that. So `verify_authorization` needs no new argument and no change at all.

**Why the grant belongs on the token.** `verify_authorization` has seven callers, and only four of
them are places a `JwtVerifier` or the server settings can reach:

- the gRPC interceptors (`lore-server/src/auth/jwt_interceptor.rs`),
- the HTTP middleware (`lore-server/src/auth/jwt_axum_middleware.rs`),
- QUIC `Connect::handle_auth` (`lore-server/src/protocol/storage/connect.rs`),
- QUIC v4 `AuthorizeStart` (`lore-server/src/quic/storage_service_v4.rs`).

The other three hold only an `AuthorizationToken` recovered from request extensions or the connection's
attribute map, and they are the interesting ones: both `copy` handlers
(`lore-server/src/grpc/storage/v1/copy.rs`, `lore-server/src/protocol/storage/copy.rs`) authorize a
*source* repository other than the connected one, and `link_read_authorizer`
(`lore-server/src/grpc/mod.rs`) hands the revision layer a predicate deciding which linked repositories
a read may traverse. A mode threaded as a per-call argument would have to be plumbed to all three
through layers that have no business knowing about authentication settings — and a site that was
missed would fail closed for `copy` and silently narrow for link traversal. Putting the grant on the
token makes every consumer, present and future, correct by construction.

**What is being synthesized, and what is not.** The wildcard resource exists only in the in-process
`AuthorizationToken` for the duration of the request. Nothing re-serializes it, nothing signs it,
nothing returns it to a client, and no Lore signing key exists anywhere in this design — the
server-minted-tokens non-goal holds exactly. What the server does is record, in the structure the rest
of the request already reads, the authorization decision it just made from configuration.

This is a degenerate case of the third option ADR-00003 considered and rejected: one token that only
identifies the user, with the server resolving authorization. ADR-00003 rejected it because the server
would perform authorization work per connection, possibly involving external services or other I/O.
That objection does not reach this mode, because the resolution is a constant read from configuration.
It does reach the per-repository follow-up, which is why that work is a separate LEP and why
ADR-00003's reasoning still stands where it was aimed. That follow-up replaces one function — the one
that decides what `resources` a verified token carries — instead of revisiting seven call sites.

**Delete is the one operation this mode does not reach, and that is an interim.** Repository delete is
the only repository operation whose authorization does not run through `verify_authorization`: both
implementations ask the relationship-based authorization service when `auth_url` names one, and
otherwise fall back to a local check that the caller is the repository's recorded creator. The scheme
gate takes that second path under OIDC, so delete is governed by creator ownership — the same rule an
unconfigured server applies — while every other operation is governed by the all-repositories grant.
This is the safer of two answers rather than a designed one: dialing the provider as though it were
the authorization service is not an option, and letting any authenticated identity delete any
repository on the server, silently and as a side effect of a scheme check, is a wider grant than this
proposal argues for anywhere else. **Unresolved Questions** asks which it should be, and the answer
belongs in this LEP's discussion rather than in the guard that currently decides it.

### The enforcement points (Goal 4)

Every plug point that admits a request already holds a `JwtVerifier`, and none is added or moved. The
three public protocols reach the verifier through four entry points, because the QUIC storage protocol
has two versions in service:

- **gRPC** — the tonic interceptors in `lore-server/src/auth/jwt_interceptor.rs`, installed from
  `lore-server/src/grpc/server.rs` only when a verifier exists.
- **HTTP** — `jwt_axum_verify_authorization` in `lore-server/src/auth/jwt_axum_middleware.rs`.
- **QUIC** — `Connect::handle_auth` (`lore-server/src/protocol/storage/connect.rs`) and
  `AuthorizeStart` (`lore-server/src/quic/storage_service_v4.rs`), each verifying once per connection
  or session, following ADR-00003's one-token-per-connection shape.

Because the grant travels on the token, all four admit a request identically and every downstream
check — both `copy` source checks and link traversal — reaches the same verdict from the same value.
The `JWTAuthnInterceptor` placeholder (`TODO(UCS-13506)`) is completed by the same mechanism: it
verifies authentication and inserts the token, and the token now carries the grant, so the repository
service stops being a hole in the model.

`EnvironmentService` stays unauthenticated, as its own documentation states: a client has to be able
to ask how to authenticate before it can authenticate. The health check stays open.

### Advertising the provider (Goal 2, and the fix for issue #161)

The server advertises the provider through the existing `EnvironmentGet` `auth_url` field
(`lore-proto/proto/lore/environment/v1/environment.proto`), encoded as:

```text
oidc+https://id.example.com?client_id=lore
oidc+https://id.example.com/realms/studio?client_id=lore&resource=lore.example.com
```

When the OIDC block is configured and `environment.endpoint.auth_url` is empty, the server derives
this string rather than making the operator write the issuer down twice. An explicitly configured
`auth_url` still wins. Deriving it is the direct fix for the shape of issue #161: verification and
advertisement stop being two independent settings that can disagree.

The encoding is worth defending, because five things constrain it at once.

**The scheme is the dispatch key.** `authentication::find` splits on the first `://` and looks the
prefix up in the registry, so the prefix is the whole extension mechanism. `oidc+https` registers as
one entry, `oidc+http` as another that the implementation accepts only for a loopback host — which is
what a local provider in a test harness or a development deployment is. The `+` composition follows
the convention Git uses for transport-qualified remotes (`git+https`, `svn+ssh`), and it states the
transport instead of assuming it.

**The issuer has to survive intact.** Issuer validation is a byte comparison: the `iss` claim, the
discovery document's `issuer` member, and the configured value must all match exactly. Stripping the
`oidc+` prefix from `oidc+https://id.example.com` yields the issuer string unchanged, with no
reassembly and no normalization to get wrong.

**Query parameters are safe to append.** An issuer identifier "MUST NOT contain a query or fragment
component" (Discovery §2), so the query string cannot collide with the issuer. `client_id` is
required and is not a secret — this is a public client using PKCE. `resource` is present exactly
when `[server.auth.oidc].resource` is configured, percent-encoded because a resource indicator is
itself an absolute URI, and it does two jobs. It is the RFC 8707 resource indicator the client sends
on its grant requests, which is what makes **Binding tokens to one deployment** work at all rather
than merely be strict — advertisement is the only channel by which a client learns to ask for a
resource-bound token, so a derivation that dropped it would leave every login succeeding and every
request denied. And it distinguishes two Lore deployments that share an issuer and a client id in
the client's token store, because the credential store keys on the auth URL. An operator who writes
`auth_url` out by hand has to carry the parameter themselves, which the configuration reference
says.

**No proto change.** `auth_url` is a string the server stores verbatim and the client dispatches on;
carrying a new scheme through it is what the field and the registry were built for. A new proto field
would be worse in both directions: an old client would ignore it silently and report no
authentication, where an unknown scheme produces an error naming the scheme and listing the ones it
does know.

**The server reads this field too, and in more places than one.** Reusing `auth_url` means reusing it
everywhere it is read, and on the server every reader wants the same thing from it: a dial target for
Epic's relationship-based authorization service. `repository_authorizer`
(`lore-server/src/authnz/repository_authorizer.rs`) selects an `AuthClientAuthorizer` — a gRPC client
for that service — whenever the value is `Some`, and `AllowAllRepositoryAuthorizer` otherwise; and
four repository handlers dial the service directly to register or check a resource. Left alone,
advertising an `oidc+https://…` URL would point every one of them at the identity provider and fail
repository create, delete, query, and metadata operations alike.

Two mechanisms keep advertisement and dialing apart, and the design needs both.

**The derived URL never reaches an internal consumer.** `launch_grpc_server`
(`lore-server/src/server.rs`) derives the advertisement into a clone rather than into the
configuration itself: `environment` keeps whatever the operator configured and remains what internal
consumers read, while `advertised_environment` carries the derived value and is what `EnvironmentGet`
returns — `GrpcServerBuilder::with_environment` now takes both. For a deployment configuring OIDC and
nothing else, the internal dial target is therefore `None`, exactly as on an unconfigured server,
rather than a string every downstream reader has to recognize and refuse.

**Each consumer gates on the scheme as well**, because an operator may still set `auth_url`
explicitly, and because a value that travels this far should not be safe only by virtue of where it
came from. `is_auth_client_scheme` (`repository_authorizer.rs`) is the single predicate — `ucs-auth`
and `https` name the authorization service, every other scheme does not — and it gates all five
reading sites: `repository_authorizer` itself, plus the four direct dials, in the two independent
repository-create implementations (`grpc/handlers/repository_create.rs`,
`grpc/repository/v1/repository_create.rs`) and the two repository-delete ones
(`grpc/handlers/repository_delete.rs`, `grpc/repository/v1/repository_delete.rs`). Falling back to
`AllowAllRepositoryAuthorizer` is the correct answer under `authorize_all_repositories`, and refusing
to be a silent broken client is the correct answer under anything else. Delete is the one operation
where the fallback is not simply "allow": it lands on the local creator-ownership check instead, which
**One authorization mode** takes up.

This is the strongest argument for prefixing the scheme rather than putting a bare issuer URL in the
field: the prefix is the only thing that makes the two cases distinguishable at all, and a bare URL
would have made this failure mode undiagnosable.

### The client implementation (Goal 5)

A new `Authentication` implementation registers for `oidc+https` and `oidc+http` beside `ucs-auth`.
It parses the issuer and parameters out of the auth URL, fetches the same discovery document the
server did — the client needs `authorization_endpoint`, `token_endpoint`, and
`device_authorization_endpoint`, none of which the server has any reason to relay — and fits three
flows onto the trait's existing method shapes. Every network client and task is constructed under
`lore_spawn_net!` on the net runtime, per the accepted
[runtime-split LEP](2026-07-24-tokio-runtime-split-and-async-io.md).

**Browser login: authorization code with PKCE over a loopback redirect.** `start_auth_session` binds
a listener on `127.0.0.1:0`, generates a code verifier and its S256 challenge
([RFC 7636](https://www.rfc-editor.org/rfc/rfc7636)), generates `state` and `nonce`, and returns the
provider's authorization URL as `login_url` with an opaque handle as `session_code`. The redirect URI
is `http://127.0.0.1:{port}/callback` with the port the kernel assigned — loopback interface
redirection, the mechanism [RFC 8252](https://www.rfc-editor.org/rfc/rfc8252) §7.3 specifies for
native applications, and the reason a native client needs no client secret and no registered public
callback host. `poll_auth_session` returns `None` until the listener has a request, then checks
`state`, exchanges the code with the verifier, validates the ID token's `nonce`, and returns it. The
existing `poll_interactive_session` loop in `lore-revision/src/auth/login.rs` drives this unchanged.

**Headless login: the device authorization grant.** `lore login --no-browser` today emits the
`login_url` as an event instead of opening a browser, and that is the shape
[RFC 8628](https://www.rfc-editor.org/rfc/rfc8628) wants: `start_auth_session` posts to the device
authorization endpoint and returns `verification_uri_complete` (or the URI and user code) as
`login_url` and the device code as `session_code`; `poll_auth_session` polls the token endpoint,
mapping `authorization_pending` to `None`, honoring `interval`, and backing off on `slow_down` (§3.5).
This is not a hoped-for capability: PocketID 2.6.2, the provider this work validates against,
advertises `device_authorization_endpoint` in its discovery document and completes the grant, so the
headless path is proven against the first configured provider rather than deferred to a later one.

A provider that advertises no `device_authorization_endpoint` gets a typed `NotSupported` failure
naming the missing capability and saying to log in from a host with a browser instead. The
alternative — printing the authorization URL for the user to open on another device — is not offered
because it cannot complete: that flow's redirect goes to a loopback listener on *this* host, so the
code has nowhere to land, and the honest answer arrives immediately rather than as a poll loop
waiting on a redirect that can never arrive.

**Staying logged in: the refresh grant.** The client requests the `offline_access` scope, and
`refresh_authentication` posts a `refresh_token` grant. `AuthenticationToken.refresh_token` and
`token_store::store_refresh_token` already exist and already treat refresh tokens as separately
stored and rotated, so this is filling in an implementation, not extending a mechanism.

**`exchange_for_repository` returns the authentication token unchanged.** There is nothing to
exchange it with and nothing to mint. The call shape ADR-00003 established survives — the client
still asks for a token for a repository and still gets one back, and the QUIC path still sends one
token per connection — and the server authorizes it under `AllRepositories`. When the follow-up LEP
adds per-repository authorization from claims, this is the seam it works at.

`exchange_for_custom_resource` returns the same token for the same reason.

`exchange_external_token`, `get_user_info`, and `get_user_id` return `NotSupported`: the provider owns
identity resolution, and this proposal reads no directory. `lore user info` against a secured server
therefore reports that the provider exposes no lookup, rather than resolving a display name, and the
operator documentation has to say so.

**Displaying who is logged in needs one claim relaxed.** After a login, the orchestration layer builds
its `UserInfo` through `insecure_decode_token` into `lore-credential`'s `JWTUserInfo`
(`lore-credential/src/jwt.rs`), whose `name` field is a required `String`. `name` is an OpenID Connect
claim, but an optional one delivered with the `profile` scope, so a provider that omits it makes
`user_info_from_token` return `None` and the login fail with "Unable to load user info" after having
succeeded. The field becomes `Option<String>`, falling back to `sub` for display. This is the client
half of the same mismatch the server's claim shape has, and it is the same fix: require what the
standards require, and no more.

### Keeping the token-recipient guard (Goal 6)

The threat the guard exists for is written down in `lore-revision/src/auth.rs`: an attacker stands up
a server whose environment names a trusted auth service, a user clones from it, and the CLI dutifully
sends that service's token to the attacker. `verify_jwt_usage_for_remote`
(`lore-credential/src/jwt.rs`) is the defense — a token goes only to a domain in its acceptable set —
and the set is stored alongside the token in the credential store, filtered on load by
`tokens_only_for_recipient_domain`.

Today `login::interactive` derives that set by decoding the token and calling
`JWTUserInfo::acceptable_root_domains()`, which concatenates `iss` and `aud`. That works for
`ucs-auth`, where the auth service issues `aud` as a list of root domains — the code says so. It
cannot work for OpenID Connect, where `aud` carries a client id rather than any domain, and `iss` is a
URL rather than a bare host.
Both would fail `domain_in_root_domains` against any remote, so every OIDC login would refuse its own
token.

`AuthenticationToken` already carries an `acceptable_root_domains` field, and `ucs_auth.rs` leaves it
empty with a comment saying the orchestration layer fills it in from the JWT. This proposal makes that
field authoritative when it is non-empty: the implementation knows how its own tokens' audience
semantics work, and the orchestration layer stops guessing. `ucs-auth` returns an empty vector and
keeps today's behavior exactly.

The OIDC implementation returns the issuer's **host** — a token can always go back to the party that
issued it, which is what the refresh and token endpoints are — and the orchestration layer adds the
host of the remote the login was performed against, which is the only layer that knows it. So the
rule for an OIDC token is: usable at the remote you logged in to, and at its issuer, nowhere else. The
guard's actual property is preserved in full — a stored token never reaches a third party — and it is
preserved without asking the operator to configure their own public hostname, which is the class of
second-place-to-configure mistake issue #161 is.

One consequence is worth stating, because it is visible to users. The credential store keys tokens by
`(auth_url, identity)` and holds one token per pair. Two Lore deployments sharing an issuer and a
client id therefore share a bucket, and logging in to the second replaces the first's entry, whose
acceptable set named a different host — so the user re-runs `lore login` when switching between them.
The `resource` parameter is the fix: two deployments advertising different `resource` values advertise
different auth URLs and get separate buckets. This is the second job that parameter does, and the
reason it is in the encoding rather than left out as redundant.

### Building on existing dependencies rather than adopting a crate

The flows are implemented on `reqwest`, `jsonwebtoken`, `ring`, and `url`, all already workspace
dependencies. What the client actually owes the provider is small and entirely mechanical: a discovery
fetch and four JSON field reads; a code verifier, its SHA-256 challenge, and base64url encoding; two
form posts; a loopback listener; and a polling loop with a documented back-off. `deny.toml` bans
`openssl`, `openssl-sys`, `aws-lc-rs`, and `aws-lc-sys`, so rustls and `ring` are the only options a
new dependency could be built on in any case. **Alternatives Considered** states the trade-off against
the `openidconnect` crate rather than dismissing it.

### Provider quirks this design does not absorb, and where they would attach

Goal 2 says the server carries no provider-specific code, and three known provider behaviors are the
places that claim would come under pressure. None is handled, because no validated provider needs
it; each is named here rather than discovered later, with the seam it would attach to, so a
follow-up extends a mechanism instead of reopening this design.

- **Refresh-grant scope adapters** — some providers require the refresh request to repeat `scope`,
  or narrow the granted set when it is omitted. The seam is the refresh grant's form, which already
  carries a conditional parameter.
- **A fixed loopback redirect port** — RFC 8252 §7.3's kernel-assigned port is what this design
  uses, and a provider that will not register a wildcard callback cannot accept it. The seam is
  client configuration choosing the port before the listener binds; nothing else changes.
- **Encrypted (JWE) ID tokens** — a provider that encrypts ID tokens by default produces a token the
  verifier cannot decode, which **Risks and Assumptions** already records as an invalidating
  assumption. The seam is a decryption step ahead of the claim decode, plus key material to
  configure for it; RFC 9068 §4 step 2 reserves the same step on the access-token path.

### Goal tracing

Goal 1 → **Server configuration**. Goal 2 → **Discovery**, **Advertising the provider**, and
**Provider quirks this design does not absorb**. Goal 3 → **One authorization mode**. Goal 4 →
**The enforcement points**. Goal 5 → **The client implementation**. Goal 6 → **Keeping the
token-recipient guard** and **Binding tokens to one deployment**. Goal 7 → **Compatibility**, below.

## Compatibility

- **Wire format** — N/A. No message, framing, serialization, or byte layout changes. The QUIC
  `Connect` message already carries an optional token as its payload and carries the same one.

- **Client/server protocols** — No new or changed RPC, and `lore-proto` has no diff: the provider
  travels in the existing `EnvironmentEndpoint.auth_url` string. Three directions matter.

  *An unconfigured server* behaves exactly as today on every path. `state.jwt_verifier` is `None`, so
  the HTTP middleware inserts no identity and calls the next layer; `Connect::handle_auth` receives an
  `Arc<Option<JwtVerifier>>` holding `None` and skips verification; the gRPC interceptors are
  constructed inside an `if let Some(jwt_verifier)` and so are never installed; `auth_url` is whatever
  the operator configured, which for every shipped configuration is nothing. The authorization mode
  never comes into existence, and the third claim decode is gated off.

  *An old client against a new secured server* reads `oidc+https://…` from the environment response
  and fails in the registry: `authentication::find` reports "no authentication implementation
  registered for scheme 'oidc+https'" and lists the schemes it does have, which on an old client are
  `ucs-auth` and the `https` transition fallback. On `lore auth login` that surfaces as an internal
  error carrying that text; on a repository operation the connection path
  finds no usable identity and returns `NotAuthenticated`. The failure is clean, immediate, and names
  the cause — the user upgrades the client. There is no path on which an old client reaches a
  repository unauthenticated, because the server's refusal does not depend on the client understanding
  the scheme.

  *A new client against an old or unconfigured server* is unchanged: the server advertises an empty
  `auth_url` or a `ucs-auth://` one, the new scheme is never selected, and the registry entry is
  inert. `scripts/test/test_auth.py`'s assertions that `lore auth login` fails with `NotSupported`
  against the unauthenticated test server continue to hold, for the same reason as before — an empty
  `auth_url`.

- **On-disk format** — N/A for repositories: no fragment flag, index, or schema change, and an
  upgraded and a downgraded Lore read the same repositories. The credential store's `tokens.toml`
  gains no field: `IdentityToken.acceptable_root_domains` and `refresh_token` both already exist, both
  are `#[serde(default)]`, and an OIDC token is one more entry of the shape already written there.

- **CLI and public API** — Additive. `lore login`, `lore auth login --no-browser`, `lore auth info`,
  `list`, `logout`, and `clear` keep their syntax, exit codes, and output; what changes is that
  against a secured server they now succeed instead of failing. `lore user info` against a secured
  server reports that the provider exposes no directory lookup, which is a new message on a command
  that has no working path there today. No `lore-capi` or JS binding surface changes — `lore.h` has no
  diff. No existing script breaks, because every command that works today works identically against a
  server that has not turned this on.

- **Rust crate surfaces** — Three changes, none of which alters an existing behavior, and none of
  which crosses the C or JavaScript boundary.

  `JWTUserInfo.name` (`lore-credential`) becomes `Option<String>`. This strictly widens what is
  accepted: every token that deserializes today still deserializes, and some that did not now do.

  `Authentication::start_auth_session` (`lore-transport`) gains a `LoginFlow` parameter, so an
  implementation can select a ceremony that suits the calling host — the OIDC implementation runs the
  device authorization grant where `ucs-auth` has only one ceremony and ignores the argument. The
  value is derived from the existing `lore login --no-browser` flag, so no CLI surface changes and no
  caller gains a decision it did not already make; the fallout is mechanical, in `ucs_auth.rs`, the
  one call site in `lore-revision`, and the test doubles.

  `GrpcServerBuilder::with_environment` (`lore-server`) takes the advertised environment as a second
  argument, per **Advertising the provider**. Passing the same value twice is exactly today's
  behavior, which is what every caller outside `launch_grpc_server` does.

  `verify_authorization` keeps its signature and its behavior, because the grant arrives on the token
  rather than as an argument.

  `repository_authorizer` (`lore-server/src/authnz/repository_authorizer.rs`) keeps its signature and
  changes its selection rule from "any `Some` value" to "a scheme this server implements an
  authorization client for". For every deployment that exists today the outcome is identical, because
  every `auth_url` in use is a `ucs-auth` or `https` one; what changes is that a scheme it cannot speak
  no longer produces a client pointed at the wrong service.

- **Configuration** — Additive and backward-compatible. `[server.auth.oidc]` is a new optional block;
  `AuthSettings`' three existing fields keep their meanings and their behavior when set explicitly.
  Its `resource` field is optional and absent by default, and a block without one behaves exactly as
  it did before the field existed — no parameter on the wire, no change to what verifies. Two new
  failure modes, both at start-up and both by design: a server that configures the block without
  `authorize_all_repositories = true` refuses to start (see **Server configuration**), and one whose
  `resource` is not an absolute URI without a fragment refuses to start (see **Binding tokens to one
  deployment**). No environment variable is retired.

## Non-Functional Considerations

- **Concurrency** — No new shared mutable state on the server. Discovery runs once at start-up. Key
  fetches go through `JwkServiceImpl`, whose refresh mutex already collapses concurrent misses into a
  single outbound request and whose `MIN_REFRESH_INTERVAL` already bounds fetches however many unknown
  key ids arrive — both properties tested, and both load-bearing here because an unauthenticated
  caller can present arbitrary key ids. Verification itself is a pure function of the token and a
  cached key, so concurrent requests neither contend nor order against each other. On the client, a
  pending login is one task owning one listener, and concurrent `lore` commands each run their own.

- **Memory** — Bounded and small, with nothing proportional to repository or file size. The key-set
  document is capped at `JWKS_MAX_RESPONSE_BYTES` (1 MiB) by an accumulating read that does not trust
  `Content-Length`; the discovery document is read under the same cap. Tokens are kilobytes. The
  streaming and sparse-data-structure model is untouched — this proposal never touches a payload.

- **Statelessness** — The server gains none. It holds the key cache it already holds, and every
  authorization decision is a function of one token. There is no session, no nonce store, no replay
  cache, and no revocation list, which is what makes a secured server as horizontally scalable as an
  unsecured one — the property PR #22's design lists as an unresolved question for itself. On the
  client, pending login state (verifier, `state`, `nonce`, listener, device code) is
  process-local and dies with the command; only tokens outlive it, in the store that already holds
  them.

- **Determinism** — N/A, with the reason: nothing in this proposal enters repository content,
  addressing, or history, so the property it is asking about is not one this design can affect. Two
  runs of the same operation against the same revision produce the same result whether or not
  authentication is on. Token verification is not deterministic in the same sense and cannot be — it
  reads the clock for `exp` and the provider's current key set for the signature, which is what
  expiry and rotation mean.

- **Runtime placement** — Discovery and key-set fetches are network I/O and belong on the net runtime
  established by the [runtime-split LEP](2026-07-24-tokio-runtime-split-and-async-io.md); every client
  flow constructs its HTTP client and its listener under `lore_spawn_net!`. This proposal adds no
  blocking call and does not worsen the known `block_in_place` in `jwt_interceptor.rs`: the
  all-repositories path takes the identical cached-then-fallback route the resource-claim path takes,
  so the hot path stays synchronous on a cache hit and the fallback stays exactly as frequent as it
  is now. That
  LEP's phase 1 owns removing the `block_in_place`, and this design neither depends on it nor
  obstructs it.

- **Latency** — One extra HTTP round trip at server start-up (discovery), before the listeners open.
  Steady-state request latency is unchanged: verification on a warm key cache is signature
  verification and claim checks, with no I/O. A key rotation costs one throttled fetch, shared by
  every request that raced it.

## Migration Plan

`N/A — no breaking changes, no migration required.`

Turning it on is a configuration change and a restart, and turning it off is the same in reverse:
remove the block, restart, and the server is unsecured again with no state to clean up, because the
design stores none. Tokens issued in the meantime expire on their own, and a client whose token is
refused falls back to the same `NotAuthenticated` path it uses today.

## Security Considerations

**The trust model changes, in one specific way: the operator's provider becomes a trust boundary.**
An identity the provider admits is an identity Lore admits. That is the point of the feature, and it
is a smaller change than it sounds, because the server trusts the provider to *authenticate* and
nothing more: it does not read groups, does not read roles, and cannot be steered by any claim the
provider chooses to add.

**Pinning is what makes trusting one provider not mean trusting any provider.** Four pins, each on a
value the operator configured or the provider published: the discovery document's `issuer` must equal
the configured issuer (Discovery §4.3), the token's `iss` must equal it too, the token's `aud` must
contain the configured client id, and `exp` must not have passed. Discovery and key-set fetches go
over TLS through the shared `reqwest` client, which is built `use_rustls_tls()` with webpki and
native roots. The verification algorithm comes from the key, never from the token header — the
existing pin, tested against a forgery that signs with the public modulus as an HMAC secret — and in
OIDC mode a symmetric algorithm is refused outright rather than merely left out of the inference,
which closes the case of a provider publishing a symmetric secret in its own key set. `alg: none` is
refused in every mode, by a decoder that cannot represent it.

**The all-repositories grant is stated plainly, because it is the sharpest edge here.** In this mode
every identity the provider admits can read and write every repository on the server. There is no
per-repository distinction, no read-only identity, and no administrative separation. Three
consequences follow from the wildcard reaching every consumer, and they are the point of putting it on
the token rather than an accident of it: a `copy` may name any repository on the server as its source,
a link traversal may read any linked repository, and the repository service's per-repository check
resolves to `AllowAllRepositoryAuthorizer`, because the relationship-based authorization service it
would otherwise call is not part of this deployment. Each is the same sentence as the first one —
every repository, every authenticated identity — and each would otherwise have been an inconsistency
for an operator to discover. Repository delete is the exception and runs narrower than the grant, not
wider: it falls back to the creator-ownership check an unconfigured server uses, so an authenticated
identity that may write every repository may still only delete the ones it created. **One
authorization mode** explains why that is an interim, and **Unresolved Questions** asks what it should
settle into. An operator whose repositories have different audiences needs either the
follow-up
per-repository LEP or one server per trust boundary, and `authorize_all_repositories` has no default
precisely so that nobody arrives at this grant by omission.

**The grant is identical to a wildcard the server already honors**, which is worth saying because it
bounds the review surface: `resource_id = "urc-*"` is a value `ResourcePermission` already implements
and `verify_authorization` already accepts, and PR #22's own reference implementation ships
`allowed_resources = ["urc-*"]` as its default resource policy. This proposal introduces no new
authorization primitive; it decides, from configuration rather than from a claim, when the existing
one applies.

**Code interception on the browser flow** is answered by the two mechanisms the standards specify for
a public native client. The redirect goes to `127.0.0.1` on a port the kernel assigned to a listener
this process holds, so the loopback interface itself binds the response to the process that started
the flow (RFC 8252 §7.3); no other host is registered, so there is nowhere else for a code to land.
PKCE S256 (RFC 7636) means an intercepted code is useless without the verifier, which never leaves the
process. `state` is checked before the code is used, and the ID token's `nonce` is checked after, so
neither a cross-session response nor a replayed token is accepted. The
[OAuth 2.0 Security BCP](https://www.rfc-editor.org/rfc/rfc9700) is the shape of all of this.

**The device flow's surface is the user, not the protocol.** Its premise is that somebody approves,
on one device, something initiated on another, which is the premise a phishing message needs too. The
mitigations are the ones RFC 8628 §5.1 and §5.2 name and are limited: the CLI prints the user code so
the user can compare it with what the provider shows, and the client honors `interval` and `slow_down`
so it cannot be used to hammer the token endpoint. It does not need to be printed in a browser to be
approved, which is exactly why it works on a headless host and exactly why it is worth a warning in
the operator documentation. It is opt-in behind `--no-browser`.

**Refresh tokens are the longest-lived secret this design stores**, and they go where Lore's tokens
already go: the existing credential store, encrypted, with the OS keyring holding the key, and
rotated on use — `store_refresh_token` already keeps them separate from access tokens for that
reason. A stolen store file without the keyring entry is not a usable credential.

**The non-oracle behavior is preserved.** `jwt_interceptor.rs` deliberately collapses every
verification failure — bad signature, expired, unknown key id, unreachable provider — into a uniform
`permission_denied`, keeping the reason in the log where the operator can see it and out of the
response where an unauthenticated caller could learn from it. The OIDC path adds failure modes and
adds no responses: all of them collapse the same way.

**Two residual risks are worth naming rather than burying.**

**First: token confusion between deployments, narrowed by `resource` rather than removed.** In the
default mode `aud` names the client, so it cannot tell two Lore deployments apart, and three
things follow. Any deployment behind the same issuer and client id accepts any other's tokens. A
token harvested from one deployment's users opens all of them. And a malicious server can advertise
a real deployment's issuer and client id, so a user who points `lore login` at it completes a
genuine login and hands over a token the real server would also accept. The recipient guard does
not prevent this and is not meant to — it prevents the *stored* token from a different remote
leaking, which it still does.

**Binding tokens to one deployment** ships the standards-track answer, and the honest claim for it
is *narrows*, not *removes*. With `resource` configured, a token names one deployment: cross-
deployment interchange ends, and so does untargeted replay of a harvested token against any Lore
server other than the one it was minted for. What survives is the targeted variant. An attacker who
stands up a server advertising *your* resource identifier, and persuades a user to log in to it,
receives a token your server accepts — because the user asked their provider for a token for that
resource, and got one. No audience restriction can distinguish that from a legitimate login; it is
the phishing premise, not a gap in RFC 8707. What bounds it is that the user chose the remote.

Two further limits belong on the record. The mode requires a provider implementing both RFCs, and a
provider that implements neither does not say so — RFC 8707 obliges nobody to reject a `resource`
parameter it ignores, so the failure is silent at the protocol level and is caught instead by the
client checking the token it received (**Binding tokens to one deployment**). PocketID 2.6.2 is
exactly this case. And where the mode is unavailable, the baseline mitigation is registering a
distinct `client_id` per deployment, which restores the `aud` distinction without needing anything
of the provider beyond ordinary client registration; the operator guide says so.

**Second**, an ID token is an authentication assertion being presented as a bearer credential to a
resource server, which is a compromise the standards discourage; it is recorded in **Drawbacks**
rather than argued away. Configuring `resource` retires it, because an RFC 9068 access token is a
credential for a resource server by construction — which is the second reason to prefer that mode
where a provider allows it.

## Privacy Considerations

**The server sees an identity where it previously saw none.** For a token carrying only the required
claims, that is the provider's subject identifier, its issuer, and the client id — no email, no name,
no group membership, because the server reads none of those and the provider need not send them. Where
the provider does include `name`, `preferred_username`, or `email`, they are in the token the server
verifies, so they are visible to the operator. That is the same category of data a Lore token already
carries, and it reaches Lore only because the operator's own provider put it there.

**What reaches logs needs care, and one existing line is the reason.** `verify_token_internal` logs
`"Decoded user info: {:?}"` with the whole claim set at `debug`. With `ucs-auth` those claims are
Lore's own; with a provider's ID token they may include an email address or any other claim the
provider chose to add. The OIDC path must not widen this, and the implementation should narrow that
line to the fields Lore actually uses. Beyond it, `sub` is recorded as the `USER_ID` span field, which
is what it is for and is what the authenticated paths already record. Tokens, authorization codes,
code verifiers, device codes, and refresh tokens are never logged.

**Deletion and expiry are unaffected, and slightly better.** The server persists no identity: there
is no session table, no user store, and nothing to delete when a user leaves — revoking access is
revoking it at the provider, and the next token simply fails to verify. On the client, `lore auth
logout` and `lore auth clear` already remove stored tokens, and refresh tokens live in the same store
and go with them.

## Risks and Assumptions

**Assumptions**

- **Assumption:** the target provider is conformant enough to serve a discovery document at
  `{issuer}/.well-known/openid-configuration` whose `issuer` matches, and to publish a key set of
  asymmetric keys — *invalidated if:* a deployment must use a provider with no discovery endpoint, or
  one that publishes only symmetric keys, at which point the explicit `[server.auth.jwk].endpoint`
  covers the first case and nothing covers the second.
- **Assumption:** the ID token is a signed JWT whose `aud` contains the client id, per OpenID Connect
  Core §2, and is therefore verifiable by the existing verifier — *invalidated if:* a provider encrypts
  ID tokens by default, or issues them with an `aud` the server cannot pin.
- **Assumption:** providers grant `offline_access` (or issue refresh tokens by default) to a public
  native client — *invalidated if:* a deployment's provider refuses, in which case the session lasts
  one ID-token lifetime and the user re-runs `lore login`, which the CLI has to say clearly rather
  than failing opaquely.
- **Assumption:** an all-repositories grant is useful to real self-hosted operators, most of whom run
  one team's repositories on one server — *invalidated if:* early feedback says the coarse grant is
  unusable, which makes the per-repository follow-up a prerequisite rather than a successor.
- **Assumption:** the "larger auth overhaul" the maintainers mentioned on PR #22 in June 2026, whose
  details are undisclosed, does not preclude direct in-server verification — *invalidated if:*
  maintainer feedback on this LEP reveals plans that conflict. Opening this proposal for discussion
  early is the mitigation, and implementation effort ahead of that signal is at risk.

**Risks**

- **Risk:** a server restarts while the provider is unreachable, and comes up with no keys, refusing
  every request — *mitigation:* the explicit `[server.auth.jwk].endpoint` accepts a `file://` key set
  (issue #32, PR #44), which is the offline path; within a running process the existing cache means a
  provider outage does not immediately break verification.
- **Risk:** two Lore deployments sharing an issuer and client id share one credential-store bucket, so
  logging in to one evicts the other's token and the user re-logs in when switching —
  *mitigation:* distinct `resource` parameters give distinct auth URLs and distinct buckets; documented
  in the operator guide.
- **Risk:** a consumer of `auth_url` other than the client registry is missed, and an `oidc+https` URL
  is handed to code that expects an authorization service, failing repository create, delete, query,
  and metadata operations against a live provider — *materialized during implementation, and caught
  by the mitigation.* This entry originally named `repository_authorizer` as the one such consumer in
  the tree; that was wrong. There are five reading sites, because repository create and delete each
  have two independent implementations, and each dials the authorization service itself. The
  end-to-end test asserting that repository operations succeed against a secured server failed on
  `repository create` — a plaintext h2c dial into the provider's TLS port — and the delete path was
  found by tracing the same call shape rather than by a second failure. *Mitigation, as shipped:* the
  two mechanisms in **Advertising the provider** — the derived URL is confined to
  `advertised_environment` so internal consumers never see it, and `is_auth_client_scheme` gates all
  five sites — plus the integration and end-to-end coverage of create and delete against a live
  provider, which now exists and is what turned a design assumption into a caught bug.
- **Risk:** an unauthenticated caller drives outbound key-set fetches by cycling unknown key ids —
  *mitigation:* already bounded, and tested: `MIN_REFRESH_INTERVAL` throttles fetches once any key is
  cached, the refresh mutex collapses concurrent misses into one request, and a failure that no key
  could rescue (expiry, wrong audience) never asks for a refresh at all.
- **Risk:** hand-rolled flow code gets a security detail wrong that a maintained crate would have got
  right — *mitigation:* each mechanism is small, specified, and testable in isolation (PKCE challenge
  derivation, `state` and `nonce` comparison, discovery parsing, the polling state machine), and each
  gets unit tests written before the flow code; the provider-in-the-loop integration suite exercises
  the rejection paths, not only the happy one.
- **Risk:** the third claim decode accepts a token the operator did not intend, because it demands so
  little — *mitigation:* it is gated on the OIDC block, and what it demands little of is *claims*, not
  verification: signature, issuer, audience, and expiry are all checked before it runs, and the
  algorithm allowlist narrows in that mode rather than widening.
- **Risk:** the browser flow against a provider that requires a passkey or a hardware token cannot be
  driven from CI, so the end-to-end suite is harder to keep honest than the unit tests —
  *mitigation:* settled rather than pending. The device grant is scriptable end to end against PocketID
  2.6.2, so the headless flow covers the acceptance and rejection matrix in CI without a browser, and
  the passkey ceremony is what remains verified by hand.

## Drawbacks

- The server now depends on an external HTTP service being reachable at start-up to obtain the keys it
  verifies with.
- Lore owns the correctness of PKCE, the device flow, discovery parsing, and refresh handling instead
  of a library maintainer.
- The all-repositories grant is too coarse for any operator who needs different access to different
  repositories, and they must wait for the follow-up LEP.
- Presenting an ID token as a bearer credential to a resource server is a compromise the standards
  discourage, taken because it is the only token OpenID Connect guarantees is verifiable. It is the
  default rather than the only mode — configuring `resource` retires it — but the deployments that
  need the default most are the ones whose provider cannot offer the alternative.
- The resource-bound mode's requirements land entirely on the provider, and a provider that does not
  meet them says nothing: the failure surfaces as a Lore-side diagnostic at login rather than as a
  protocol error, which is a worse experience than an `invalid_target` would have been and is not
  something this design can fix.
- A second authentication scheme means every `lore auth` subcommand has two implementations to behave
  consistently across, and one of them cannot answer `get_user_info`.

## Alternatives Considered

### A token-minting broker service

[PR #22](https://github.com/EpicGames/lore/pull/22) proposes `lore-auth-server`: a service that
authenticates a user against a provider and mints a Lore JWT, signed asymmetrically, which the
existing verifier accepts unchanged. It is a good design for what it targets, a managed UEFN-style
deployment, and it is approved by one reviewer. This proposal targets self-hosted deployments, and for
those the costs land differently.

*Rejected because:* it is a third process to deploy, put behind a TLS-terminating proxy, rate-limit,
monitor, and upgrade, for an operator whose entire deployment today is one binary and a configuration
file. It introduces a second token format, so the tree carries two claim shapes and two issuance
paths where the provider already issues a perfectly good token. And it creates a second trust boundary
the operator has to protect: the broker holds a signing key that mints tokens the server trusts
without question, so key storage, key rotation, and the blast radius of a compromise all become the
operator's problem — PR #22 itself lists a single key with no rotation procedure, process-local session
state that prevents a second replica, and no rate limiting as known gaps of its initial deployment. In
a managed deployment those are a team's operational backlog. In a self-hosted one they are a burden
placed on someone who wanted to put their server behind the identity provider they already run.

PR #22's stated objection to direct verification is that it "moves OIDC discovery, JWKS handling, and
claim policy into Lore Server and every client, and ties Lore Server's releases to provider
specifics" — taking those in turn: key-set handling is not moved, it is already there and is the
actively hardened path in the tree (issue #32/PR #44, issue #60/PR #65, issue #78/PR #99, plus response
caps and the algorithm-confusion refusals — all of it in `jwk.rs` today with the tests to match).
Discovery is one document and three field reads, and it is what makes the coupling argument run the
other way: the server holds an issuer URL from configuration and no provider-specific code, so a new
provider needs no release. Claim policy is not moved either, because this proposal has none — it reads
`sub`, `iss`, `aud`, and `exp`, and everything a claim policy would decide is out of scope by
construction.

The two designs also compose rather than compete, which is worth saying plainly: to a server doing
direct verification, a broker is just another issuer. A managed deployment that wants
`lore-auth-server` points `issuer` at it and gets exactly the design PR #22 describes, while a
self-hosted deployment points `issuer` at its own provider and deploys nothing. Direct verification
does not foreclose the broker; it makes it optional. The same is true of
[issue #59](https://github.com/EpicGames/lore/issues/59)'s request for headless service-token
issuance: the device grant this proposal implements is the interactive half of that story, and the
client credentials grant is the natural extension, needing a scope decision rather than a new
architecture.

### The `openidconnect` or `oauth2` crates

Adopt `openidconnect` (or `oauth2` plus manual ID-token validation) for the client flows instead of
building on `reqwest` and `jsonwebtoken`.

The trade-off is genuine and worth stating before the verdict. The crates are well maintained,
rustls-compatible, and license-clean, and they supply discovery, PKCE, the device flow, and refresh
with their edge cases already handled — which is the honest reason to hesitate about hand-rolling any
of it.

*Rejected because:* what Lore needs is a strict subset — one grant-type family, one client type, no
dynamic registration, no ID-token encryption, no session management — while the crates bring their own
HTTP client abstraction and type-state builders that would have to be threaded onto the net runtime
and onto the `Authentication` trait's start-and-poll shape, and every added dependency and its tree
has to clear `deny.toml` and the `notices/` requirements. Integration cost plus ongoing supply chain
surface outweighs the code saved on a subset this small. This is the weakest rejection in this list,
and a reviewer who disagrees has a real case; the decision reverses in either direction, because the
flows sit behind one trait implementation.

### The status quo — pointing the key-set endpoint at the provider by hand

Configure `jwt_issuer` and `[server.auth.jwk].endpoint` against the provider's own endpoints, which is
what issues #60 and #161 show operators already doing.

*Rejected because:* it verifies signatures and nothing else works. A conformant ID token is refused at
deserialization for lacking `env`, `name`, and `preferred_username`; if it got past that,
`verify_authorization` refuses it for lacking `resources`; and the client is never told there is a
provider to log in to, so `lore auth login` reports "No authentication configured on server" against a
fully configured server. It is not a lighter version of this proposal — it is the part of it that is
already there, which is why the two issues exist.

### Front Lore with a reverse proxy or `oauth2-proxy`

Terminate authentication in front of the server, as `oauth2-proxy` does for HTTP applications.

*Rejected because:* Lore's primary transport is QUIC, not HTTP, so a proxy cannot cover the protocol
most traffic uses, and the gRPC and HTTP paths would be secured while the QUIC path stayed open —
the worst possible split. The server would still need the identity for the `USER_ID` span field and
for lock ownership, so it would need to trust a header the proxy injects, which is a weaker boundary
than a signature it verifies itself. And it does nothing for the client: the CLI would still have no
way to obtain a credential.

### A new proto field for provider advertisement

Add a dedicated field or message to `EnvironmentGet` describing the provider, rather than encoding it
in `auth_url`.

*Rejected because:* the scheme registry exists to dispatch on exactly this string, and `auth_url` is
already documented as stored verbatim and interpreted by the client. A new field is also worse on
compatibility: proto3 makes an old client ignore an unknown field silently, so it would report "no
authentication configured" — the confusing failure of issue #161 all over again — where an unknown
scheme produces an error naming the scheme and listing the ones the client knows.

## Prior Art

- **`gh`, and the device grant as the headless default.** GitHub's CLI logs in with the device
  authorization grant, printing a code to enter on another device
  ([gh auth login](https://cli.github.com/manual/gh_auth_login)). It is the closest analogue to
  `lore login --no-browser` and the reason this proposal treats the device grant as the headless path
  rather than as an exotic option.
- **kubectl and OpenID Connect.** Kubernetes verifies provider-issued ID tokens directly in the API
  server, configured with an issuer URL and a client id and nothing provider-specific
  ([Kubernetes authentication reference](https://kubernetes.io/docs/reference/access-authn-authz/authentication/)),
  and pushes the flows out to the client. That is the same split this proposal makes, at a much larger
  scale, and it is the strongest evidence that direct verification does not couple a server to
  providers. Worth avoiding: Kubernetes has to bolt group and username claim mapping on top, and the
  configuration surface that grew around it is what this proposal keeps out of scope until there is a
  design for it.
- **Git credential helpers.** Git owns no authentication code and delegates to helpers
  ([gitcredentials](https://git-scm.com/docs/gitcredentials)). Lore's scheme registry is the same idea
  arriving at the same place — a dispatch point rather than a policy — which is why adding a scheme is
  the whole of the client-side change here.
- **Dex and `oauth2-proxy`.** [Dex](https://dexidp.io/) brokers upstream identity into its own tokens;
  [oauth2-proxy](https://oauth2-proxy.github.io/oauth2-proxy/) terminates authentication in front of an
  HTTP application. Both are the shapes this proposal declines, and both are the shapes it composes
  with: Dex in front of a Lore server is simply the configured issuer.
- **PocketID as the first validated provider.** [PocketID](https://github.com/pocket-id/pocket-id) is
  a small self-hosted provider aimed at exactly this deployment, and it is the one this work validates
  against end to end, on the grounds that a provider a self-hoster would actually run is a better
  conformance test than one from a large cloud provider.

## Unresolved Questions

- Is `jsonwebtoken`'s 60-second default clock leeway the right tolerance for provider-issued tokens,
  or should the OIDC path set it explicitly?
- Is `authorize_all_repositories` the right name and the right shape, or should the mode be an enum
  from the start so the per-repository follow-up extends a setting instead of replacing one?
- Should a single server be able to trust more than one issuer, and if so, does anything in this design
  need to change now to keep that from being a breaking addition later?
- Should repository delete under `authorize_all_repositories` follow the grant — any authenticated
  identity may delete any repository, consistent with every other operation — or keep the
  creator-ownership check it currently falls back to? The grant's own logic argues for the first: a
  mode that says "every repository, every authenticated identity" and then makes delete the one
  exception is an asymmetry an operator has to learn by hitting it. Against that, delete is the one
  irreversible operation here, and a coarse mode staying narrow at exactly that point is defensible.
  What is not defensible is the status quo's provenance — the current behavior is what a scheme check
  happened to produce, not what anybody chose.
- What should a CLI login do when the credential store's keychain blocks on a user prompt? On macOS the
  keychain item's access control binds to the binary that created it, so a rebuilt or reinstalled
  `lore` faces an authorization prompt on the next read, and `get_secret_from_store`
  (`lore-credential/src/token_store.rs`) waits on it with no timeout — its own comment says "a locked
  keychain blocks until the user answers a prompt". None of this is new or caused by this proposal:
  it is how the store has always behaved, for `ucs-auth` tokens too. It belongs here because OIDC
  login is the first flow that puts a store read in front of ordinary self-hosted users, on the one
  path where an indefinite wait is indistinguishable from a hung login. The directions are a bounded,
  prompt-aware read that fails with a message naming the keychain, or documenting `LORE_AUTH_STORE`
  as the escape hatch, or both; deciding belongs with the maintainers rather than in this LEP's
  implementation.
- Should `login::with_token` accept a provider-issued token? Its `token_type = "lore"` branch derives
  the recipient domains from the token's own claims, which for an ID token are a client id and an
  issuer URL, so the recipient guard refuses it and there is no non-interactive way to hand a token to
  the CLI under OIDC. That is a defensible default — `exchange_external_token` is `NotSupported` by
  design, and interactive login is the flow this proposal specifies — but it means an OIDC deployment
  has no headless credential path at all, which is what
  [issue #59](https://github.com/EpicGames/lore/issues/59) asks for. Whether the answer is making the
  implementation-supplied domains authoritative on this path too, as they now are at login and at
  exchange, or the client credentials grant issue #59 points at, is the question; the two are not the
  same door.
- Should `resource` become mandatory for a deployment sharing an issuer with another once enough
  providers support it? The operator guide recommends it wherever the provider allows, and a
  distinct `client_id` per deployment is the baseline where it does not, but neither is enforced —
  and the server cannot detect the condition, since it does not know about its siblings.
