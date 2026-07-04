# Pithos Auth

OAuth 2.0 / OIDC client implementations for the Pithos agent platform. Each module provides an async, Guice-injectable client for a specific identity provider.

## Modules

### auth-model
Protobuf-generated model types and gRPC service stubs for the auth API. Java package: `info.pithos.auth.model`

Proto source: `auth-model/src/main/proto/Auth.proto`

| Message | Fields |
|---|---|
| `LoginRequest` | `username`, `password`, `scopes` (repeated), `idToken` |
| `LoginResponse` | `accessToken`, `refreshToken`, `expiresIn`, `tokenType`, `scope` |

gRPC service: `AuthService` with a single `Login(LoginRequest) returns (LoginResponse)` RPC. The generated `AuthServiceGrpc` stub is the base class used by `service-container` to expose this operation over gRPC.

Build note: this module runs both `compile` and `compile-custom` protobuf plugin goals — the latter invokes `protoc-gen-grpc-java` to generate the gRPC service stubs.

### auth-api
Interface and abstract base for OAuth operations. Java package: `info.pithos.auth`

| Type | Description |
|---|---|
| `OAuthClient` | Interface extending `ServiceLifeCycle` — token acquisition, refresh, revocation, introspection, and user info |
| `AbstractOAuthClient` | Base class providing `submitAsync` via the platform `ForkJoinExecutor` |

Operations:

| Group | Methods |
|---|---|
| Token acquisition | `clientCredentialsGrant`, `login`, `loginWithIdToken` |
| Token lifecycle | `refreshToken`, `revokeToken` |
| Token validation | `introspectToken` |
| Identity | `getUserInfo` |

Model types (`info.pithos.auth.model`):

| Type | Fields |
|---|---|
| `TokenResponse` | `accessToken`, `refreshToken`, `expiresIn`, `tokenType`, `scope` |
| `TokenIntrospection` | `active`, `subject`, `enterpriseId`, `clientId`, `username`, `expiresAt`, `issuedAt`, `scope`, `roles` |
| `UserInfo` | `subject`, `name`, `email`, `preferredUsername`, `groups` |
| `TokenType` | Enum: `ACCESS`, `REFRESH` |

### auth-keycloak
Keycloak implementation of `OAuthClient`. Java package: `info.pithos.auth.keycloak`

Uses `keycloak-admin-client` (`KeycloakBuilder` + `TokenManager.grantToken()`) for client-credentials token acquisition and `quarkus-oidc-client` (`OidcConstants`) for standard OIDC endpoint paths. All other endpoints (`/token`, `/introspect`, `/userinfo`, `/revoke`) are called via Java's built-in `HttpClient` using the OIDC standard paths provided by `quarkus-oidc-client`.

Config proto: `KeycloakOAuthConfigs` (`serverUrl`, `realm`, `clientId`, `clientSecret`, `timeoutMs`, `idpAlias`)

`introspectToken` returns `null` for `enterpriseId` — OAuth tokens do not carry enterprise-scoped identity; `enterpriseId` is populated instead from the `X-Enterprise-Id` request header by the service container layer.

`login` uses the Resource Owner Password Credentials grant (`grant_type=password`) against the Keycloak token endpoint. `loginWithIdToken` uses the RFC 8693 token-exchange grant (`grant_type=urn:ietf:params:oauth:grant-type:token-exchange`, `subject_token_type=urn:ietf:params:oauth:token-type:id_token`) — it exchanges a Google (or other external) ID token for a Keycloak access + refresh token pair. The `idpAlias` config field must match the identity provider alias configured in the Keycloak realm. `refreshToken` calls the token endpoint directly with the provided refresh token. `revokeToken` accepts a `TokenType` hint (`ACCESS` or `REFRESH`) and posts to the revocation endpoint. `introspectToken` returns realm roles from `realm_access.roles`.

### auth-gcp
GCP Identity implementation of `OAuthClient`. Java package: `info.pithos.auth.gcp`

Supports three distinct identity flows, all sharing the same `GcpIdentityOAuthModule` / `GcpIdentityOAuthClient`:

#### Flow 1 — GCP service account (M2M / headless)

`clientCredentialsGrant` acquires a service-account access token via Application Default Credentials (`GoogleCredentials.getApplicationDefault()`). When `serviceAccountEmail` is set the client uses `ImpersonatedCredentials` to impersonate that account; otherwise ADC scoped to `defaultScopes` is used directly. `login` delegates to `clientCredentialsGrant` — GCP does not support the ROPC grant for service accounts. `refreshToken` forces a credential refresh; GCP service accounts do not use long-lived refresh tokens.

#### Flow 2 — Google Identity (direct user login)

`loginWithIdToken` accepts a Google-issued ID token (`iss: https://accounts.google.com`). Validates via `https://www.googleapis.com/oauth2/v3/tokeninfo?id_token=` — no additional config required. Returns the ID token itself as the `accessToken` with the remaining TTL as `expiresIn`; no refresh token is issued (the client re-authenticates with Google on expiry). `introspectToken` routes tokens with `iss: accounts.google.com` back through `tokeninfo?id_token=`.

How to obtain a Google ID token:
- Developer machine: `gcloud auth print-identity-token`
- CI / service account: `gcloud auth print-identity-token --impersonate-service-account=<sa>@<project>.iam.gserviceaccount.com`
- Browser / SPA: Google OAuth2 Playground (`developers.google.com/oauthplayground`) — select `openid email profile` scope

#### Flow 3 — Firebase with Google Identity

`loginWithIdToken` accepts a Firebase-issued ID token (`iss: https://securetoken.google.com/{projectId}`). Validates by:
1. Fetching Firebase signing keys from `https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com` (keys are cached in memory; refreshed automatically when a new `kid` is encountered)
2. Verifying the RS256 signature using Java's built-in `Signature` / `KeyFactory`
3. Checking `iss` = `https://securetoken.google.com/{projectId}`, `aud` = `{projectId}`, and `exp`

Returns the Firebase ID token as the `accessToken`; no refresh token. `introspectToken` routes Firebase tokens (`iss` starts with `securetoken.google.com/`) through the same JWKS verification path.

`projectId` must be set in `GcpIdentityOAuthConfigs` and must match the Firebase / GCP project ID (they are the same value — Firebase projects are GCP projects). Any Google account is accepted without pre-registration; Firebase auto-provisions users on first sign-in.

How to obtain a Firebase ID token:
- Exchange a Google ID token via `POST https://identitytoolkit.googleapis.com/v1/accounts:signInWithIdp?key={firebaseApiKey}` with `providerId=google.com` and `returnSecureToken=true` (requires Google sign-in provider enabled in Firebase Auth)

#### `introspectToken` routing summary

| Token issuer (`iss`) | Validation path |
|---|---|
| `https://accounts.google.com` | `tokeninfo?id_token=` |
| `https://securetoken.google.com/{projectId}` | Firebase JWKS (RS256 verify) |
| other (GCP service-account access token) | `tokeninfo?access_token=` |

`getUserInfo` calls the Google `userinfo` endpoint for all token types.

Config proto: `GcpIdentityOAuthConfigs` (`projectId`, `serviceAccountEmail`, `defaultScopes`)

---

## Metrics

Every `OAuthClient` operation emits infra-tier metrics automatically via `MetricsCommitter`. No caller instrumentation required.

### AuthNOperation

| Enum value | Metric stem |
|---|---|
| `CLIENT_CREDENTIALS_GRANT` | `authn.client.credentials` |
| `LOGIN` | `authn.login` |
| `LOGIN_ID_TOKEN` | `authn.login.idtoken` |
| `REFRESH_TOKEN` | `authn.token.refresh` |
| `REVOKE_TOKEN` | `authn.token.revoke` |
| `INTROSPECT_TOKEN` | `authn.token.introspect` |
| `GET_USER_INFO` | `authn.userinfo` |

`GcpIdentityOAuthClient.login()` delegates to `clientCredentialsGrant()` and is not instrumented separately to avoid double-counting.

### What is emitted per operation

Each operation fires **4 metric events** across two levels:

| Level | `componentId` | Example |
|---|---|---|
| Per tenant | Realm name (Keycloak) or project ID (GCP) | `"pithos-dev"` |
| Provider aggregate | Provider name | `"keycloak"` or `"gcp-identity"` |

At each level:
1. `{op}.latency` — `MetricUnit.MS`
2. `{op}.success` / `{op}.failure` / `{op}.timeout` — `MetricUnit.COUNT`

| Field | Value |
|---|---|
| `componentType` | `AUTH` |
| `componentId` | realm (Keycloak) or projectId (GCP) |
| `componentProvider` | `"keycloak"` or `"gcp-identity"` |
| `RequestContext` | passed through from the caller |

### Example: `introspectToken(rc, token)` via Keycloak (realm `"pithos-dev"`)

| metric | unit | componentId | componentProvider |
|---|---|---|---|
| `authn.token.introspect.latency` | MS | `pithos-dev` | `keycloak` |
| `authn.token.introspect.success` | COUNT | `pithos-dev` | `keycloak` |
| `authn.token.introspect.latency` | MS | `keycloak` | `keycloak` |
| `authn.token.introspect.success` | COUNT | `keycloak` | `keycloak` |

### componentProvider values

| Implementation | `componentProvider` | `componentId` |
|---|---|---|
| `KeycloakOAuthClient` | `"keycloak"` | `configs.getRealm()` |
| `GcpIdentityOAuthClient` | `"gcp-identity"` | `configs.getProjectId()` |

---

## Config.proto

Two messages added to `Config.proto` and registered on `ConfigMap` (fields 17 and 18):

```proto
message KeycloakOAuthConfigs {
  string serverUrl = 1;
  string realm = 2;
  string clientId = 3;
  string clientSecret = 4;
  int32 timeoutMs = 5;
  string idpAlias = 6;
}

message GcpIdentityOAuthConfigs {
  string projectId = 1;
  string serviceAccountEmail = 2;
  repeated string defaultScopes = 3;
}
```

Rebuild `runtime-model` after proto changes to regenerate `KeycloakOAuthConfigs` and `GcpIdentityOAuthConfigs` before compiling auth modules.

---

## Usage

All clients follow the same lifecycle pattern used across the Pithos data layer:

```java
// 1. Create and initialise the Guice module
KeycloakOAuthModule module = new KeycloakOAuthModule(applicationContext);
module.init();

// 2. Create an injector
Injector injector = Guice.createInjector(module);

// 3. Start the client before use
OAuthClient client = injector.getInstance(OAuthClient.class);
client.start(10, TimeUnit.SECONDS).join();

// 4. Use the client

// ── Flow 1: GCP service account (M2M) ────────────────────────────────────────
// Uses ADC; serviceAccountEmail impersonation is optional via config.
TokenResponse saToken = client.clientCredentialsGrant(requestContext, List.of()).join();

// ── Flow 2: Google Identity — direct user login ───────────────────────────────
// Client obtains a Google ID token (OAuth Playground / gcloud / Google Sign-In SDK).
// GcpIdentityOAuthClient validates via tokeninfo; returns the id_token as accessToken.
// KeycloakOAuthClient exchanges it for a Keycloak token pair via RFC 8693 token exchange.
TokenResponse googleUserToken = client.loginWithIdToken(requestContext, googleIdToken).join();

// ── Flow 3: Firebase with Google Identity ─────────────────────────────────────
// Client exchanges a Google ID token for a Firebase ID token via signInWithIdp, then
// passes the Firebase token here. GcpIdentityOAuthClient validates via Firebase JWKS
// (RS256 signature + iss/aud/exp checks). Requires projectId in GcpIdentityOAuthConfigs.
TokenResponse firebaseUserToken = client.loginWithIdToken(requestContext, firebaseIdToken).join();

// ── Subsequent request validation (all flows) ─────────────────────────────────
client.introspectToken(requestContext, googleUserToken.accessToken())
      .thenAccept(info -> System.out.println("active: " + info.active() + ", sub: " + info.subject()));

client.getUserInfo(requestContext, googleUserToken.accessToken())
      .thenAccept(u -> System.out.println("email: " + u.email()));

// ── Keycloak only ─────────────────────────────────────────────────────────────
// Resource Owner Password Credentials grant (not supported by GCP).
TokenResponse userToken = client.login(requestContext, "alice", "secret").join();

// 5. Shut down gracefully
client.shutdown(10, TimeUnit.SECONDS).join();
```

Swap `KeycloakOAuthModule` for `GcpIdentityOAuthModule` to switch identity providers with no changes to call sites.

## Build

Requires JDK 23, Maven 3.9.x, and the `pithos-runtime-core-model` and `pithos-runtime-core-context` SNAPSHOTs installed locally. The `pithos-runtime-core-model` module must be rebuilt after any proto changes to regenerate `KeycloakOAuthConfigs` and `GcpIdentityOAuthConfigs`:

```bash
mvn install -f ../runtime-model/pom.xml
mvn compile          # compile all auth modules (proto codegen runs automatically for auth-model)
mvn install          # install all auth modules to local Maven repository
```

`auth-model` requires `protoc` and `protoc-gen-grpc-java` binaries, which the `protobuf-maven-plugin` downloads automatically on first build via the `os-maven-plugin` classifier.

## Dependencies

| Dependency | Version | Used by |
|---|---|---|
| `protobuf-java` (com.google.protobuf) | 4.34.2 | auth-model |
| `grpc-stub` (io.grpc) | 1.68.1 | auth-model |
| `grpc-protobuf` (io.grpc) | 1.68.1 | auth-model |
| `quarkus-oidc-client` (io.quarkus) | 3.15.1 | auth-keycloak |
| `keycloak-admin-client` (org.keycloak) | 26.0.7 | auth-keycloak |
| `google-auth-library-oauth2-http` | 1.30.0 | auth-gcp |
| `jackson-databind` | 2.18.2 | auth-keycloak, auth-gcp |
| `guice` | 7.0.0 | auth-api, auth-keycloak, auth-gcp |
| `slf4j-api` | 2.0.16 | auth-api |
