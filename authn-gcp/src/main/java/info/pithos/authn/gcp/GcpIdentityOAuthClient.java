/*
 * Copyright 2026 Pithos
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package info.pithos.authn.gcp;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.auth.oauth2.AccessToken;
import com.google.auth.oauth2.GoogleCredentials;
import com.google.auth.oauth2.ImpersonatedCredentials;
import info.pithos.authn.AbstractOAuthClient;
import info.pithos.authn.AuthNOperation;
import info.pithos.authn.model.TokenIntrospection;
import info.pithos.authn.model.TokenResponse;
import info.pithos.authn.model.TokenType;
import info.pithos.authn.model.UserInfo;
import info.pithos.runtime.core.context.ApplicationContext;
import info.pithos.runtime.core.context.ErrorCode;
import info.pithos.runtime.core.context.ServiceException;
import info.pithos.runtime.model.config.Config.GcpIdentityOAuthConfigs;
import info.pithos.runtime.model.protocol.Context.RequestContext;

import java.math.BigInteger;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

public class GcpIdentityOAuthClient extends AbstractOAuthClient {

    private static final String TOKEN_INFO_URL = "https://www.googleapis.com/oauth2/v3/tokeninfo";
    private static final String USER_INFO_URL = "https://www.googleapis.com/oauth2/v3/userinfo";
    private static final String REVOKE_URL = "https://oauth2.googleapis.com/revoke";
    private static final String FIREBASE_JWKS_URL =
        "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com";
    private static final String FIREBASE_ISSUER_PREFIX = "https://securetoken.google.com/";

    private final GcpIdentityOAuthConfigs configs;
    private volatile GoogleCredentials credentials;
    private volatile HttpClient httpClient;
    private volatile Map<String, PublicKey> firebasePublicKeys = Map.of();
    private final ObjectMapper objectMapper = new ObjectMapper();

    public GcpIdentityOAuthClient(ApplicationContext context) {
        super(context);
        this.configs = context.getSystemContext().getConfigMap().getGcpIdentityOAuthConfigs();
    }

    @Override protected String componentProvider() { return "gcp-identity"; }
    @Override protected String componentId() { return configs.getProjectId(); }

    @Override
    public CompletableFuture<Boolean> start(long timeout, TimeUnit unit) {
        return submitAsync(() -> {
            List<String> scopes = configs.getDefaultScopesList();
            GoogleCredentials base = GoogleCredentials.getApplicationDefault();
            if (!configs.getServiceAccountEmail().isEmpty()) {
                base = ImpersonatedCredentials.create(
                    base,
                    configs.getServiceAccountEmail(),
                    null,
                    scopes.isEmpty() ? List.of("https://www.googleapis.com/auth/cloud-platform") : scopes,
                    300
                );
            } else if (!scopes.isEmpty()) {
                base = base.createScoped(scopes);
            }
            credentials = base;
            credentials.refresh();
            httpClient = HttpClient.newBuilder().build();
            return true;
        });
    }

    @Override
    public CompletableFuture<Boolean> shutdown(long timeout, TimeUnit unit) {
        return submitAsync(() -> {
            credentials = null;
            httpClient = null;
            firebasePublicKeys = Map.of();
            return true;
        });
    }

    @Override
    public CompletableFuture<TokenResponse> login(RequestContext requestContext, String username, String password) {
        // GCP Identity Platform does not support Resource Owner Password Credentials grant.
        // Delegate to clientCredentialsGrant using the currently loaded service-account credentials.
        return clientCredentialsGrant(requestContext, List.of());
    }

    @Override
    public CompletableFuture<TokenResponse> loginWithIdToken(RequestContext requestContext, String idToken) {
        long startMs = System.currentTimeMillis();
        return submitAsync(() -> {
            JsonNode payload = decodeJwtPayload(idToken);
            if (isFirebaseToken(payload)) {
                payload = verifyFirebaseToken(idToken);
                long exp = payload.path("exp").asLong(0);
                long expiresIn = Math.max(0, exp - System.currentTimeMillis() / 1000);
                return new TokenResponse(idToken, null, expiresIn, "Bearer", "");
            }
            // Google ID token path — validate via tokeninfo
            String url = TOKEN_INFO_URL + "?id_token=" + URLEncoder.encode(idToken, StandardCharsets.UTF_8);
            HttpResponse<String> response = send(HttpRequest.newBuilder()
                .uri(URI.create(url))
                .GET()
                .build());
            JsonNode json = objectMapper.readTree(response.body());
            if (json.has("error")) {
                throw new ServiceException(ErrorCode.UNAUTHORIZED,
                    "invalid or expired id_token: " + json.path("error_description").asText(json.path("error").asText()));
            }
            long exp = json.path("exp").asLong(0);
            long expiresIn = Math.max(0, exp - System.currentTimeMillis() / 1000);
            return new TokenResponse(idToken, null, expiresIn, "Bearer", json.path("scope").asText(""));
        }).whenComplete((v, ex) -> recordOp(requestContext, AuthNOperation.LOGIN_ID_TOKEN, startMs, ex));
    }

    @Override
    public CompletableFuture<TokenResponse> clientCredentialsGrant(RequestContext requestContext, List<String> scopes) {
        long startMs = System.currentTimeMillis();
        return submitAsync(() -> {
            GoogleCredentials creds = credentials();
            if (!scopes.isEmpty()) {
                creds = creds.createScoped(scopes);
            }
            creds.refreshIfExpired();
            return toTokenResponse(creds);
        }).whenComplete((v, ex) -> recordOp(requestContext, AuthNOperation.CLIENT_CREDENTIALS_GRANT, startMs, ex));
    }

    @Override
    public CompletableFuture<TokenResponse> refreshToken(RequestContext requestContext, String refreshToken) {
        // GCP service accounts use short-lived tokens refreshed via the credential directly;
        // the provided refreshToken is ignored in favour of the current credential's refresh flow.
        long startMs = System.currentTimeMillis();
        return submitAsync(() -> {
            GoogleCredentials creds = credentials();
            creds.refresh();
            return toTokenResponse(creds);
        }).whenComplete((v, ex) -> recordOp(requestContext, AuthNOperation.REFRESH_TOKEN, startMs, ex));
    }

    @Override
    public CompletableFuture<Void> revokeToken(RequestContext requestContext, String token, TokenType tokenType) {
        long startMs = System.currentTimeMillis();
        return submitAsync(() -> {
            String body = "token=" + URLEncoder.encode(token, StandardCharsets.UTF_8);
            send(HttpRequest.newBuilder()
                .uri(URI.create(REVOKE_URL))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build());
            return (Void) null;
        }).whenComplete((v, ex) -> recordOp(requestContext, AuthNOperation.REVOKE_TOKEN, startMs, ex));
    }

    @Override
    public CompletableFuture<TokenIntrospection> introspectToken(RequestContext requestContext, String token) {
        long startMs = System.currentTimeMillis();
        return submitAsync(() -> {
            JsonNode payload = decodeJwtPayload(token);
            if (isFirebaseToken(payload)) {
                payload = verifyFirebaseToken(token);
                return new TokenIntrospection(
                    true,
                    payload.path("sub").asText(null),
                    null,
                    null,
                    payload.path("email").asText(null),
                    payload.path("exp").asLong(0),
                    payload.path("iat").asLong(0),
                    null,
                    List.of()
                );
            }
            // Google ID tokens (iss: accounts.google.com) use ?id_token=; service-account
            // access tokens use ?access_token=.
            String param = "https://accounts.google.com".equals(payload.path("iss").asText(""))
                ? "id_token" : "access_token";
            String url = TOKEN_INFO_URL + "?" + param + "=" + URLEncoder.encode(token, StandardCharsets.UTF_8);
            HttpResponse<String> response = send(HttpRequest.newBuilder()
                .uri(URI.create(url))
                .GET()
                .build());
            JsonNode json = objectMapper.readTree(response.body());
            boolean active = !json.has("error");
            return new TokenIntrospection(
                active,
                json.path("sub").asText(null),
                null,
                json.path("azp").asText(null),
                json.path("email").asText(null),
                json.path("exp").asLong(0),
                json.path("iat").asLong(0),
                json.path("scope").asText(null),
                List.of()
            );
        }).whenComplete((v, ex) -> recordOp(requestContext, AuthNOperation.INTROSPECT_TOKEN, startMs, ex));
    }

    @Override
    public CompletableFuture<UserInfo> getUserInfo(RequestContext requestContext, String accessToken) {
        long startMs = System.currentTimeMillis();
        return submitAsync(() -> {
            HttpResponse<String> response = send(HttpRequest.newBuilder()
                .uri(URI.create(USER_INFO_URL))
                .header("Authorization", "Bearer " + accessToken)
                .GET()
                .build());
            JsonNode json = objectMapper.readTree(response.body());
            List<String> groups = new ArrayList<>();
            JsonNode groupsNode = json.path("groups");
            if (groupsNode.isArray()) {
                groupsNode.forEach(g -> groups.add(g.asText()));
            }
            return new UserInfo(
                json.path("sub").asText(null),
                json.path("name").asText(null),
                json.path("email").asText(null),
                json.path("email").asText(null),
                List.copyOf(groups)
            );
        }).whenComplete((v, ex) -> recordOp(requestContext, AuthNOperation.GET_USER_INFO, startMs, ex));
    }

    // --- Firebase helpers ---

    private boolean isFirebaseToken(JsonNode payload) {
        String iss = payload.path("iss").asText("");
        return iss.startsWith(FIREBASE_ISSUER_PREFIX);
    }

    // Validates a Firebase ID token: verifies RS256 signature via JWKS then checks iss/aud/exp.
    // Returns the decoded payload on success; throws UNAUTHORIZED on any failure.
    private JsonNode verifyFirebaseToken(String idToken) throws Exception {
        String projectId = configs.getProjectId();
        if (projectId.isBlank()) {
            throw new ServiceException(ErrorCode.BAD_REQUEST,
                "firebaseProjectId must be configured to validate Firebase ID tokens");
        }

        String[] parts = idToken.split("\\.");
        if (parts.length != 3) {
            throw new ServiceException(ErrorCode.UNAUTHORIZED, "malformed Firebase ID token");
        }

        JsonNode header = objectMapper.readTree(Base64.getUrlDecoder().decode(padBase64(parts[0])));
        JsonNode payload = objectMapper.readTree(Base64.getUrlDecoder().decode(padBase64(parts[1])));

        String kid = header.path("kid").asText(null);
        if (kid == null) {
            throw new ServiceException(ErrorCode.UNAUTHORIZED, "Firebase token missing kid");
        }

        PublicKey publicKey = resolveFirebasePublicKey(kid);

        byte[] signingInput = (parts[0] + "." + parts[1]).getBytes(StandardCharsets.UTF_8);
        byte[] signature = Base64.getUrlDecoder().decode(padBase64(parts[2]));
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(publicKey);
        sig.update(signingInput);
        if (!sig.verify(signature)) {
            throw new ServiceException(ErrorCode.UNAUTHORIZED, "Firebase token signature invalid");
        }

        long now = System.currentTimeMillis() / 1000;
        if (payload.path("exp").asLong(0) < now) {
            throw new ServiceException(ErrorCode.UNAUTHORIZED, "Firebase token expired");
        }
        String expectedIss = FIREBASE_ISSUER_PREFIX + projectId;
        if (!expectedIss.equals(payload.path("iss").asText(""))) {
            throw new ServiceException(ErrorCode.UNAUTHORIZED, "Firebase token issuer mismatch");
        }
        if (!projectId.equals(payload.path("aud").asText(""))) {
            throw new ServiceException(ErrorCode.UNAUTHORIZED, "Firebase token audience mismatch");
        }

        return payload;
    }

    private PublicKey resolveFirebasePublicKey(String kid) throws Exception {
        PublicKey key = firebasePublicKeys.get(kid);
        if (key != null) return key;
        refreshFirebasePublicKeys();
        key = firebasePublicKeys.get(kid);
        if (key == null) {
            throw new ServiceException(ErrorCode.UNAUTHORIZED, "unknown Firebase signing key: " + kid);
        }
        return key;
    }

    private void refreshFirebasePublicKeys() throws Exception {
        HttpResponse<String> response = send(HttpRequest.newBuilder()
            .uri(URI.create(FIREBASE_JWKS_URL))
            .GET()
            .build());
        JsonNode json = objectMapper.readTree(response.body());
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        Map<String, PublicKey> keys = new HashMap<>();
        for (JsonNode jwk : json.path("keys")) {
            BigInteger modulus = new BigInteger(1, Base64.getUrlDecoder().decode(padBase64(jwk.path("n").asText())));
            BigInteger exponent = new BigInteger(1, Base64.getUrlDecoder().decode(padBase64(jwk.path("e").asText())));
            keys.put(jwk.path("kid").asText(), keyFactory.generatePublic(new RSAPublicKeySpec(modulus, exponent)));
        }
        firebasePublicKeys = Map.copyOf(keys);
    }

    private static String padBase64(String s) {
        return switch (s.length() % 4) {
            case 2 -> s + "==";
            case 3 -> s + "=";
            default -> s;
        };
    }

    private JsonNode decodeJwtPayload(String token) throws Exception {
        String[] parts = token.split("\\.");
        if (parts.length < 2) return objectMapper.createObjectNode();
        return objectMapper.readTree(Base64.getUrlDecoder().decode(padBase64(parts[1])));
    }

    // --- GCP helpers ---

    private TokenResponse toTokenResponse(GoogleCredentials creds) {
        AccessToken token = creds.getAccessToken();
        long expiresIn = token.getExpirationTime() != null
            ? Math.max(0, (token.getExpirationTime().getTime() - System.currentTimeMillis()) / 1000)
            : -1;
        return new TokenResponse(
            token.getTokenValue(),
            null,
            expiresIn,
            "Bearer",
            String.join(" ", configs.getDefaultScopesList())
        );
    }

    private HttpResponse<String> send(HttpRequest request) throws Exception {
        return httpClient().send(request, HttpResponse.BodyHandlers.ofString());
    }

    private GoogleCredentials credentials() {
        GoogleCredentials c = credentials;
        if (c == null)
            throw new IllegalStateException(getClass().getSimpleName() + " not started — call start() first");
        return c;
    }

    private HttpClient httpClient() {
        HttpClient hc = httpClient;
        if (hc == null)
            throw new IllegalStateException(getClass().getSimpleName() + " not started — call start() first");
        return hc;
    }
}
