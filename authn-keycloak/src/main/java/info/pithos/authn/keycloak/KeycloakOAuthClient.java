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

package info.pithos.authn.keycloak;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.quarkus.oidc.common.runtime.OidcConstants;
import info.pithos.authn.AbstractOAuthClient;
import info.pithos.authn.AuthNOperation;
import info.pithos.authn.model.TokenIntrospection;
import info.pithos.authn.model.TokenResponse;
import info.pithos.authn.model.TokenType;
import info.pithos.authn.model.UserInfo;
import info.pithos.runtime.core.context.ApplicationContext;
import info.pithos.runtime.core.context.ErrorCode;
import info.pithos.runtime.core.context.ServiceException;
import info.pithos.runtime.model.config.Config.Credentials;
import info.pithos.runtime.model.config.Config.KeycloakOAuthConfigs;
import info.pithos.runtime.model.protocol.Context.RequestContext;
import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.representations.AccessTokenResponse;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

public class KeycloakOAuthClient extends AbstractOAuthClient {

    private static final String PATH_TOKEN = "token";
    private static final String PATH_INTROSPECT = "introspect";
    private static final String PATH_USERINFO = "userinfo";
    private static final String PATH_REVOKE = "revoke";

    private final KeycloakOAuthConfigs configs;
    private volatile Keycloak keycloak;
    private volatile HttpClient httpClient;
    private volatile Credentials resolvedCredentials;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public KeycloakOAuthClient(ApplicationContext context) {
        super(context);
        this.configs = context.getSystemContext().getConfigMap().getKeycloakOAuthConfigs();
    }

    @Override protected String componentProvider() { return "keycloak"; }
    @Override protected String componentId() { return configs.getRealm(); }

    @Override
    public CompletableFuture<Boolean> start(long timeout, TimeUnit unit) {
        return submitAsync(() -> {
            resolvedCredentials = configs.getResolveCredential().getVaultPath().isBlank()
                ? resolvedCredentials
                : context.getSystemContext().resolve(configs.getResolveCredential());
            keycloak = KeycloakBuilder.builder()
                .serverUrl(configs.getServerUrl())
                .realm(configs.getRealm())
                .clientId(resolvedCredentials.getClientId())
                .clientSecret(resolvedCredentials.getClientSecret())
                .grantType(OAuth2Constants.CLIENT_CREDENTIALS)
                .build();
            int timeoutMs = configs.getTimeoutMs() > 0 ? configs.getTimeoutMs() : 5000;
            httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofMillis(timeoutMs))
                .build();
            return true;
        });
    }

    @Override
    public CompletableFuture<Boolean> shutdown(long timeout, TimeUnit unit) {
        return submitAsync(() -> {
            Keycloak kc = keycloak;
            keycloak = null;
            httpClient = null;
            if (kc != null) kc.close();
            return true;
        });
    }

    @Override
    public CompletableFuture<TokenResponse> clientCredentialsGrant(RequestContext requestContext, List<String> scopes) {
        long startMs = System.currentTimeMillis();
        return submitAsync(() -> {
            AccessTokenResponse resp = keycloak().tokenManager().grantToken();
            return new TokenResponse(
                resp.getToken(),
                resp.getRefreshToken(),
                resp.getExpiresIn(),
                resp.getTokenType(),
                resp.getScope()
            );
        }).whenComplete((v, ex) -> recordOp(requestContext, AuthNOperation.CLIENT_CREDENTIALS_GRANT, startMs, ex));
    }

    @Override
    public CompletableFuture<TokenResponse> login(RequestContext requestContext, String username, String password) {
        long startMs = System.currentTimeMillis();
        return submitAsync(() -> {
            String body = buildForm(
                OidcConstants.GRANT_TYPE, OAuth2Constants.PASSWORD,
                "username", username,
                "password", password,
                OidcConstants.CLIENT_ID, resolvedCredentials.getClientId(),
                OidcConstants.CLIENT_SECRET, resolvedCredentials.getClientSecret()
            );
            JsonNode json = postToTokenEndpoint(body);
            return parseTokenResponse(json);
        }).whenComplete((v, ex) -> recordOp(requestContext, AuthNOperation.LOGIN, startMs, ex));
    }

    @Override
    public CompletableFuture<TokenResponse> loginWithIdToken(RequestContext requestContext, String idToken) {
        long startMs = System.currentTimeMillis();
        return submitAsync(() -> {
            String body = buildForm(
                OidcConstants.GRANT_TYPE, "urn:ietf:params:oauth:grant-type:token-exchange",
                "subject_token", idToken,
                "subject_token_type", "urn:ietf:params:oauth:token-type:id_token",
                "subject_issuer", configs.getIdpAlias(),
                OidcConstants.CLIENT_ID, resolvedCredentials.getClientId(),
                OidcConstants.CLIENT_SECRET, resolvedCredentials.getClientSecret()
            );
            JsonNode json = postToTokenEndpoint(body);
            if (json.has("error")) {
                throw new ServiceException(ErrorCode.UNAUTHORIZED,
                    "token exchange failed: " + json.path("error_description").asText(json.path("error").asText()));
            }
            return parseTokenResponse(json);
        }).whenComplete((v, ex) -> recordOp(requestContext, AuthNOperation.LOGIN_ID_TOKEN, startMs, ex));
    }

    @Override
    public CompletableFuture<TokenResponse> refreshToken(RequestContext requestContext, String refreshToken) {
        long startMs = System.currentTimeMillis();
        return submitAsync(() -> {
            String body = buildForm(
                OidcConstants.GRANT_TYPE, OidcConstants.REFRESH_TOKEN_GRANT,
                OidcConstants.REFRESH_TOKEN_GRANT, refreshToken,
                OidcConstants.CLIENT_ID, resolvedCredentials.getClientId(),
                OidcConstants.CLIENT_SECRET, resolvedCredentials.getClientSecret()
            );
            JsonNode json = postToTokenEndpoint(body);
            return parseTokenResponse(json);
        }).whenComplete((v, ex) -> recordOp(requestContext, AuthNOperation.REFRESH_TOKEN, startMs, ex));
    }

    @Override
    public CompletableFuture<Void> revokeToken(RequestContext requestContext, String token, TokenType tokenType) {
        long startMs = System.currentTimeMillis();
        return submitAsync(() -> {
            String typeHint = tokenType == TokenType.REFRESH ? "refresh_token" : "access_token";
            String body = buildForm(
                "token", token,
                "token_type_hint", typeHint,
                OidcConstants.CLIENT_ID, resolvedCredentials.getClientId(),
                OidcConstants.CLIENT_SECRET, resolvedCredentials.getClientSecret()
            );
            String url = oidcBase() + "/" + PATH_REVOKE;
            send(HttpRequest.newBuilder()
                .uri(URI.create(url))
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
            String body = buildForm(
                "token", token,
                OidcConstants.CLIENT_ID, resolvedCredentials.getClientId(),
                OidcConstants.CLIENT_SECRET, resolvedCredentials.getClientSecret()
            );
            String url = oidcBase() + "/" + PATH_INTROSPECT;
            HttpResponse<String> response = send(HttpRequest.newBuilder()
                .uri(URI.create(url))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build());
            JsonNode json = objectMapper.readTree(response.body());
            List<String> roles = new ArrayList<>();
            JsonNode rolesNode = json.path("realm_access").path("roles");
            if (rolesNode.isArray()) {
                rolesNode.forEach(r -> roles.add(r.asText()));
            }
            return new TokenIntrospection(
                json.path(OidcConstants.INTROSPECTION_TOKEN_ACTIVE).asBoolean(false),
                json.path(OidcConstants.INTROSPECTION_TOKEN_SUB).asText(null),
                null,
                json.path(OidcConstants.INTROSPECTION_TOKEN_CLIENT_ID).asText(null),
                json.path(OidcConstants.INTROSPECTION_TOKEN_USERNAME).asText(null),
                json.path(OidcConstants.INTROSPECTION_TOKEN_EXP).asLong(0),
                json.path(OidcConstants.INTROSPECTION_TOKEN_IAT).asLong(0),
                json.path(OidcConstants.TOKEN_SCOPE).asText(null),
                List.copyOf(roles)
            );
        }).whenComplete((v, ex) -> recordOp(requestContext, AuthNOperation.INTROSPECT_TOKEN, startMs, ex));
    }

    @Override
    public CompletableFuture<UserInfo> getUserInfo(RequestContext requestContext, String accessToken) {
        long startMs = System.currentTimeMillis();
        return submitAsync(() -> {
            String url = oidcBase() + "/" + PATH_USERINFO;
            HttpResponse<String> response = send(HttpRequest.newBuilder()
                .uri(URI.create(url))
                .header("Authorization", OidcConstants.BEARER_SCHEME + " " + accessToken)
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
                json.path("preferred_username").asText(null),
                List.copyOf(groups)
            );
        }).whenComplete((v, ex) -> recordOp(requestContext, AuthNOperation.GET_USER_INFO, startMs, ex));
    }

    // --- Helpers ---

    private String oidcBase() {
        return configs.getServerUrl() + "/realms/" + configs.getRealm() + "/protocol/openid-connect";
    }

    private JsonNode postToTokenEndpoint(String formBody) throws Exception {
        String url = oidcBase() + "/" + PATH_TOKEN;
        HttpResponse<String> response = send(HttpRequest.newBuilder()
            .uri(URI.create(url))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .POST(HttpRequest.BodyPublishers.ofString(formBody))
            .build());
        return objectMapper.readTree(response.body());
    }

    private HttpResponse<String> send(HttpRequest request) throws Exception {
        return httpClient().send(request, HttpResponse.BodyHandlers.ofString());
    }

    private TokenResponse parseTokenResponse(JsonNode json) {
        return new TokenResponse(
            json.path(OidcConstants.ACCESS_TOKEN_VALUE).asText(null),
            json.path(OidcConstants.REFRESH_TOKEN_VALUE).asText(null),
            json.path(OidcConstants.EXPIRES_IN).asLong(0),
            json.path("token_type").asText(null),
            json.path(OidcConstants.TOKEN_SCOPE).asText(null)
        );
    }

    private String buildForm(String... pairs) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < pairs.length; i += 2) {
            if (i > 0) sb.append('&');
            sb.append(URLEncoder.encode(pairs[i], StandardCharsets.UTF_8))
              .append('=')
              .append(URLEncoder.encode(pairs[i + 1] != null ? pairs[i + 1] : "", StandardCharsets.UTF_8));
        }
        return sb.toString();
    }

    private Keycloak keycloak() {
        Keycloak kc = keycloak;
        if (kc == null)
            throw new IllegalStateException(getClass().getSimpleName() + " not started — call start() first");
        return kc;
    }

    private HttpClient httpClient() {
        HttpClient hc = httpClient;
        if (hc == null)
            throw new IllegalStateException(getClass().getSimpleName() + " not started — call start() first");
        return hc;
    }
}
