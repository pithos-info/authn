package info.pithos.auth.gcp;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.auth.oauth2.AccessToken;
import com.google.auth.oauth2.GoogleCredentials;
import com.google.auth.oauth2.ImpersonatedCredentials;
import info.pithos.auth.AbstractOAuthClient;
import info.pithos.auth.model.TokenIntrospection;
import info.pithos.auth.model.TokenResponse;
import info.pithos.auth.model.TokenType;
import info.pithos.auth.model.UserInfo;
import info.pithos.runtime.core.context.ApplicationContext;
import info.pithos.runtime.model.config.Config.GcpIdentityOAuthConfigs;
import info.pithos.runtime.model.protocol.http.Context.RequestContext;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

public class GcpIdentityOAuthClient extends AbstractOAuthClient {

    private static final String TOKEN_INFO_URL = "https://www.googleapis.com/oauth2/v3/tokeninfo";
    private static final String USER_INFO_URL = "https://www.googleapis.com/oauth2/v3/userinfo";
    private static final String REVOKE_URL = "https://oauth2.googleapis.com/revoke";

    private final GcpIdentityOAuthConfigs configs;
    private volatile GoogleCredentials credentials;
    private volatile HttpClient httpClient;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public GcpIdentityOAuthClient(ApplicationContext context) {
        super(context);
        this.configs = context.getSystemContext().getConfigMap().getGcpIdentityOAuthConfigs();
    }

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
            return true;
        });
    }

    @Override
    public CompletableFuture<TokenResponse> clientCredentialsGrant(RequestContext requestContext, List<String> scopes) {
        return submitAsync(() -> {
            GoogleCredentials creds = credentials();
            if (!scopes.isEmpty()) {
                creds = creds.createScoped(scopes);
            }
            creds.refreshIfExpired();
            return toTokenResponse(creds);
        });
    }

    @Override
    public CompletableFuture<TokenResponse> refreshToken(RequestContext requestContext, String refreshToken) {
        // GCP service accounts use short-lived tokens refreshed via the credential directly;
        // the provided refreshToken is ignored in favour of the current credential's refresh flow.
        return submitAsync(() -> {
            GoogleCredentials creds = credentials();
            creds.refresh();
            return toTokenResponse(creds);
        });
    }

    @Override
    public CompletableFuture<Void> revokeToken(RequestContext requestContext, String token, TokenType tokenType) {
        return submitAsync(() -> {
            String body = "token=" + URLEncoder.encode(token, StandardCharsets.UTF_8);
            send(HttpRequest.newBuilder()
                .uri(URI.create(REVOKE_URL))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build());
            return null;
        });
    }

    @Override
    public CompletableFuture<TokenIntrospection> introspectToken(RequestContext requestContext, String token) {
        return submitAsync(() -> {
            String url = TOKEN_INFO_URL + "?access_token=" + URLEncoder.encode(token, StandardCharsets.UTF_8);
            HttpResponse<String> response = send(HttpRequest.newBuilder()
                .uri(URI.create(url))
                .GET()
                .build());
            JsonNode json = objectMapper.readTree(response.body());
            boolean active = !json.has("error");
            long exp = json.path("exp").asLong(0);
            long iat = json.path("iat").asLong(0);
            List<String> roles = new ArrayList<>();
            return new TokenIntrospection(
                active,
                json.path("sub").asText(null),
                json.path("azp").asText(null),
                json.path("email").asText(null),
                exp,
                iat,
                json.path("scope").asText(null),
                List.copyOf(roles)
            );
        });
    }

    @Override
    public CompletableFuture<UserInfo> getUserInfo(RequestContext requestContext, String accessToken) {
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
        });
    }

    // --- Helpers ---

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
