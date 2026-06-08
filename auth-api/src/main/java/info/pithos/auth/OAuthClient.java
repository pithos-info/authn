package info.pithos.auth;

import info.pithos.auth.model.TokenIntrospection;
import info.pithos.auth.model.TokenResponse;
import info.pithos.auth.model.TokenType;
import info.pithos.auth.model.UserInfo;
import info.pithos.runtime.core.context.ServiceLifeCycle;
import info.pithos.runtime.model.protocol.Context.RequestContext;

import java.util.List;
import java.util.concurrent.CompletableFuture;

public interface OAuthClient extends ServiceLifeCycle {

    // --- Token acquisition ---

    CompletableFuture<TokenResponse> clientCredentialsGrant(RequestContext requestContext, List<String> scopes);

    CompletableFuture<TokenResponse> login(RequestContext requestContext, String username, String password);

    // --- Token lifecycle ---

    CompletableFuture<TokenResponse> refreshToken(RequestContext requestContext, String refreshToken);

    CompletableFuture<Void> revokeToken(RequestContext requestContext, String token, TokenType tokenType);

    // --- Token validation ---

    CompletableFuture<TokenIntrospection> introspectToken(RequestContext requestContext, String token);

    // --- Identity ---

    CompletableFuture<UserInfo> getUserInfo(RequestContext requestContext, String accessToken);
}
