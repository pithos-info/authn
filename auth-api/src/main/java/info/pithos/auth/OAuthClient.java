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

    CompletableFuture<TokenResponse> loginWithIdToken(RequestContext requestContext, String idToken);

    // --- Token lifecycle ---

    CompletableFuture<TokenResponse> refreshToken(RequestContext requestContext, String refreshToken);

    CompletableFuture<Void> revokeToken(RequestContext requestContext, String token, TokenType tokenType);

    // --- Token validation ---

    CompletableFuture<TokenIntrospection> introspectToken(RequestContext requestContext, String token);

    // --- Identity ---

    CompletableFuture<UserInfo> getUserInfo(RequestContext requestContext, String accessToken);
}
