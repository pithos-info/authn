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

import info.pithos.runtime.core.context.ApplicationContext;

import java.util.concurrent.Callable;
import java.util.concurrent.CompletableFuture;

public abstract class AbstractOAuthClient implements OAuthClient {

    protected final ApplicationContext context;

    protected AbstractOAuthClient(ApplicationContext context) {
        if (context == null) throw new IllegalArgumentException("context must not be null");
        this.context = context;
    }

    protected <T> CompletableFuture<T> submitAsync(Callable<T> task) {
        return context.getSystemContext().submitAsync(task);
    }
}
