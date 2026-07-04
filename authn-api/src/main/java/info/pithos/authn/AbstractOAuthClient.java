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

package info.pithos.authn;

import info.pithos.runtime.core.context.ApplicationContext;
import info.pithos.runtime.core.metrics.InfraOperation;
import info.pithos.runtime.core.metrics.MetricsCommitter;
import info.pithos.runtime.model.metrics.Metrics.ComponentType;
import info.pithos.runtime.model.metrics.Metrics.MetricEvent;
import info.pithos.runtime.model.metrics.Metrics.MetricUnit;
import info.pithos.runtime.model.protocol.Context.RequestContext;

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

    /** Identity provider name used as the provider-aggregate componentId, e.g. "keycloak", "gcp-identity". */
    protected abstract String componentProvider();

    /** Tenant-scoped componentId, e.g. realm name (Keycloak) or project ID (GCP). */
    protected abstract String componentId();

    // ── Metrics helpers ───────────────────────────────────────────────────────

    protected void recordOp(RequestContext rc, AuthNOperation op, long startMs, Throwable ex) {
        MetricsCommitter mc = context.getMetricsCommitter();
        if (mc == null) return;
        long elapsedMs = System.currentTimeMillis() - startMs;
        String provider = componentProvider();
        emitPair(mc, rc, componentId(), provider, op, elapsedMs, ex);
        emitPair(mc, rc, provider, provider, op, elapsedMs, ex);
    }

    private static void emitPair(MetricsCommitter mc, RequestContext rc, String componentId, String provider,
                                  AuthNOperation op, long elapsedMs, Throwable ex) {
        mc.record(rc, MetricEvent.newBuilder()
                .setMetric(op.latency()).setUnit(MetricUnit.MS).setValue(elapsedMs)
                .setComponentType(ComponentType.AUTH).setComponentId(componentId).setComponentProvider(provider)
                .build());
        mc.record(rc, MetricEvent.newBuilder()
                .setMetric(InfraOperation.outcome(op, ex)).setUnit(MetricUnit.COUNT).setValue(1.0)
                .setComponentType(ComponentType.AUTH).setComponentId(componentId).setComponentProvider(provider)
                .build());
    }
}
