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

import info.pithos.runtime.core.metrics.InfraOperation;

public enum AuthNOperation implements InfraOperation {

    CLIENT_CREDENTIALS_GRANT("authn.client.credentials"),
    LOGIN("authn.login"),
    LOGIN_ID_TOKEN("authn.login.idtoken"),
    REFRESH_TOKEN("authn.token.refresh"),
    REVOKE_TOKEN("authn.token.revoke"),
    INTROSPECT_TOKEN("authn.token.introspect"),
    GET_USER_INFO("authn.userinfo");

    private final String stem;

    AuthNOperation(String stem) {
        this.stem = stem;
    }

    @Override
    public String stem() {
        return stem;
    }
}
