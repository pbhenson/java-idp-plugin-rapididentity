/*
 * Copyright 2022 Bradley University
 *
 * Bradley University licenses this file to You under the Apache
 * License, Version 2.0 (the "License"); you may not use this file except in
 * compliance with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Developed under contract by Signet Identity
 */

package id.signet.idp.plugin.authn.rapididentity.impl;

import javax.annotation.Nonnull;
import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * An action that calls the RapidIdentity API username method and determines available auth methods.
 */
public class UsernameAPI extends AbstractAPI {

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(UsernameAPI.class);

    /** Constructor. */
    public UsernameAPI() {
    }

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext) {

        final JsonObjectBuilder jsonPostData = Json.createObjectBuilder()
                                                .add("type", "username")
                                                .add("username", rapidIdentityContext.getUsername());

        final JsonObject jsonData = apiCall(profileRequestContext, "/idp/ws/rest/authn", jsonPostData);

        if (jsonData == null) {
            return;
        }

        apiEvaluate(profileRequestContext, authenticationContext, jsonData);
    }
}
