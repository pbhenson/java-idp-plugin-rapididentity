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

import java.time.Instant;
import javax.annotation.Nonnull;
import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * An action that initiates a PingMe authentication using the RapidIdentity authentication API.
 */
public class PingMeInitAPI extends AbstractAPI {

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(PingMeInitAPI.class);

    /** Constructor. */
    public PingMeInitAPI() {
    }

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext) {

        @Nonnull final String type = "pingMe";

        if (checkLockedOut(profileRequestContext, authenticationContext)) {
            return;
        }

        final String pingMeUsername = rapidIdentityContext.getPingMeUsername();
        if (pingMeUsername == null) {
            log.error("{} PingMe username not found", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.AUTHN_EXCEPTION);
            return;
        }
        final String pingMeDomain = rapidIdentityContext.getPingMeDomain();

        final JsonObjectBuilder identityObject = Json.createObjectBuilder().add("username", pingMeUsername);
        if (pingMeDomain != null) {
            identityObject.add("domain", pingMeDomain);
        }

        final JsonObjectBuilder jsonPostData = Json.createObjectBuilder()
                                                .add("type", type)
                                                .add("step", Json.createObjectBuilder()
                                                        .add("type", "chooseIdentity")
                                                        .add("identity", identityObject));

        final JsonObject jsonData = apiCall(profileRequestContext, "/idp/ws/rest/authn", jsonPostData);

        if (jsonData == null) {
            return;
        }

        /* We count PingMe "attempts" (request sent to user) rather than explicit
         * "failures" (request denied or timed out) for the purpose of lockout
         */
        incrementLockOut(profileRequestContext);
        rapidIdentityContext.setPingMeStart(Instant.now());

        apiEvaluate(profileRequestContext, authenticationContext, jsonData);
    }
}
