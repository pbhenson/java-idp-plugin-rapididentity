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

import id.signet.idp.plugin.authn.rapididentity.context.RapidIdentityContext;
import java.util.function.Function;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.servlet.http.HttpServletRequest;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.utilities.java.support.annotation.constraint.NonnullAfterInit;
import net.shibboleth.utilities.java.support.component.AbstractIdentifiableInitializableComponent;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.net.HttpServletSupport;
import org.opensaml.messaging.context.navigate.ChildContextLookup;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
/**
 * A function to generate a key for lockout storage based on the username
 * and client IP address.
 *
 */
public class LockoutKeyStrategy extends AbstractIdentifiableInitializableComponent
    implements Function<ProfileRequestContext,String> {

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(LockoutKeyStrategy.class);

    /** Lookup strategy for RapidIdentity context. */
    @NonnullAfterInit private Function<AuthenticationContext,RapidIdentityContext> contextLookupStrategy;

    /** Servlet request to pull client ip from. **/
    @Nullable private HttpServletRequest httpRequest;

    /** Constructor. */
    public LockoutKeyStrategy() {
        contextLookupStrategy = new ChildContextLookup<>(RapidIdentityContext.class, true);
    }

    /**
     * Set the lookup strategy to locate the {@link RapidIdentityContext}.
     *
     * @param strategy lookup strategy
     */
    public void contextCreationStrategy(@Nonnull final Function<AuthenticationContext,RapidIdentityContext> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        contextLookupStrategy = Constraint.isNotNull(strategy, "Context lookup strategy cannot be null");
    }

    /**
     * Set the servlet request to read from.
     *
     * @param request servlet request
     */
    public void setHttpServletRequest(@Nonnull final HttpServletRequest request) {
        httpRequest = Constraint.isNotNull(request, "HttpServletRequest cannot be null");
    }

    /** {@inheritDoc} */
    @Nullable public String apply(@Nullable final ProfileRequestContext profileRequestContext) {
        if (profileRequestContext == null) {
            log.debug("profileRequestContext is null");
            return null;
        }

        final AuthenticationContext authenticationContext =
            profileRequestContext.getSubcontext(AuthenticationContext.class);
        if (authenticationContext == null) {
            log.debug("authenticationContext is null");
            return null;
        }

        final RapidIdentityContext rapidIdentityContext = contextLookupStrategy.apply(authenticationContext);
        if (rapidIdentityContext == null) {
            log.debug("rapidIdentityContext is null");
            return null;
        }

        final String username = rapidIdentityContext.getUsername();
        if (username == null || username.isEmpty()) {
            log.debug("username is null");
            return null;
        }

        final String remoteAddr = HttpServletSupport.getRemoteAddr(httpRequest);
        if (remoteAddr == null || remoteAddr.isEmpty()) {
            log.debug("remoteAddr is null");
            return null;
        }

        final String lockoutKey = username.toLowerCase() + '!' + remoteAddr;

        log.debug("lockoutKey = {}", lockoutKey);

        return lockoutKey;
    }
}
