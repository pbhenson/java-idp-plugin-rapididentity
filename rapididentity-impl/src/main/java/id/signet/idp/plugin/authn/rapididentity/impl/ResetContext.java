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
import net.shibboleth.idp.authn.AbstractAuthenticationAction;
import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.context.AuthenticationErrorContext;
import net.shibboleth.utilities.java.support.annotation.constraint.NonnullAfterInit;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;
import org.opensaml.messaging.context.navigate.ChildContextLookup;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
/**
 * An action resetting a RapidIdentity context to restart the auth process.
 *
 */
public class ResetContext extends AbstractAuthenticationAction {

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(ResetContext.class);

    /** Lookup strategy for RapidIdentity context. */
    @NonnullAfterInit private Function<AuthenticationContext,RapidIdentityContext> contextLookupStrategy;

    /** RapidIdentity context in use. */
    private RapidIdentityContext rapidIdentityContext;

    /** Constructor. */
    public ResetContext() {
        contextLookupStrategy = new ChildContextLookup<>(RapidIdentityContext.class, true);
    }

    /**
     * Set the lookup strategy to locate the {@link RapidIdentityContext}.
     *
     * @param strategy lookup strategy
     */
    public void setContextLookupStrategy(@Nonnull final Function<AuthenticationContext,RapidIdentityContext> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        contextLookupStrategy = Constraint.isNotNull(strategy, "Context lookup strategy cannot be null");
    }

    /**
     * Performs this authentication action's pre-execute step.
     *
     * @param profileRequestContext the current IdP profile request context
     * @param authenticationContext the current authentication context
     *
     * @return true iff execution should continue
     */
    @Override
    protected boolean doPreExecute(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext) {

        if (!super.doPreExecute(profileRequestContext, authenticationContext)) {
            return false;
        }

        rapidIdentityContext = contextLookupStrategy.apply(authenticationContext);
        if (rapidIdentityContext == null) {
            log.error("{} No RapidIdentityContext available", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.UNKNOWN_USERNAME);
            return false;
        }

        return true;
    }

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext) {

        // Clear error state
        authenticationContext.removeSubcontext(AuthenticationErrorContext.class);

        rapidIdentityContext.reset();
    }

}
