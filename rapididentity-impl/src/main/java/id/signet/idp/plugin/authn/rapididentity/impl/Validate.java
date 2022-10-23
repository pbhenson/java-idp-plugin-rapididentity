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
import javax.security.auth.Subject;
import net.shibboleth.idp.authn.AbstractValidationAction;
import net.shibboleth.idp.authn.AccountLockoutManager;
import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.principal.UsernamePrincipal;
import net.shibboleth.utilities.java.support.annotation.constraint.NonnullAfterInit;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import org.opensaml.messaging.context.navigate.ChildContextLookup;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * An action that directly produces an {@link
 * net.shibboleth.idp.authn.AuthenticationResult} based on the entity
 * authenticated via the RapidIdentity authentication API.
 *
 */
public class Validate extends AbstractValidationAction {

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(Validate.class);

    /** Lookup strategy for RapidIdentity context. */
    @NonnullAfterInit private Function<AuthenticationContext,RapidIdentityContext> contextLookupStrategy;

    /** RapidIdentity context in use. */
    @NonnullAfterInit private RapidIdentityContext rapidIdentityContext;

    /** Optional lockout management interface. */
    @Nullable private AccountLockoutManager lockoutManager;

    /** Constructor. */
    public Validate() {
        contextLookupStrategy = new ChildContextLookup<>(RapidIdentityContext.class, true);
    }

    /**
     * Set an account lockout management component.
     *
     * @param manager lockout manager
     */
    public void setLockoutManager(@Nullable final AccountLockoutManager manager) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        lockoutManager = manager;
    }

    /** {@inheritDoc} */
    @Override
    protected boolean doPreExecute(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext) {

        if (!super.doPreExecute(profileRequestContext, authenticationContext)) {
            return false;
        }

        rapidIdentityContext = contextLookupStrategy.apply(authenticationContext);
        if (rapidIdentityContext == null) {
            log.error("{} No RapidIdentityContext available", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.AUTHN_EXCEPTION);
            return false;
        }

        return true;
    }

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext) {

        log.info("{} RapidIdentity MFA by '{}' succeeded", getLogPrefix(), rapidIdentityContext.getUsername());

        if (lockoutManager != null) {
            log.debug("{} clearing lockout state", getLogPrefix());

            if (!lockoutManager.clear(profileRequestContext)) {
                log.warn("{} failed to clear lockout state", getLogPrefix());
            }
        } else {
            log.debug("{} lockoutManager not enabled", getLogPrefix());
        }

        buildAuthenticationResult(profileRequestContext, authenticationContext);
        ActionSupport.buildProceedEvent(profileRequestContext);
    }

    /** {@inheritDoc} */
    @Override
    @Nonnull protected Subject populateSubject(@Nonnull final Subject subject) {
        subject.getPrincipals().add(new UsernamePrincipal(rapidIdentityContext.getUsername()));

        return subject;
    }

}
