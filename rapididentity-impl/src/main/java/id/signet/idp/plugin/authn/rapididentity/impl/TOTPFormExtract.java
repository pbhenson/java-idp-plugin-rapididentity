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
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import javax.annotation.Nonnull;
import javax.servlet.http.HttpServletRequest;
import net.shibboleth.idp.authn.AbstractAuthenticationAction;
import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.context.AuthenticationErrorContext;
import net.shibboleth.utilities.java.support.annotation.constraint.NonnullAfterInit;
import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.primitive.StringSupport;
import org.opensaml.messaging.context.navigate.ChildContextLookup;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
/**
 * An action extracting a TOTP code from a form post.
 *
 * @event {@link org.opensaml.profile.action.EventIds#PROCEED_EVENT_ID}
 * @event {@link AuthnEventIds#INVALID_CREDENTIALS}
 */
public class TOTPFormExtract extends AbstractAuthenticationAction {

    /** Default token code field name. */
    @Nonnull @NotEmpty public static final String DEFAULT_FIELD_NAME = "tokencode";

    /** Name of form token field. */
    @NonnullAfterInit @NotEmpty private String fieldName;

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(TOTPFormExtract.class);

    /** Lookup strategy for RapidIdentity context. */
    @NonnullAfterInit private Function<AuthenticationContext,RapidIdentityContext> contextLookupStrategy;

    /** RapidIdentity context in use. */
    @NonnullAfterInit private RapidIdentityContext rapidIdentityContext;

    /** Constructor. */
    public TOTPFormExtract() {
        contextLookupStrategy = new ChildContextLookup<>(RapidIdentityContext.class, true);
        fieldName = DEFAULT_FIELD_NAME;
    }

    /**
     * Set the lookup strategy to locate the {@link RapidIdentityContext}.
     *
     * @param strategy lookup strategy
     */
    public void setContextLookupStrategy(@Nonnull final Function<AuthenticationContext,RapidIdentityContext> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        contextLookupStrategy = Constraint.isNotNull(strategy, "RapidIdentityContext lookup strategy cannot be null");
    }

    /**
     * Set the name of the field to examine.
     *
     * @param field field name
     */
    public void setFieldName(@Nonnull @NotEmpty final String field) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        fieldName = Constraint.isNotNull(StringSupport.trimOrNull(field), "Field name cannot be null or empty");
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

        final HttpServletRequest httpRequest = getHttpServletRequest();
        if (httpRequest == null) {
            log.warn("{} Profile action does not contain an HttpServletRequest", getLogPrefix());
            authenticationContext.getSubcontext(AuthenticationErrorContext.class,
                true).getClassifiedErrors().add(AuthnEventIds.NO_CREDENTIALS);
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
            return;
        }

        final String code = httpRequest.getParameter(fieldName);

        if (code == null) {
            log.warn("{} parameter {} not found", getLogPrefix(), fieldName);
            authenticationContext.getSubcontext(AuthenticationErrorContext.class,
                true).getClassifiedErrors().add(AuthnEventIds.NO_CREDENTIALS);
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
            return;
        }

        try {
            if (!Pattern.matches("^\\d{6}$", code)) {
                log.warn("{} invalid token code {}", getLogPrefix(), code);
                authenticationContext.getSubcontext(AuthenticationErrorContext.class,
                    true).getClassifiedErrors().add(AuthnEventIds.INVALID_CREDENTIALS);
                ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.INVALID_CREDENTIALS);
                return;
            }
        } catch (final PatternSyntaxException e) {
            log.error("{} internal error parsing code check regex", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.AUTHN_EXCEPTION);
            return;
        }

        log.debug("{} storing code {}", getLogPrefix(), code);
        rapidIdentityContext.setTOTPCode(code);

        ActionSupport.buildProceedEvent(profileRequestContext);
    }
}
