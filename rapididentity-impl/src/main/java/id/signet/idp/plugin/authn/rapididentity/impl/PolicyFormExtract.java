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
import javax.servlet.http.HttpServletRequest;
import net.shibboleth.idp.authn.AbstractAuthenticationAction;
import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.utilities.java.support.annotation.constraint.NonnullAfterInit;
import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.net.CookieManager;
import net.shibboleth.utilities.java.support.primitive.StringSupport;
import org.opensaml.messaging.context.navigate.ChildContextLookup;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
/**
 * An action extracting a policy id from a form post.
 *
 */
public class PolicyFormExtract extends AbstractAuthenticationAction {

    /** Default policy field name. */
    @Nonnull @NotEmpty public static final String DEFAULT_POLICY_FIELD_NAME = "policy";

    /** Default remember field name. */
    @Nonnull @NotEmpty public static final String DEFAULT_REMEMBER_FIELD_NAME = "remember";

    /** Default forget field name. */
    @Nonnull @NotEmpty public static final String DEFAULT_FORGET_FIELD_NAME = "forget";

    /** Name of form policy field. */
    @NonnullAfterInit @NotEmpty private String policyFieldName;

    /** Name of form remember field. */
    @NonnullAfterInit @NotEmpty private String rememberFieldName;

    /** Name of form forget field. */
    @NonnullAfterInit @NotEmpty private String forgetFieldName;

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(PolicyFormExtract.class);

    /** Lookup strategy for RapidIdentity context. */
    @NonnullAfterInit private Function<AuthenticationContext,RapidIdentityContext> contextLookupStrategy;

    /** RapidIdentity context in use. */
    @NonnullAfterInit private RapidIdentityContext rapidIdentityContext;

    /** Cookie name for auth policy autoselection. */
    @NonnullAfterInit private String policyCookieName;

    /** Manages cookies. */
    @NonnullAfterInit private CookieManager cookieManager;

    /** Constructor. */
    public PolicyFormExtract() {
        contextLookupStrategy = new ChildContextLookup<>(RapidIdentityContext.class, true);
        policyFieldName = DEFAULT_POLICY_FIELD_NAME;
        rememberFieldName = DEFAULT_REMEMBER_FIELD_NAME;
        forgetFieldName = DEFAULT_FORGET_FIELD_NAME;
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
     * Set the {@link CookieManager} to use.
     *
     * @param manager the CookieManager to use.
     */
    public void setCookieManager(@Nonnull final CookieManager manager) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        cookieManager = Constraint.isNotNull(manager, "CookieManager cannot be null");
    }

    /**
     * Get the {@link CookieManager}.
     *
     * @return the CookieManager.
     */
    @Nonnull public CookieManager getCookieManager() {
        return cookieManager;
    }

    /**
     * Set the cookie name for auth policy autoselection.
     *
     * @param cookieName cookie name for auth policy autoselection
     */
    public void setPolicyCookieName(@Nonnull @NotEmpty final String cookieName)
        throws ComponentInitializationException {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        policyCookieName = Constraint.isNotNull(cookieName, "cookie name cannot be null");
    }

    /**
     * Set the name of the field to examine for policy.
     *
     * @param field field name
     */
    public void setPolicyFieldName(@Nonnull @NotEmpty final String field) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        policyFieldName = Constraint.isNotNull(StringSupport.trimOrNull(field), "Field name cannot be null or empty");
    }

    /**
     * Set the name of the field to examine for remember checkbox.
     *
     * @param field field name
     */
    public void setRememberFieldName(@Nonnull @NotEmpty final String field) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        rememberFieldName = Constraint.isNotNull(StringSupport.trimOrNull(field), "Field name cannot be null or empty");
    }

    /**
     * Set the name of the field to examine for forget checkbox.
     *
     * @param field field name
     */
    public void setForgetFieldName(@Nonnull @NotEmpty final String field) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        forgetFieldName = Constraint.isNotNull(StringSupport.trimOrNull(field), "Field name cannot be null or empty");
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
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
            return;
        }

        final String policy = httpRequest.getParameter(policyFieldName);

        if (policy == null) {
            log.warn("{} parameter {} not found", getLogPrefix(), policyFieldName);
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
            return;
        }

        if (rapidIdentityContext.getAuthPolicyById(policy) == null) {
            log.warn("{} policy {} not found", getLogPrefix(), policy);
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
            return;
        }

        final String remember = httpRequest.getParameter(rememberFieldName);
        if (remember != null) {
            log.debug("{} saving policy choice to cookie {}", getLogPrefix(), policyCookieName);
            cookieManager.addCookie(policyCookieName, policy);
            rapidIdentityContext.setStoredCookiePolicy(true);
        } else {
            final String forget = httpRequest.getParameter(forgetFieldName);
            if (forget != null) {
                log.debug("{} removing policy choice cookie {}", getLogPrefix(), policyCookieName);
                cookieManager.unsetCookie(policyCookieName);
                rapidIdentityContext.setStoredCookiePolicy(false);
            }
        }

        log.debug("{} storing selected policy {}", getLogPrefix(), policy);
        rapidIdentityContext.setSelectedPolicy(policy);

        ActionSupport.buildProceedEvent(profileRequestContext);
    }

}
