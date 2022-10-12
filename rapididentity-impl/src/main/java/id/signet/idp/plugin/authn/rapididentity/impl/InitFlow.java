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
import java.time.Duration;
import java.util.function.Function;
import javax.annotation.Nonnull;
import net.shibboleth.idp.authn.AbstractAuthenticationAction;
import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.context.AuthenticationErrorContext;
import net.shibboleth.utilities.java.support.annotation.constraint.NonnullAfterInit;
import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.net.CookieManager;
import org.opensaml.messaging.context.navigate.ChildContextLookup;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.security.httpclient.HttpClientSecurityParameters;
import org.opensaml.security.httpclient.HttpClientSecuritySupport;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
/**
 * An action that initializes the RapidIdentity authentication API flow by:
 *     Creating a {@link RapidIdentityContext} from lookup strategy
 *     Checking for a username from a lookup strategy
 *     Setting the HttpClientSecurityParameters on the RapidIdentityContext HttpContext
 *     Checking for a cookie for auth policy autoselection.
 *
 * @event {@link org.opensaml.profile.action.EventIds#PROCEED_EVENT_ID}
 * @event {@link AuthnEventIds#UNKNOWN_USERNAME}
 * @pre <pre>ProfileRequestContext.getSubcontext(AuthenticationContext.class) != null</pre>
 * @post <pre>AuthenticationContext.getSubcontext(RapidIdentityContext.class) != null</pre>
 */
public class InitFlow extends AbstractAuthenticationAction {

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(InitFlow.class);

    /** Lookup strategy for username. */
    @NonnullAfterInit private Function<ProfileRequestContext,String> usernameLookupStrategy;

    /** Creation strategy for RapidIdentity context. */
    @NonnullAfterInit private Function<AuthenticationContext,RapidIdentityContext> contextCreationStrategy;

    /** RapidIdentity context being operated on. */
    @NonnullAfterInit private RapidIdentityContext rapidIdentityContext;

    /** Cookie name for auth policy autoselection. */
    @NonnullAfterInit private String policyCookieName;

    /** RapidIdentity server hostname. */
    @NonnullAfterInit private String server;

    /** Include proxy header in API requests. */
    @NonnullAfterInit private boolean includeProxyHeader;

    /** Timeout for PingMe auth attempt. */
    @NonnullAfterInit private Duration pingMeTimeout;

    /** Refresh interval for PingMe status view. */
    @NonnullAfterInit private Duration pingMeRefresh;

    /** Manages cookies. */
    @NonnullAfterInit private CookieManager cookieManager;

    /** Security parameters for httpClientContext. */
    @NonnullAfterInit private HttpClientSecurityParameters httpClientSecurityParameters;

    /** Constructor. */
    public InitFlow() {
        contextCreationStrategy = new ChildContextLookup<>(RapidIdentityContext.class, true);
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
     * Set the RapidIdentity server hostname.
     *
     * @param hostname RapidIdentity server hostname.
     */
    public void setServer(@Nonnull @NotEmpty final String hostname) throws ComponentInitializationException {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        server = Constraint.isNotNull(hostname, "RapidIdentity server hostname cannot be null");
    }

    /**
     * Set the proxy header flag.
     *
     * @param flag whether to include proxy header in request.
     */
    public void setIncludeProxyHeader(@Nonnull final boolean flag) throws ComponentInitializationException {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        includeProxyHeader = Constraint.isNotNull(flag, "proxy header include flag cannot be null");
    }

    /**
     * Set the timeout for PingMe auth attempt.
     *
     * @param timeout
     *
     */
    @Nonnull public void setPingMeTimeout(@Nonnull final String timeout) {
        pingMeTimeout = Duration.parse(timeout);
    }

    /**
     * Set the refresh interval for PingMe status view.
     *
     * @param refresh
     *
     */
    @Nonnull public void setPingMeRefresh(@Nonnull final String refresh) {
        pingMeRefresh = Duration.parse(refresh);
    }

    /**
     * Set the HttpClientSecurityParameters for TLS validation.
     *
     * @param securityParameters HttpClientSecurityParameters.
     */
    public void setHttpClientSecurityParameters(@Nonnull final HttpClientSecurityParameters securityParameters)
        throws ComponentInitializationException {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        httpClientSecurityParameters = Constraint.isNotNull(securityParameters, "securityParameters cannot be null");
    }

    /**
     * Set the lookup strategy to use for the username.
     *
     * @param strategy lookup strategy
     */
    public void setUsernameLookupStrategy(@Nonnull final Function<ProfileRequestContext,String> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        usernameLookupStrategy = Constraint.isNotNull(strategy, "Username lookup strategy cannot be null");
    }

    /**
     * Set the lookup strategy to locate/create the {@link RapidIdentityContext}.
     *
     * @param strategy lookup/creation strategy
     */
    public void setContextCreationStrategy(@Nonnull final Function<AuthenticationContext,RapidIdentityContext> strategy)
        throws ComponentInitializationException {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        contextCreationStrategy = Constraint.isNotNull(strategy, "Context creation strategy cannot be null");
    }

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext) {

        // Clear error state.
        authenticationContext.removeSubcontext(AuthenticationErrorContext.class);

        // Create auth subcontext
        rapidIdentityContext = contextCreationStrategy.apply(authenticationContext);

        log.debug("{} server = {}", getLogPrefix(), server);
        rapidIdentityContext.setServer(server);

        log.debug("{} includeProxyHeader = {}", getLogPrefix(), includeProxyHeader);
        rapidIdentityContext.setIncludeProxyHeader(includeProxyHeader);

        log.debug("{} pingMeTimeout = {}", getLogPrefix(), pingMeTimeout);
        rapidIdentityContext.setPingMeTimeout(pingMeTimeout);

        log.debug("{} pingMeRefresh = {}", getLogPrefix(), pingMeRefresh);
        rapidIdentityContext.setPingMeRefresh(pingMeRefresh);

        // Find username
        final String username = usernameLookupStrategy.apply(profileRequestContext);
        if (username == null) {
            log.warn("{} No principal name available", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.UNKNOWN_USERNAME);
            return;
        }
        log.debug("{} username = {}", getLogPrefix(), username);
        rapidIdentityContext.setUsername(username);

        HttpClientSecuritySupport.marshalSecurityParameters(rapidIdentityContext.getHttpClientContext(),
            httpClientSecurityParameters, true);

        final String policy = cookieManager.getCookieValue(policyCookieName, null);
        if (policy != null) {
            log.debug("{} found policy cookie {} value {}", getLogPrefix(), policyCookieName, policy);
            rapidIdentityContext.setCookiePolicy(policy);
        } else {
            log.debug("{} policy cookie {} not found", getLogPrefix(), policyCookieName, policy);
        }

        ActionSupport.buildProceedEvent(profileRequestContext);
    }
}
