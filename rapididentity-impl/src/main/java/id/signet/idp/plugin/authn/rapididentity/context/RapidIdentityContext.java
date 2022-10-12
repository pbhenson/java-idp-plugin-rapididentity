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

package id.signet.idp.plugin.authn.rapididentity.context;

import com.google.common.base.Strings;
import id.signet.idp.plugin.authn.rapididentity.impl.AuthPolicy;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import net.shibboleth.utilities.java.support.annotation.constraint.NonnullAfterInit;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.impl.client.BasicCookieStore;
import org.opensaml.messaging.context.BaseContext;

/**
 * Context class for RapidIdentity authentication API flow.
 */
public class RapidIdentityContext extends BaseContext {

    /** RapidIdentity API server hostname. */
    @NonnullAfterInit private String server;

    /** Include proxy header with IP of client. */
    @NonnullAfterInit boolean includeProxyHeader;

    /** Timeout for PingMe auth attempt. */
    @NonnullAfterInit private Duration pingMeTimeout;

    /** Refresh interval for PingMe status view. */
    @NonnullAfterInit private Duration pingMeRefresh;

    /** RapidIdentity API identifier for auth session in progress. */
    @Nullable private String authID;

    /** Persistent HTTP client context for API calls. */
    @Nonnull private final HttpClientContext httpClientContext = HttpClientContext.create();

    /** Subject identifier with respect to the RapidIdentity API. */
    @Nullable private String username;

    /** Policy retrieved from client cookie if set. */
    @Nullable private String cookiePolicy;

    /** Whether or not a stored policy cookie exists. */
    @Nonnull private boolean storedCookiePolicy;

    /** Policy select if multiple available. */
    @Nullable private String selectedPolicy;

    /** Code for TOTP method. */
    @Nullable private String tOTPCode;

    /** Username for PingMe method. */
    @Nullable private String pingMeUsername;

    /** Domain for PingMe method. */
    @Nullable private String pingMeDomain;

    /** Start time of PingMe auth. */
    @Nullable private Instant pingMeStart;

    /** List of available auth policies if multiple set. */
    @Nonnull private List<AuthPolicy> authPolicies = new ArrayList<>();

    /** Constructor. */
    public RapidIdentityContext() {
        /* Add a persistent cookie store to http client context */
        httpClientContext.setCookieStore(new BasicCookieStore());
    }

    /**
     * Get the RapidIdentity server hostname.
     *
     * @return RapidIdentity server hostname
     */
    @Nullable public String getServer() {
        return server;
    }

    /**
     * Set the RapidIdentity server hostname.
     *
     * @param server the RapidIdentity server hostname
     *
     * @return this context
     */
    @Nonnull public RapidIdentityContext setServer(@Nullable final String theServer) {
        if (Strings.isNullOrEmpty(theServer)) {
            server = null;
        } else {
            server = theServer;
        }

        return this;
    }

    /**
     * Get the proxy header include flag.
     *
     * @return proxy header include flag
     */
    @Nullable public boolean getIncludeProxyHeader() {
        return includeProxyHeader;
    }

    /**
     * Set the proxy header include flag.
     *
     * @param flag whether to include proxy header in API requests
     *
     * @return this context
     */
    @Nonnull public RapidIdentityContext setIncludeProxyHeader(@Nullable final boolean flag) {
        includeProxyHeader = flag;

        return this;
    }

    /**
     * Get the timeout for PingMe auth attempt.
     *
     * @return timeout for PingMe auth attempt
     */
    @Nullable public Duration getPingMeTimeout() {
        return pingMeTimeout;
    }

    /**
     * Set the timeout for PingMe auth attempt.
     *
     * @param timeout
     *
     * @return this context
     */
    @Nonnull public RapidIdentityContext setPingMeTimeout(@Nonnull final Duration timeout) {
        pingMeTimeout = timeout;

        return this;
    }

    /**
     * Get refresh interval for PingMe status view.
     *
     * @return refresh interval for PingMe status view
     */
    @Nullable public Duration getPingMeRefresh() {

        return pingMeRefresh;
    }

    /**
     * Set the refresh interval for PingMe status view.
     *
     * @param refresh
     *
     * @return this context
     */
    @Nonnull public RapidIdentityContext setPingMeRefresh(@Nonnull final Duration refresh) {
        pingMeRefresh = refresh;

        return this;
    }

    /**
     * Get the RapidIdentity API session identifier.
     *
     * @return RapidIdentity API session identifier
     */
    @Nullable public String getAuthID() {
        return authID;
    }

    /**
     * Set the RapidIdentity API session identifier.
     *
     * @param id the RapidIdentity API session identifier
     *
     * @return this context
     */
    @Nonnull public RapidIdentityContext setAuthID(@Nullable final String id) {
        if (Strings.isNullOrEmpty(id)) {
            authID = null;
        } else {
            authID = id;
        }

        return this;
    }

    /**
     * Get the username.
     *
     * @return the username
     */
    @Nullable public String getUsername() {
        return username;
    }

    /**
     * Set the username.
     *
     * @param name the username
     *
     * @return this context
     */
    @Nonnull public RapidIdentityContext setUsername(@Nullable final String name) {
        if (Strings.isNullOrEmpty(name)) {
            username = null;
        } else {
            username = name;
        }

        return this;
    }

    /**
     * Get the selected policy if multiple available.
     *
     * @return the selected policy
     */
    @Nullable public String getSelectedPolicy() {
        return selectedPolicy;
    }

    /**
     * Set the policy to select if multiple available.
     *
     * @param policy the selected policy
     *
     * @return this context
     */
    @Nonnull public RapidIdentityContext setSelectedPolicy(@Nullable final String policy) {
        if (Strings.isNullOrEmpty(policy)) {
            selectedPolicy = null;
        } else {
            selectedPolicy = policy;
        }

        return this;
    }

    /**
     * Get the policy from client cookie.
     *
     * @return the policy from client cookie
     */
    @Nullable public String getCookiePolicy() {
        return cookiePolicy;
    }

    /**
     * Set the policy from client cookie.
     *
     * @param policy the policy from client cookie
     *
     * @return this context
     */
    @Nonnull public RapidIdentityContext setCookiePolicy(@Nullable final String policy) {
        if (Strings.isNullOrEmpty(policy)) {
            cookiePolicy = null;
        } else {
            cookiePolicy = policy;
            storedCookiePolicy = true;
        }

        return this;
    }

    /**
     * Whether a stored cookie policy exists.
     *
     * @return boolean indicating whether a stored cookie policy exists
     */
    @Nonnull public boolean getStoredCookiePolicy() {
        return storedCookiePolicy;
    }

    /**
     * Update boolean indicating whether a stored cookie policy exists.
     *
     * @param stored whether a stored cookie policy exists
     *
     * @return this context
     */
    @Nonnull public RapidIdentityContext setStoredCookiePolicy(@Nonnull final boolean stored) {
        storedCookiePolicy = stored;

        return this;
    }

    /**
     * Get the TOTP code.
     *
     * @return the TOTP code
     */
    @Nullable public String getTOTPCode() {
        return tOTPCode;
    }

    /**
     * Set the TOTP code.
     *
     * @param code the TOTP code
     *
     * @return this context
     */
    @Nonnull public RapidIdentityContext setTOTPCode(@Nullable final String code) {
        if (Strings.isNullOrEmpty(code)) {
            tOTPCode = null;
        } else {
            tOTPCode = code;
        }

        return this;
    }

    /**
     * Get the PingMe username.
     *
     * @return the PingMe username
     */
    @Nullable public String getPingMeUsername() {
        return pingMeUsername;
    }

    /**
     * Set the PingMe username.
     *
     * @param theUsername the PingMe username
     *
     * @return this context
     */
    @Nonnull public RapidIdentityContext setPingMeUsername(@Nullable final String theUsername) {
        if (Strings.isNullOrEmpty(theUsername)) {
            pingMeUsername = null;
        } else {
            pingMeUsername = theUsername;
        }

        return this;
    }

    /**
     * Get the PingMe domain.
     *
     * @return the PingMe domain
     */
    @Nullable public String getPingMeDomain() {
        return pingMeDomain;
    }

    /**
     * Set the PingMe domain.
     *
     * @param domain the PingMe domain
     *
     * @return this context
     */
    @Nonnull public RapidIdentityContext setPingMeDomain(@Nullable final String domain) {
        if (Strings.isNullOrEmpty(domain)) {
            pingMeDomain = null;
        } else {
            pingMeDomain = domain;
        }

        return this;
    }

    /**
     * Get start time of PingMe auth.
     *
     * @return time start time of PingMe auth
     */
    @Nullable public Instant getPingMeStart() {
        return pingMeStart;
    }

    /**
     * Set the start time of PingMe auth.
     *
     * @param time start time of PingMe auth
     *
     * @return this context
     */
    @Nonnull public RapidIdentityContext setPingMeStart(@Nonnull final Instant time) {
        pingMeStart = time;

        return this;
    }

    /**
     * Get the HttpClientContext.
     *
     * @return httpClientContext
     */
    @Nonnull public HttpClientContext getHttpClientContext() {
        return httpClientContext;
    }

    /**
     * Add an auth policy to list.
     *
     * @param policy AuthPolicy describing auth policy to add
     *
     * @return this context
     */
    @Nonnull public RapidIdentityContext addAuthPolicy(@Nonnull final AuthPolicy policy) {
        authPolicies.add(policy);

        return this;
    }

    /**
     * Return auth policy identified by id.
     *
     * @param id the id to search for
     * @return AuthPolicy describing auth policy identified by id or null if not found
     */
    @Nullable public AuthPolicy getAuthPolicyById(@Nonnull final String id) {
        for (final AuthPolicy authPolicy : authPolicies) {
            if (authPolicy.getId().equals(id)) {
                return authPolicy;
            }
        }

        return null;
    }

    /**
     * Return array of available auth policies.
     *
     * @return array of available auth policies
     */
    @Nonnull public AuthPolicy[] getAuthPolicies() {
        return authPolicies.toArray(new AuthPolicy[authPolicies.size()]);
    }

    /**
     * Return whether all auth policies are "simple" (have exactly one method).
     *
     * @return boolean indicating whether all auth policies are "simple"
     */
    @Nonnull public boolean authPoliciesSimple() {
        for (final AuthPolicy policy : authPolicies) {
            if (policy.getMethods().length > 1) {
                return false;
            }
        }

        return true;
    }

    /**
     * Return how many seconds left until PingMe auth times out.
     *
     * @return int seconds left until PingMe auth times out
     */
    @Nonnull public long pingMeTimeLeft() {
        return Math.max(0, pingMeTimeout.getSeconds() -
                            ChronoUnit.SECONDS.between(pingMeStart, Instant.now()));
    }

    /**
     * Reset context state.
     *
     */
    public void reset() {
        authID = null;
        cookiePolicy = null;
        selectedPolicy = null;
        tOTPCode = null;
        pingMeUsername = null;
        pingMeDomain = null;
        pingMeStart = null;
        authPolicies = new ArrayList<>();
    }
}
