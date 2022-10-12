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
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.function.Function;
import java.util.List;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.json.JsonReader;
import javax.json.JsonValue;
import javax.json.JsonWriter;
import javax.json.stream.JsonParsingException;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.servlet.http.HttpServletRequest;
import net.shibboleth.idp.authn.AbstractAuthenticationAction;
import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.context.AuthenticationErrorContext;
import net.shibboleth.utilities.java.support.annotation.constraint.NonnullAfterInit;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.config.CookieSpecs;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.entity.StringEntity;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.util.EntityUtils;
import org.opensaml.messaging.context.navigate.ChildContextLookup;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.security.httpclient.HttpClientSecuritySupport;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
/**
 * An abstract action providing the framework for making RapidIdentity
 * authentication API calls and evaluating the response.
 *
 * @event {@link AuthnEventIds#UNKNOWN_USERNAME}
 */
public abstract class AbstractAPI extends AbstractAuthenticationAction {

    /** RapidIdentity context in use. */
    @Nullable protected RapidIdentityContext rapidIdentityContext;

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(AbstractAPI.class);

    /** Lookup strategy for RapidIdentity context. */
    @NonnullAfterInit private Function<AuthenticationContext,RapidIdentityContext> contextLookupStrategy;

    /** HttpClient to use. */
    @NonnullAfterInit private HttpClient httpClient;

    /** List of support authentication methods. */
    @Nonnull private List<String> supportedAuthMethods =
        new ArrayList<>(List.of("totp", "pingMe"));

    /** Constructor. */
    public AbstractAPI() {
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
     * Set the HttpClient to use.
     *
     * @param theHttpClient HttpClient to use
     */
    public void setHttpClient(@Nonnull final HttpClient theHttpClient) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        httpClient = Constraint.isNotNull(theHttpClient, "httpClient cannot be null");
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

    /**
     * Executes a RapidIdentity API call.
     *
     * @param profileRequestContext ProfileRequestContext for request
     * @param endpoint path of API endpoint
     * @param postData JsonObjectBuilder with data to post
     *
     * @return JsonObject result of API call
     */
    protected JsonObject apiCall(final ProfileRequestContext profileRequestContext,
            final String endpoint, final JsonObjectBuilder postData) {
        final String URI = "https://" + rapidIdentityContext.getServer() + endpoint;
        final HttpClientContext httpClientContext = rapidIdentityContext.getHttpClientContext();

        @NonnullAfterInit final HttpRequestBase httpRequest;

        log.debug("{} API URI {}", getLogPrefix(), URI);

        if (postData == null) {
            httpRequest = new HttpGet(URI);
        } else {
            httpRequest = new HttpPost(URI);

            final String authID = rapidIdentityContext.getAuthID();
            if (authID != null) {
                log.debug("{} API session id {}", getLogPrefix(), authID);
                postData.add("id", authID);
            }

            final StringWriter stringWriter = new StringWriter();
            final JsonWriter jsonWriter = Json.createWriter(stringWriter);
            jsonWriter.writeObject(postData.build());
            jsonWriter.close();

            try {
                final String jsonString = stringWriter.toString();
                log.trace("{} json post data {}", getLogPrefix(), jsonString);

                final StringEntity stringEntity = new StringEntity(jsonString);
                stringEntity.setContentType("application/json");
                HttpPost.class.cast(httpRequest).setEntity(stringEntity);
            } catch (final java.io.UnsupportedEncodingException e) {
                log.error("{} JSON encoding error: {}", getLogPrefix(), e);
                ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.AUTHN_EXCEPTION);
                return null;
            }

        }
        httpRequest.setHeader( "Accept", "application/json" );

        final boolean includeProxyHeader = rapidIdentityContext.getIncludeProxyHeader();
        if (includeProxyHeader) {
            final HttpServletRequest clientHttpRequest = getHttpServletRequest();
            if (clientHttpRequest != null) {
                final String remoteAddr = clientHttpRequest.getRemoteAddr();
                log.debug("{} including proxy header for client IP {}", getLogPrefix(), remoteAddr);
                httpRequest.setHeader("X-Forwarded-For", remoteAddr);
            }
            else {
                log.error("{} no HttpServletRequest found, cannot include proxy header", getLogPrefix());
                ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.AUTHN_EXCEPTION);
                return null;
            }
        }
        else {
            log.debug("{} proxy header disabled", getLogPrefix());
        }

        final RequestConfig requestConfig =
            RequestConfig.custom().setCookieSpec(CookieSpecs.STANDARD).build();
        httpRequest.setConfig(requestConfig);

        JsonObject returnJson = null;
        HttpResponse httpResponse = null;
        try {
            httpResponse = httpClient.execute(httpRequest, httpClientContext);
            HttpClientSecuritySupport.checkTLSCredentialEvaluated(httpClientContext,
                httpRequest.getURI().getScheme());

            final int httpStatusCode = httpResponse.getStatusLine().getStatusCode();

            if (httpStatusCode != HttpStatus.SC_OK) {
                throw new IOException("Non-ok status code (" + httpStatusCode +
                    ") returned from RapidIdentity API: " + httpResponse.getStatusLine().getReasonPhrase());
            }

            final HttpEntity httpEntity = httpResponse.getEntity();
            if (httpEntity == null) {
                throw new IOException("No response body returned from RapidIdentity API");
            }

            final String responseContent = EntityUtils.toString(httpEntity);
            log.trace("{} api response {}", getLogPrefix(), responseContent);

            final JsonReader jsonReader = Json.createReader(new StringReader(responseContent));
            returnJson = jsonReader.readObject();
            jsonReader.close();
        } catch (final ClientProtocolException e) {
            log.error("{} HTTP protocol error", getLogPrefix(), e);
        } catch (final SSLPeerUnverifiedException e) {
            log.error("{} Untrusted certificate presented by RapidIdentity API server", getLogPrefix());
        } catch (final SSLException e) {
            log.error("{} SSL connection error", getLogPrefix(), e);
        } catch (final IOException e) {
            log.error("{} IO error", getLogPrefix(), e);
        } catch (final JsonParsingException e) {
            log.error("{} JSON parsing error", getLogPrefix(), e);
        } finally {
            if (httpResponse != null && CloseableHttpResponse.class.isInstance(httpResponse)) {
                try {
                    CloseableHttpResponse.class.cast(httpResponse).close();
                } catch (final IOException e) {
                    log.debug("{} error closing HttpResponse", getLogPrefix(), e);
                }
            }

            if (returnJson == null) {
                ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.AUTHN_EXCEPTION);
            }

            return returnJson;
        }
    }

    /**
     * Evaluates API call response.
     *
     * @param profileRequestContext ProfileRequestContext for request
     * @param authenticationContext authenticationContext for request
     * @param jsonData JsonObject with result from API call
     *
     */
    protected void apiEvaluate(@Nonnull final ProfileRequestContext profileRequestContext,
        @Nonnull final AuthenticationContext authenticationContext, @Nonnull final JsonObject jsonData) {

        @NonnullAfterInit final String type;
        try {
            type = jsonData.getString("type");
        } catch (final NullPointerException e) {
            log.error("{} type not found in api response", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.AUTHN_EXCEPTION);
            return;
        } catch (final ClassCastException e) {
            log.error("{} type not string in api response", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.AUTHN_EXCEPTION);
            return;
        }
        log.debug("{} type = {} in api response", getLogPrefix(), type);

        String error = null;
        try {
            final JsonObject errorObject = jsonData.getJsonObject("error");

            if (errorObject != null) {
                @NonnullAfterInit final String errorType;
                try {
                    errorType = errorObject.getString("type");
                } catch (final NullPointerException e) {
                    log.error("{} type not found in api error response", getLogPrefix());
                    ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.AUTHN_EXCEPTION);
                    return;
                } catch (final ClassCastException e) {
                    log.error("{} type not string in api error response", getLogPrefix());
                    ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.AUTHN_EXCEPTION);
                    return;
                }

                if (!errorType.equals("simple")) {
                    log.error("{} unsupported error type {} in api error response",
                        getLogPrefix(), errorType);
                    ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.AUTHN_EXCEPTION);
                    return;
                }

                try {
                    error = errorObject.getString("message");
                } catch (final NullPointerException e) {
                    log.error("{} message not found in api error response", getLogPrefix());
                    ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.AUTHN_EXCEPTION);
                    return;
                } catch (final ClassCastException e) {
                    log.error("{} message not string in api error response", getLogPrefix());
                    ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.AUTHN_EXCEPTION);
                    return;
                }

                log.debug("{} error message = {}", getLogPrefix(), error);
            }
        } catch (final ClassCastException e) {
            log.error("{} error not json object", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.AUTHN_EXCEPTION);
            return;
        }

        if (type.equals("fail")) {
            if (error == null) {
                log.error("{} fail event with no error", getLogPrefix());
            } else {
                log.error("{} fail - {}", getLogPrefix(), error);
            }
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.AUTHN_EXCEPTION);
            return;
        } else if (type.equals("username")) {
            if (error != null) {
                log.error("{} unexpected username error {}", getLogPrefix(), error);
                ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.AUTHN_EXCEPTION);
                return;
            }

            log.debug("{} proceeding to username API call", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, Events.UsernameAPI.event(this));
        } else if (type.equals("totp")) {
            if (error != null) {
                if (error.equals("Authentication Failed")) {
                    log.warn("{} TOTP by '{}' failed", getLogPrefix(), rapidIdentityContext.getUsername());
                    authenticationContext.getSubcontext(AuthenticationErrorContext.class,
                        true).getClassifiedErrors().add(AuthnEventIds.INVALID_CREDENTIALS);
                    ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.INVALID_CREDENTIALS);
                    return;
                } else {
                    log.error("{} unexpected TOTP error {}", getLogPrefix(), error);
                    ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.AUTHN_EXCEPTION);
                    return;
                }
            }

            /* XXX - This is returned when the user doesn't have TOTP configured, but if they
             * have PingMe configured they can still do TOTP. So, guess we ignore it.

            try {
                JsonObject setupObject = jsonData.getJsonObject("setup");

                if (setupObject != null) {
                    log.error("{} user TOTP not configured", getLogPrefix());
                    ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.AUTHN_EXCEPTION);
                    return;
                }
            }
            catch (final ClassCastException e) {
                log.error("{} setup not json object", getLogPrefix());
                ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.AUTHN_EXCEPTION);
                return;
            }
            */

            log.debug("{} proceeding to TOTP form", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, Events.TOTPForm.event(this));
        } else if (type.equals("pingMe")) {
            if (error != null) {
                if (error.equals("Authentication Failed")) {
                    log.warn("{} PingMe by '{}' failed", getLogPrefix(), rapidIdentityContext.getUsername());
                    authenticationContext.getSubcontext(AuthenticationErrorContext.class,
                        true).getClassifiedErrors().add(AuthnEventIds.INVALID_CREDENTIALS);
                    ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.INVALID_CREDENTIALS);
                    return;
                } else {
                    log.error("{} unexpected PingMe error {}", getLogPrefix(), error);
                    ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.AUTHN_EXCEPTION);
                    return;
                }
            }

            final JsonObject stepObject;
            try {
                stepObject = jsonData.getJsonObject("step");
            } catch (final ClassCastException e) {
                log.error("{} step not json object in api PingMe response", getLogPrefix());
                ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.AUTHN_EXCEPTION);
                return;
            }
            if (stepObject == null) {
                log.error("{} step not found in api PingMe response", getLogPrefix());
                ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.AUTHN_EXCEPTION);
                return;
            }

            final String stepType;
            try {
                stepType = stepObject.getString("type");
            } catch (final NullPointerException e) {
                log.error("{} step type not found in api PingMe response", getLogPrefix());
                ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.AUTHN_EXCEPTION);
                return;
            } catch (final ClassCastException e) {
                log.error("{} step type not string in api PingMe response", getLogPrefix());
                ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.AUTHN_EXCEPTION);
                return;
            }

            if (stepType.equals("chooseIdentity")) {
                Integer stepRetriesLeft = null;
                try {
                    stepRetriesLeft = stepObject.getInt("authenticationRetries");
                    log.debug("{} {} PingMe retries left", getLogPrefix(), stepRetriesLeft);
                } catch (final NullPointerException e) {
                    // not found
                } catch (final ClassCastException e) {
                    log.error("{} step authenticationRetries not int in api PingMe response", getLogPrefix());
                    ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.AUTHN_EXCEPTION);
                    return;
                }

                final JsonArray identitiesArray;
                try {
                    identitiesArray = stepObject.getJsonArray("identities");
                } catch (final ClassCastException e) {
                    log.error("{} step identities not json array in api PingMe response", getLogPrefix());
                    ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.AUTHN_EXCEPTION);
                    return;
                }
                if (identitiesArray == null) {
                    log.error("{} step identities not found in api PingMe response", getLogPrefix());
                    ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.AUTHN_EXCEPTION);
                    return;
                }

                if (identitiesArray.size() > 1) {
                    log.warn("{} multiple PingMe identities, defaulting to first one", getLogPrefix());
                    // XXX - do we need an intermediate page to let the user select one?
                }

                final JsonObject identityObject;
                try {
                    identityObject = identitiesArray.getJsonObject(0);
                } catch (final IndexOutOfBoundsException e) {
                    log.error("{} no entries in step identities in api PingMe response", getLogPrefix());
                    ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.AUTHN_EXCEPTION);
                    return;
                } catch (final ClassCastException e) {
                    log.error("{} step identities entry not json object in api PingMe response", getLogPrefix());
                    ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.AUTHN_EXCEPTION);
                    return;
                }

                final String identityUsername;
                try {
                    identityUsername = identityObject.getString("username");
                } catch (final NullPointerException e) {
                    log.error("{} step identities entry username not found in api PingMe response",
                        getLogPrefix());
                    ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.AUTHN_EXCEPTION);
                    return;
                } catch (final ClassCastException e) {
                    log.error("{} step identities entry username not string in api PingMe response",
                            getLogPrefix());
                    ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.AUTHN_EXCEPTION);
                    return;
                }

                log.debug("{} PingMe username = {}", getLogPrefix(), identityUsername);
                rapidIdentityContext.setPingMeUsername(identityUsername);

                String identityDomain = null;
                try {
                    identityDomain = identityObject.getString("domain");
                    log.debug("{} PingMe domain = {}", getLogPrefix(), identityDomain);
                    rapidIdentityContext.setPingMeDomain(identityDomain);
                } catch (final NullPointerException e) {
                    // not found
                } catch (final ClassCastException e) {
                    log.error("{} step identities entry domain not string in api PingMe response",
                            getLogPrefix());
                    ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.AUTHN_EXCEPTION);
                    return;
                }

              log.debug("{} proceeding to PingMe init", getLogPrefix());
                ActionSupport.buildEvent(profileRequestContext, Events.PingMeInitAPI.event(this));
            } else if (stepType.equals("authenticating")) {
                @Nonnull final long pingMeTimeLeft = rapidIdentityContext.pingMeTimeLeft();
                if (pingMeTimeLeft > 0) {
                    log.debug("{} {} seconds left before PingMe timeout", getLogPrefix(), pingMeTimeLeft);
                    ActionSupport.buildProceedEvent(profileRequestContext);
                } else {
                    log.warn("{} PingMe timed out");
                    authenticationContext.getSubcontext(AuthenticationErrorContext.class,
                        true).getClassifiedErrors().add(AuthnEventIds.INVALID_CREDENTIALS);
                    ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.INVALID_CREDENTIALS);
                    return;
                }
            } else {
                log.error("{} unknown step type {} in api PingMe response", getLogPrefix(), stepType);
                ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.AUTHN_EXCEPTION);
                return;
            }
        } else if (type.equals("policyChoice")) {
            final String cookiePolicy = rapidIdentityContext.getCookiePolicy();

            if (cookiePolicy != null) {
                log.debug("{} found policy {} in cookie", getLogPrefix(), cookiePolicy);
            }

            final JsonArray policiesArray;
            try {
                policiesArray = jsonData.getJsonArray("policies");
            } catch (final ClassCastException e) {
                log.error("{} policies not json array in api response", getLogPrefix());
                ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.AUTHN_EXCEPTION);
                return;
            }
            
            if (policiesArray == null) {
                log.error("{} policies array not found in api response", getLogPrefix());
                ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.AUTHN_EXCEPTION);
                return;
            }
            
            if (policiesArray.size() < 2) {
                log.error("{} policies array size less than 2", getLogPrefix());
                ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.AUTHN_EXCEPTION);
                return;
            }

            for (final javax.json.JsonValue jsonValue : policiesArray) {
                if (jsonValue.getValueType() != JsonValue.ValueType.OBJECT) {
                    log.error("{} policies array member not jsonObject ({})", getLogPrefix(),
                        jsonValue.getValueType());
                    ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.AUTHN_EXCEPTION);
                    return;
                }

                final JsonObject jsonValueObject = JsonObject.class.cast(jsonValue);

                String policyId = null;
                try {
                    policyId = jsonValueObject.getString("id");
                } catch (final NullPointerException e) {
                    log.error("{} policies array member missing id", getLogPrefix());
                    ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.AUTHN_EXCEPTION);
                    return;
                } catch (final ClassCastException e) {
                    log.error("{} policies array member not string",
                            getLogPrefix());
                    ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.AUTHN_EXCEPTION);
                    return;
                }

                String policyName = null;
                try {
                    policyName = jsonValueObject.getString("name");
                } catch (final NullPointerException e) {
                    log.error("{} policies array member missing name", getLogPrefix());
                    ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.AUTHN_EXCEPTION);
                    return;
                } catch (final ClassCastException e) {
                    log.error("{} policies array member name not string",
                            getLogPrefix());
                    ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.AUTHN_EXCEPTION);
                    return;
                }

                final JsonArray policyMethodsArray;
                try {
                    policyMethodsArray = jsonValueObject.getJsonArray("methods");
                } catch (final ClassCastException e) {
                    log.error("{} policies array member methods not json array", getLogPrefix());
                    ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.AUTHN_EXCEPTION);
                    return;
                }
                if (policiesArray == null) {
                    log.error("{} policies array member methods not found", getLogPrefix());
                    ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.AUTHN_EXCEPTION);
                    return;
                }

                final List<String> methods = new ArrayList<>();

                for (final javax.json.JsonValue jsonMethodValue : policyMethodsArray) {
                    if (jsonMethodValue.getValueType() != JsonValue.ValueType.OBJECT) {
                        log.error("{} policies array methods member not jsonObject ({})", getLogPrefix(),
                                jsonMethodValue.getValueType());
                        ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.AUTHN_EXCEPTION);
                        return;
                    }

                    final JsonObject jsonMethodValueObject = JsonObject.class.cast(jsonMethodValue);

                    final String methodType;
                    try {
                        methodType = jsonMethodValueObject.getString("type");
                    } catch (final NullPointerException e) {
                        log.error("{} policies array methods member type not found", getLogPrefix());
                        ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.AUTHN_EXCEPTION);
                        return;
                    } catch (final ClassCastException e) {
                        log.error("{} policies array methods member type not string", getLogPrefix());
                        ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.AUTHN_EXCEPTION);
                        return;
                    }

                    if (!supportedAuthMethods.contains(methodType)) {
                        log.error("{} policy {} ({}) contains unsupported method {}",
                            getLogPrefix(), policyId, policyName, methodType);
                        ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.AUTHN_EXCEPTION);
                        return;
                    }

                    methods.add(methodType);
                }

                log.debug("{} adding policy {} ({}) methods {}", getLogPrefix(), policyId,
                    policyName, methods);

                if (cookiePolicy != null && cookiePolicy.equals(policyId)) {
                    log.debug("{} cookie policy {} found",
                        getLogPrefix(), cookiePolicy);
                    rapidIdentityContext.setSelectedPolicy(policyId);
                }

                rapidIdentityContext.addAuthPolicy(new AuthPolicy(policyId, policyName, methods));
            }

            if (rapidIdentityContext.getSelectedPolicy() != null) {
                log.debug("{} proceeding directly to policy selection processing", getLogPrefix());
                ActionSupport.buildEvent(profileRequestContext, Events.PolicyAPI.event(this));
            } else {
                log.debug("{} proceeding to policy selection form", getLogPrefix());
                ActionSupport.buildEvent(profileRequestContext, Events.PolicyForm.event(this));
            }
        } else if (type.equals("complete")) {
            log.debug("{} proceeding to validate", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, Events.Validate.event(this));
        } else {
            log.error("{} unsupported type {}", getLogPrefix(), type);
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.AUTHN_EXCEPTION);
        }
    }
}
