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
import org.springframework.webflow.execution.Event;

/**
 * RapidIdentity authentication flow events.
 *
 */
public enum Events {

    /** Process username API call. */
    UsernameAPI,

    /** Display TOTP form. */
    TOTPForm,

    /** Process TOTP auth. */
    TOTPAPI,

    /** Initiate PingMe auth. */
    PingMeInitAPI,

    /** Display Policy Choice form. */
    PolicyForm,

    /** Process Policy Choice. */
    PolicyAPI,

    /** Final validation and population of auth context. */
    Validate;

    /**
     * Creates a Spring webflow event whose ID is given by {@link #name()}.
     *
     * @param source Event source.
     *
     * @return Spring webflow event.
     */
    @Nonnull public Event event(final Object source) {
        return new Event(source, name());
    }
}
