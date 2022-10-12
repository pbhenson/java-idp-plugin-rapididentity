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

import java.util.List;
import javax.annotation.Nonnull;
import net.shibboleth.utilities.java.support.annotation.constraint.NonnullAfterInit;

/**
 * Class to hold info for a RapidIdentity API authentication policy.
 */
public class AuthPolicy {

    /** RapidIdentity policy id. */
    @NonnullAfterInit private String id;

    /** RapidIdentity policy name. */
    @NonnullAfterInit private String name;

    /** Auth methods in policy. */
    @NonnullAfterInit private List<String> methods;

    /** Constructor.
     *
     * @param setId id of the policy
     * @param setName name of the policy
     * @param setMethods methods required by the policy
     */
    public AuthPolicy(@Nonnull final String setId, @Nonnull final String setName,
            @Nonnull final List<String> setMethods) {
        id = setId;
        name = setName;
        methods = setMethods;
    }

    /**
     * Get the auth policy id.
     *
     * @return auth policy id
     */
    @Nonnull public String getId() {
        return id;
    }

    /**
     * Get the auth policy name.
     *
     * @return auth policy name
     */
    @Nonnull public String getName() {
        return name;
    }

    /**
     * Get the auth methods.
     *
     * @return auth policy methods
     */
    @Nonnull public String[] getMethods() {
        return methods.toArray(new String[methods.size()]);
    }
}
