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

package id.signet.idp.plugin.authn.rapididentity;

import java.io.IOException;

import net.shibboleth.idp.module.IdPModule;
import net.shibboleth.idp.module.ModuleException;
import net.shibboleth.idp.module.PropertyDrivenIdPModule;

/**
 * {@link IdPModule} implementation.
 */
public final class RapidIdentityModule extends PropertyDrivenIdPModule {

    /**
     * Constructor.
     *
     * @throws ModuleException on error
     * @throws IOException on error
     */
    public RapidIdentityModule() throws IOException, ModuleException {
        super(RapidIdentityModule.class);
    }

}
