/*
 * The MIT License
 *
 * Copyright (c) 2016  Michael Bischoff & GeriMedica - www.gerimedica.nl
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package org.jenkinsci.plugins.oic;

import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.ExtensionPoint;
import hudson.model.AbstractDescribableImpl;
import java.io.Serializable;
import org.pac4j.oidc.config.OidcConfiguration;

/**
 * Extension point defining how the {@link OicSecurityRealm} authenticates itself to the OpenID
 * Connect provider's token endpoint, e.g. using a client secret or a JWT bearer assertion.
 */
public abstract class OicClientAuthentication extends AbstractDescribableImpl<OicClientAuthentication>
        implements ExtensionPoint, Serializable {

    private static final long serialVersionUID = 1L;

    /**
     * Configure the client secret / authentication method needed to authenticate to the token
     * endpoint on the given {@link OidcConfiguration}.
     */
    protected abstract void configure(@NonNull OidcConfiguration oidcConfiguration);

    /**
     * Allows further customization of the fully built {@link OidcConfiguration}, once all
     * {@link OidcProperty} customizations have been applied. Most implementations do not need to
     * override this; the default is a no-op.
     *
     * @param clientId the OAuth2 client id configured on the {@link OicSecurityRealm}
     */
    protected void customizeOidcConfiguration(
            @NonNull OidcConfiguration oidcConfiguration,
            @NonNull OicServerConfiguration serverConfiguration,
            @NonNull String clientId) {
        // no-op by default
    }
}
