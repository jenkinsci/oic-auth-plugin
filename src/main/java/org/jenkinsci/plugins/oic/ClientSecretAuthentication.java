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
import hudson.Extension;
import hudson.Util;
import hudson.model.Descriptor;
import hudson.util.FormValidation;
import hudson.util.Secret;
import jenkins.model.Jenkins;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.interceptor.RequirePOST;
import org.pac4j.oidc.config.OidcConfiguration;

/**
 * Authenticates to the token endpoint using a shared client secret (the classic OAuth2
 * {@code client_secret} authentication).
 */
public class ClientSecretAuthentication extends OicClientAuthentication {

    private static final long serialVersionUID = 1L;

    private static final String NO_SECRET = "none";

    private final Secret clientSecret;

    @DataBoundConstructor
    public ClientSecretAuthentication(Secret clientSecret) {
        this.clientSecret = clientSecret;
    }

    @NonNull
    public Secret getClientSecret() {
        return clientSecret == null ? Secret.fromString(NO_SECRET) : clientSecret;
    }

    @Override
    protected void configure(@NonNull OidcConfiguration oidcConfiguration) {
        oidcConfiguration.setSecret(getClientSecret().getPlainText());
    }

    @Extension
    @Symbol("secret")
    public static class DescriptorImpl extends Descriptor<OicClientAuthentication> {

        @Override
        public String getDisplayName() {
            return Messages.ClientSecretAuthentication_DisplayName();
        }

        @RequirePOST
        public FormValidation doCheckClientSecret(@QueryParameter String clientSecret) {
            Jenkins.get().checkPermission(Jenkins.ADMINISTER);
            if (Util.fixEmptyAndTrim(clientSecret) == null) {
                return FormValidation.error(Messages.OicSecurityRealm_ClientSecretRequired());
            }
            return FormValidation.ok();
        }
    }
}
