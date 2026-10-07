package org.jenkinsci.plugins.oic;

import hudson.Extension;
import hudson.model.Descriptor.FormException;
import hudson.util.FormValidation;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.verb.POST;
import org.pac4j.oidc.config.OidcConfiguration;

public class LoginQueryParameter extends AbstractQueryParameter<LoginQueryParameter> {

    @DataBoundConstructor
    public LoginQueryParameter(String key, String value) throws FormException {
        super(key, value);
    }

    @Extension
    public static class DescriptorImpl extends AbstractKeyValueDescribable.DescriptorImpl<LoginQueryParameter> {

        @POST
        @Override
        public FormValidation doCheckKey(@QueryParameter String key) {
            if (key == null || key.trim().isEmpty()) {
                return FormValidation.error("key must not be blank");
            }
            // These keys are set on the authorization request by pac4j itself, so overriding them
            // through a login query parameter would conflict. `prompt` is intentionally NOT reserved:
            // pac4j only sets it for its forceAuthn (prompt=login) and passive (prompt=none) modes,
            // neither of which this plugin configures, so an operator-supplied `prompt` (for example
            // `prompt=consent`, required to obtain Google offline-access refresh tokens) cannot clash.
            return switch (key.trim()) {
                case OidcConfiguration.SCOPE,
                        OidcConfiguration.RESPONSE_TYPE,
                        OidcConfiguration.RESPONSE_MODE,
                        OidcConfiguration.REDIRECT_URI,
                        OidcConfiguration.CLIENT_ID,
                        OidcConfiguration.STATE,
                        OidcConfiguration.MAX_AGE,
                        OidcConfiguration.NONCE,
                        OidcConfiguration.CODE_CHALLENGE,
                        OidcConfiguration.CODE_CHALLENGE_METHOD -> FormValidation.error(key + " is a reserved word");
                default -> FormValidation.ok();
            };
        }

        @POST
        @Override
        public FormValidation doCheckValue(String value) {
            return FormValidation.ok();
        }
    }
}
