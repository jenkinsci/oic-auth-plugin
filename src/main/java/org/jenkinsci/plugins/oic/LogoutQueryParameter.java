package org.jenkinsci.plugins.oic;

import hudson.Extension;
import hudson.model.Descriptor.FormException;
import hudson.util.FormValidation;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.verb.POST;

public class LogoutQueryParameter extends AbstractQueryParameter<LogoutQueryParameter> {

    @DataBoundConstructor
    public LogoutQueryParameter(String key, String value) throws FormException {
        super(key, value, true);
    }

    @Extension
    public static class DescriptorImpl extends AbstractKeyValueDescribable.DescriptorImpl<LogoutQueryParameter> {

        @POST
        @Override
        public FormValidation doCheckKey(@QueryParameter String key) {
            return switch (key.trim()) {
                case "id_token_hint", "state", "post_logout_redirect_uri" ->
                    FormValidation.error(key + " is a reserved word");
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
