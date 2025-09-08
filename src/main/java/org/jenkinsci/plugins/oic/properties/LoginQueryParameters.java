package org.jenkinsci.plugins.oic.properties;

import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.model.Descriptor;
import java.util.ArrayList;
import java.util.List;
import org.jenkinsci.plugins.oic.LoginQueryParameter;
import org.jenkinsci.plugins.oic.OicPropertyExecution;
import org.jenkinsci.plugins.oic.OicServerConfiguration;
import org.jenkinsci.plugins.oic.OidcProperty;
import org.jenkinsci.plugins.oic.OidcPropertyDescriptor;
import org.kohsuke.stapler.DataBoundConstructor;
import org.pac4j.oidc.config.OidcConfiguration;

/**
 * Allows the addition of custom query parameters to the login request.
 */
public class LoginQueryParameters extends OidcProperty {
    @NonNull
    private List<LoginQueryParameter> items;

    @DataBoundConstructor
    public LoginQueryParameters(@CheckForNull List<LoginQueryParameter> items) throws Descriptor.FormException {
        if (items == null || items.isEmpty()) {
            throw new Descriptor.FormException("There must be at least one login query parameter defined", "items");
        }
        this.items = new ArrayList<>(items);
    }

    public List<LoginQueryParameter> getItems() {
        return items;
    }

    @NonNull
    @Override
    public OicPropertyExecution newExecution(@NonNull OicServerConfiguration serverConfiguration) {
        return new ExecutionImpl(items);
    }

    private record ExecutionImpl(@NonNull List<LoginQueryParameter> items) implements OicPropertyExecution {
        @Override
        public void customizeConfiguration(@NonNull OidcConfiguration configuration) {
            for (LoginQueryParameter lqp : items) {
                configuration.addCustomParam(lqp.getKey(), lqp.getValue());
            }
        }
    }

    @Extension
    public static class DescriptorImpl extends OidcPropertyDescriptor {
        @NonNull
        @Override
        public String getDisplayName() {
            return Messages.LoginQueryParameters_DisplayName();
        }
    }
}
