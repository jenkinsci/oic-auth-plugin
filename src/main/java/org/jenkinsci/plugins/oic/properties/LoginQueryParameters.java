package org.jenkinsci.plugins.oic.properties;

import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import java.util.ArrayList;
import java.util.List;
import org.jenkinsci.plugins.oic.LoginQueryParameter;
import org.jenkinsci.plugins.oic.OicProperty;
import org.jenkinsci.plugins.oic.OicPropertyDescriptor;
import org.jenkinsci.plugins.oic.OicPropertyExecution;
import org.jenkinsci.plugins.oic.OicServerConfiguration;
import org.kohsuke.stapler.DataBoundConstructor;
import org.pac4j.oidc.config.OidcConfiguration;

/**
 * Allows the addition of custom query parameters to the login request.
 */
public class LoginQueryParameters extends OicProperty {
    @NonNull
    private List<LoginQueryParameter> items;

    @DataBoundConstructor
    public LoginQueryParameters(@CheckForNull List<LoginQueryParameter> items) {
        this.items = items == null ? List.of() : new ArrayList<>(items);
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
    public static class DescriptorImpl extends OicPropertyDescriptor {
        @NonNull
        @Override
        public String getDisplayName() {
            return Messages.LoginQueryParameters_DisplayName();
        }
    }
}
