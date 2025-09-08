package org.jenkinsci.plugins.oic.properties;

import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import java.util.ArrayList;
import java.util.List;
import org.jenkinsci.plugins.oic.LogoutQueryParameter;
import org.jenkinsci.plugins.oic.OidcProperty;
import org.jenkinsci.plugins.oic.OidcPropertyDescriptor;
import org.kohsuke.stapler.DataBoundConstructor;

/**
 * Allows the addition of custom query parameters to the logout request.
 */
public class LogoutQueryParameters extends OidcProperty {
    @NonNull
    private final List<LogoutQueryParameter> items;

    @DataBoundConstructor
    public LogoutQueryParameters(@CheckForNull List<LogoutQueryParameter> items) {
        this.items = items == null ? List.of() : new ArrayList<>(items);
    }

    @NonNull
    public List<LogoutQueryParameter> getItems() {
        return items;
    }

    @NonNull
    @Override
    public List<LogoutQueryParameter> contributeLogoutQueryParameters() {
        return items;
    }

    @Extension
    public static class DescriptorImpl extends OidcPropertyDescriptor {
        @NonNull
        @Override
        public String getDisplayName() {
            return Messages.LogoutQueryParameters_DisplayName();
        }
    }
}
