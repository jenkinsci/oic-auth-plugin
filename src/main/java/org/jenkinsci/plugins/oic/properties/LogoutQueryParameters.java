package org.jenkinsci.plugins.oic.properties;

import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import java.util.ArrayList;
import java.util.List;
import org.jenkinsci.plugins.oic.LogoutQueryParameter;
import org.jenkinsci.plugins.oic.OicProperty;
import org.jenkinsci.plugins.oic.OicPropertyDescriptor;
import org.kohsuke.stapler.DataBoundConstructor;

public class LogoutQueryParameters extends OicProperty {
    @NonNull
    private final List<LogoutQueryParameter> items;

    @DataBoundConstructor
    public LogoutQueryParameters(@CheckForNull List<LogoutQueryParameter> items) {
        this.items = items == null ? List.of() : new ArrayList<>(items);
    }

    @NonNull
    @Override
    public List<LogoutQueryParameter> contributeLogoutQueryParameters() {
        return items;
    }

    @Extension
    public static class DescriptorImpl extends OicPropertyDescriptor {
        @NonNull
        @Override
        public String getDisplayName() {
            return Messages.LogoutQueryParameters_DisplayName();
        }
    }
}
