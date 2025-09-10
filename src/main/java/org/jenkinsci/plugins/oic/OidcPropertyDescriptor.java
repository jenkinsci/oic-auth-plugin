package org.jenkinsci.plugins.oic;

import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.ExtensionList;
import hudson.ExtensionPoint;
import hudson.model.Descriptor;
import org.pac4j.oidc.config.OidcConfiguration;

public abstract class OidcPropertyDescriptor extends Descriptor<OidcProperty> implements ExtensionPoint {
    public static ExtensionList<OidcPropertyDescriptor> all() {
        return ExtensionList.lookup(OidcPropertyDescriptor.class);
    }

    /**
     * This method gets called if the property is not configured explicitly. For example, providing a default value.
     */
    public void getFallbackConfiguration(
            @NonNull OicServerConfiguration serverConfiguration, @NonNull OidcConfiguration configuration) {
        // no-op
    }
}
