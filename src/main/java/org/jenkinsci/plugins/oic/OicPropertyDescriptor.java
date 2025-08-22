package org.jenkinsci.plugins.oic;

import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.ExtensionList;
import hudson.ExtensionPoint;
import hudson.model.Descriptor;
import org.pac4j.oidc.config.OidcConfiguration;

public abstract class OicPropertyDescriptor extends Descriptor<OicProperty> implements ExtensionPoint {
    public static ExtensionList<OicPropertyDescriptor> all() {
        return ExtensionList.lookup(OicPropertyDescriptor.class);
    }

    /**
     * Allows the property to restrict its applicability depending on the context (for example, FIPS)
     */
    public boolean isApplicable() {
        return true;
    }

    /**
     * This method gets called if the property is not configured explicitly. For example, providing a default value.
     */
    public void getFallbackConfiguration(
            @NonNull OicServerConfiguration serverConfiguration, @NonNull OidcConfiguration configuration) {
        // no-op
    }
}
