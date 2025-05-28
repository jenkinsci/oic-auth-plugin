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

    public boolean isApplicable() {
        return true;
    }

    public void getFallbackConfiguration(
            @NonNull OicServerConfiguration serverConfiguration, @NonNull OidcConfiguration configuration) {
        // no-op
    }
}
