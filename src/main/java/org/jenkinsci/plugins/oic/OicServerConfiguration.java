package org.jenkinsci.plugins.oic;

import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import hudson.ExtensionPoint;
import hudson.model.AbstractDescribableImpl;
import java.io.Serializable;

public abstract class OicServerConfiguration extends AbstractDescribableImpl<OicServerConfiguration>
        implements ExtensionPoint, Serializable {

    private static final long serialVersionUID = 1L;

    /**
     * Convert the OicServerConfiguration to {@link OIDCProviderMetadata} for use by the client.
     */
    public abstract OIDCProviderMetadata toProviderMetadata();
}
