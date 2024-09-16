package org.jenkinsci.plugins.oic;

import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.ExtensionPoint;
import hudson.model.AbstractDescribableImpl;
import java.io.Serializable;
import org.jenkinsci.plugins.oic.OicSecurityRealm.TokenAuthMethod;

public abstract class OicServerConfiguration extends AbstractDescribableImpl<OicServerConfiguration>
        implements ExtensionPoint, Serializable {

    private static final long serialVersionUID = 1L;

    @NonNull
    public abstract String getTokenServerUrl();

    @NonNull
    public abstract String getJwksServerUrl();

    @NonNull
    public abstract String getAuthorizationServerUrl();

    @CheckForNull
    public abstract String getUserInfoServerUrl();

    @NonNull
    public abstract String getScopes();

    @NonNull
    public abstract TokenAuthMethod getTokenAuthMethod();

    @CheckForNull
    public abstract String getEndSessionUrl();

    public abstract boolean isUseRefreshTokens();
}
