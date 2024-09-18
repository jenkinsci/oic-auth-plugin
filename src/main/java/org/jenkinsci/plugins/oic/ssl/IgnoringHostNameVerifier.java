package org.jenkinsci.plugins.oic.ssl;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;
import jenkins.security.FIPS140;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;

/**
 * {@link HostnameVerifier} that accepts any presented hostanme including incorrect ones.
 */
@Restricted(NoExternalUse.class)
public final class IgnoringHostNameVerifier implements HostnameVerifier {

    public static final HostnameVerifier INSTANCE = new IgnoringHostNameVerifier();

    private IgnoringHostNameVerifier() {}

    @Override
    public boolean verify(String hostname, SSLSession session) {
        // hostnames must be validated in FIPS mode
        // outside of FIPS mode anything goes
        return !FIPS140.useCompliantAlgorithms();
    }
}
