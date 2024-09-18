package org.jenkinsci.plugins.oic.ssl;

import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import jenkins.security.FIPS140;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;

@Restricted(NoExternalUse.class)
public class TLSUtils {

    /**
     * Construct an {@link SSLSocketFactory} that trust all certificates using "TLS".
     */
    public static SSLSocketFactory createAnythingGoesSSLSocketFactory()
            throws KeyManagementException, NoSuchAlgorithmException {
        if (FIPS140.useCompliantAlgorithms()) {
            throw new IllegalStateException(
                    "createAnythingGoesSSLSocketFactory is not supported when running in FIPS mode");
        }
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, new TrustManager[] {AnythingGoesTrustManager.INSTANCE}, new SecureRandom());
        return sslContext.getSocketFactory();
    }
}
