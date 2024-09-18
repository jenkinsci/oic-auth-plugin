package org.jenkinsci.plugins.oic;

import com.nimbusds.jose.util.DefaultResourceRetriever;
import com.nimbusds.jose.util.ResourceRetriever;
import hudson.ProxyConfiguration;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Map;
import javax.net.ssl.HttpsURLConnection;
import jenkins.security.FIPS140;
import jenkins.util.SystemProperties;
import org.jenkinsci.plugins.oic.ssl.IgnoringHostNameVerifier;
import org.jenkinsci.plugins.oic.ssl.TLSUtils;
import org.pac4j.core.context.HttpConstants;

/**
 * A {@link ResourceRetriever} that is configured with sane connection/timeout defaults and the Jenkins proxy.
 */
class ProxyAwareResourceRetriever extends DefaultResourceRetriever {

    @SuppressWarnings("boxing")
    private static final int CONNECTION_TIMEOUT_MS = SystemProperties.getInteger("OIC_CONNECTION_TIMEOUT_MS", 2_000);

    @SuppressWarnings("boxing")
    private static final int READ_TIMEOUT_MS = SystemProperties.getInteger("OIC_CONNECTION_READ_TIMEOUT_MS", 5_000);

    @SuppressWarnings("boxing")
    private static final int SIZE_LIMIT = SystemProperties.getInteger("OIC_CONNECTION_SIZE_LIMIT", 0);

    private final boolean disableTLSValidation;

    private ProxyAwareResourceRetriever(boolean disableTLSValidation)
            throws KeyManagementException, NoSuchAlgorithmException {
        super(
                CONNECTION_TIMEOUT_MS,
                READ_TIMEOUT_MS,
                SIZE_LIMIT,
                true,
                disableTLSValidation ? TLSUtils.createAnythingGoesSSLSocketFactory() : null);
        this.disableTLSValidation = disableTLSValidation;
        // set the same default headers as the in the default client should a resolver not be specified
        // https://github.com/pac4j/pac4j/blob/pac4j-parent-5.7.7/pac4j-oidc/src/main/java/org/pac4j/oidc/config/OidcConfiguration.java#L179-L193
        setHeaders(Map.of(HttpConstants.ACCEPT_HEADER, List.of(HttpConstants.APPLICATION_JSON)));
    }

    @Override
    protected HttpURLConnection openHTTPConnection(URL url) throws IOException {
        @SuppressWarnings("deprecation")
        HttpURLConnection con = (HttpURLConnection) ProxyConfiguration.open(url);
        if (disableTLSValidation && con instanceof HttpsURLConnection) {
            ((HttpsURLConnection) con).setHostnameVerifier(IgnoringHostNameVerifier.INSTANCE);
        }
        return con;
    }

    /**
     * Create a ResourceRetriver that uses the Jenkins ProxyConfiguration.
     * @param disableTLSValidation {@code true} if we want to trust all certificates
     */
    static ProxyAwareResourceRetriever createProxyAwareResourceRetriver(boolean disableTLSValidation) {
        if (FIPS140.useCompliantAlgorithms() && disableTLSValidation) {
            throw new IllegalArgumentException("Can not disable TLS validation when running Jenkins in FIPS 140 mode");
        }
        try {
            return new ProxyAwareResourceRetriever(disableTLSValidation);
        } catch (KeyManagementException | NoSuchAlgorithmException e) {
            // we are not using a keystore so KeyManagementException should never be thrown
            // "TLS" is mandated by the spec.
            throw new IllegalStateException("Could not construct the ProxyAwareResourceRetriver", e);
        }
    }
}
