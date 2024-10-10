package org.jenkinsci.plugins.oic;

import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import hudson.ProxyConfiguration;
import java.net.Proxy;
import java.net.http.HttpRequest;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import jenkins.model.Jenkins;
import jenkins.security.FIPS140;
import org.jenkinsci.plugins.oic.ssl.IgnoringHostNameVerifier;
import org.jenkinsci.plugins.oic.ssl.TLSUtils;
import org.pac4j.oidc.config.OidcConfiguration;

/**
 * An OidcConfiguration that will customize {@link HttpRequest} with the Jenkins proxy, and iff TLS is disabled a lenient {@link HostnameVerifier} and {@link SSLContext}.
 */
class CustomOidcConfiguration extends OidcConfiguration {

    private final boolean disableTLS;

    CustomOidcConfiguration(boolean disableTLS) {
        this.disableTLS = disableTLS;
        if (FIPS140.useCompliantAlgorithms() && disableTLS) {
            throw new IllegalStateException("Cannot disable TLS validation in FIPS-140 mode");
        }
    }

    @Override
    public void configureHttpRequest(HTTPRequest request) {
        Proxy proxy = null;
        Jenkins jenkins = Jenkins.getInstanceOrNull();
        if (jenkins != null) { // unit tests
            ProxyConfiguration pc = jenkins.getProxy();
            if (pc != null) {
                proxy = pc.createProxy(request.getURL().getHost());
            }
        }
        request.setProxy(proxy);
        if (disableTLS) {
            request.setHostnameVerifier(IgnoringHostNameVerifier.INSTANCE);
            try {
                request.setSSLSocketFactory(TLSUtils.createAnythingGoesSSLSocketFactory());
            } catch (KeyManagementException | NoSuchAlgorithmException e) {
                throw new IllegalStateException("could not configure the SSLFactory, this should not be possible", e);
            }
        }
        super.configureHttpRequest(request);
    }
}
