package org.jenkinsci.plugins.oic.ssl;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import javax.net.ssl.X509TrustManager;
import jenkins.security.FIPS140;

final class AnythingGoesTrustManager implements X509TrustManager {

    static final X509TrustManager INSTANCE = new AnythingGoesTrustManager();

    private AnythingGoesTrustManager() {}

    @Override
    public void checkClientTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
        if (FIPS140.useCompliantAlgorithms()) {
            throw new CertificateException("can not bypass certificate checking in FIPS mode");
        }
    }

    @Override
    public void checkServerTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
        if (FIPS140.useCompliantAlgorithms()) {
            throw new CertificateException("can not bypass certificate checking in FIPS mode");
        }
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return new X509Certificate[0];
    }
}
