package org.jenkinsci.plugins.oic;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import hudson.ProxyConfiguration;
import java.net.HttpURLConnection;
import java.net.UnknownHostException;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

@WithJenkins
class ProxyAwareResourceRetrieverTest {

    @Test
    void testOpenConnection_WithoutProxy(JenkinsRule r) throws Exception {
        r.jenkins.setProxy(null);

        ProxyAwareResourceRetriever retreiver = ProxyAwareResourceRetriever.createProxyAwareResourceRetriver(false);
        HttpURLConnection conn = retreiver.openHTTPConnection(r.getURL());
        assertNotNull(conn.getContent());
    }

    @Test
    void testOpenConnection_WithProxy(JenkinsRule r) throws Exception {
        r.jenkins.setProxy(new ProxyConfiguration("ignored.invalid", 8000));

        ProxyAwareResourceRetriever retreiver = ProxyAwareResourceRetriever.createProxyAwareResourceRetriver(false);
        HttpURLConnection conn = retreiver.openHTTPConnection(r.getURL());
        // should attempt to connect to the proxy which is ignored.invalid which can not be resolved and hence throw an
        // UnknownHostException
        assertThrows(UnknownHostException.class, conn::getContent);
    }

    @Test
    void testOpenConnection_WithProxyAndExclusion(JenkinsRule r) throws Exception {
        r.jenkins.setProxy(new ProxyConfiguration(
                "ignored.invalid", 8000, null, null, r.getURL().getHost()));

        ProxyAwareResourceRetriever retreiver = ProxyAwareResourceRetriever.createProxyAwareResourceRetriver(false);
        HttpURLConnection conn = retreiver.openHTTPConnection(r.getURL());
        assertNotNull(conn.getContent());
    }
}
