package org.jenkinsci.plugins.oic;

import hudson.ProxyConfiguration;
import java.net.HttpURLConnection;
import java.net.UnknownHostException;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;

import static org.junit.Assert.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class ProxyAwareResourceRetrieverTest {

    @Rule
    public JenkinsRule jr = new JenkinsRule();

    @Test
    public void testOpenConnection_WithoutProxy() throws Exception {
        jr.jenkins.setProxy(null);

        ProxyAwareResourceRetriever retreiver = ProxyAwareResourceRetriever.createProxyAwareResourceRetriver(false);
        HttpURLConnection conn = retreiver.openHTTPConnection(jr.getURL());
        assertNotNull(conn.getContent());
    }

    @Test
    public void testOpenConnection_WithProxy() throws Exception {
        jr.jenkins.setProxy(new ProxyConfiguration("ignored.invalid", 8000));

        ProxyAwareResourceRetriever retreiver = ProxyAwareResourceRetriever.createProxyAwareResourceRetriver(false);
        HttpURLConnection conn = retreiver.openHTTPConnection(jr.getURL());
        // should attempt to connect to the proxy which is ignored.invalid which can not be resolved and hence throw an
        // UnknownHostException
        assertThrows(UnknownHostException.class, () -> conn.getContent());
    }

    @Test
    public void testOpenConnection_WithProxyAndExclusion() throws Exception {
        jr.jenkins.setProxy(new ProxyConfiguration(
                "ignored.invalid", 8000, null, null, jr.getURL().getHost()));

        ProxyAwareResourceRetriever retreiver = ProxyAwareResourceRetriever.createProxyAwareResourceRetriver(false);
        HttpURLConnection conn = retreiver.openHTTPConnection(jr.getURL());
        assertNotNull(conn.getContent());
    }
}
