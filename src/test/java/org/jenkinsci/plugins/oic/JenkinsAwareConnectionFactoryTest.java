package org.jenkinsci.plugins.oic;

import static org.junit.Assert.assertNotNull;

import hudson.ProxyConfiguration;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import jenkins.model.Jenkins;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;

public class JenkinsAwareConnectionFactoryTest {

    private JenkinsAwareConnectionFactory factory = new JenkinsAwareConnectionFactory();

    @Rule
    public JenkinsRule jenkinsRule = new JenkinsRule();

    @Test
    public void testOpenConnection_WithNullProxy() throws ClassCastException, IOException {
        Jenkins.getInstance().proxy = null;
        URL url = new URL("http://localhost");
        HttpURLConnection conn = factory.openConnection(url);
        assertNotNull(conn);
    }

    @Test
    public void testOpenConnection_WithProxy() throws ClassCastException, IOException {
        Jenkins.getInstance().proxy = new ProxyConfiguration("someHost", 8000);
        URL url = new URL("http://localhost");
        HttpURLConnection conn = factory.openConnection(url);
        assertNotNull(conn);
    }
}
