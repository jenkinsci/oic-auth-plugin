package org.jenkinsci.plugins.oic;

import static org.junit.Assert.assertNotNull;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;

import org.junit.Test;

public class JenkinsAwareConnectionFactoryTest2 {

    private JenkinsAwareConnectionFactory factory = new JenkinsAwareConnectionFactory();

    @Test
    public void testOpenConnection_WithNullJenkins() throws ClassCastException, IOException {
        URL url = new URL("http://localhost");
        HttpURLConnection conn = factory.openConnection(url);
        assertNotNull(conn);
    }
}

