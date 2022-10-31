package org.jenkinsci.plugins.oic;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import org.junit.Test;

import static org.junit.Assert.assertNotNull;

public class JenkinsAwareConnectionFactoryTest2 {

    private JenkinsAwareConnectionFactory factory = new JenkinsAwareConnectionFactory();

    @Test
    public void testOpenConnection_WithNullJenkins() throws ClassCastException, IOException {
        URL url = new URL("http://localhost");
        HttpURLConnection conn = factory.openConnection(url);
        assertNotNull(conn);
    }
}

