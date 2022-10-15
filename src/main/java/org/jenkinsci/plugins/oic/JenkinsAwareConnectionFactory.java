package org.jenkinsci.plugins.oic;

import com.google.api.client.http.javanet.ConnectionFactory;
import hudson.ProxyConfiguration;
import jenkins.model.Jenkins;

import edu.umd.cs.findbugs.annotations.NonNull;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;

/**
 * This Factory for {@link HttpURLConnection} honors the jenkins (proxy) settings when creating connections
 *
 * @see com.google.api.client.http.javanet.DefaultConnectionFactory
 * This class uses, instead of a proxy object passed to the constructor, the jenkins {@link ProxyConfiguration} (Jenkins.getInstance().proxy) settings when available.
 * @author Michael Bischoff
 */
public class JenkinsAwareConnectionFactory implements ConnectionFactory {

    public JenkinsAwareConnectionFactory() {}

    @Override
    public HttpURLConnection openConnection(@NonNull URL url) throws IOException, ClassCastException {
        Jenkins jenkins = Jenkins.get();
        if(jenkins != null){
            ProxyConfiguration proxyConfig = jenkins.proxy;
            if (proxyConfig != null) {
                return (HttpURLConnection) url.openConnection(proxyConfig.createProxy(url.getHost()));
            }
        }
        return (HttpURLConnection) url.openConnection();
    }
}
