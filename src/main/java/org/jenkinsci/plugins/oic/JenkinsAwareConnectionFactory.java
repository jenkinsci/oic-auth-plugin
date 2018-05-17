package org.jenkinsci.plugins.oic;

import com.google.api.client.http.javanet.ConnectionFactory;
import com.google.common.base.Preconditions;
import hudson.ProxyConfiguration;
import jenkins.model.Jenkins;

import javax.annotation.Nonnull;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;

/**
 * This Factory for {@link HttpURLConnection} honors the jenkins (proxy) settings when creating connections
 *
 * @see com.google.api.client.http.javanet.DefaultConnectionFactory
 * This class uses, instead of a proxy object passed to the constructor, the jenkins {@link ProxyConfiguration} (Jenkins.getInstance().proxy) settings when available.
 */
public class JenkinsAwareConnectionFactory implements ConnectionFactory {

    public JenkinsAwareConnectionFactory() {}

    @Override
    public HttpURLConnection openConnection(@Nonnull URL url) throws IOException, ClassCastException {
        Jenkins jenkins = Jenkins.getInstance();
        if(jenkins != null){
            ProxyConfiguration proxyConfig = jenkins.proxy;
            if (proxyConfig != null) {
                return (HttpURLConnection) url.openConnection(proxyConfig.createProxy(url.getHost()));
            }
        }
        return (HttpURLConnection) url.openConnection();
    }
}
