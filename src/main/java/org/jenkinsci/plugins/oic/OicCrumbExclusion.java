package org.jenkinsci.plugins.oic;

import hudson.Extension;
import hudson.security.SecurityRealm;
import hudson.security.csrf.CrumbExclusion;
import java.io.IOException;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import jenkins.model.Jenkins;

/**
 * Crumb exclusion to allow POSTing to {@link OicSecurityRealm#doFinishLogin(org.kohsuke.stapler.StaplerRequest, org.kohsuke.stapler.StaplerResponse)}
 */
@Extension
public class OicCrumbExclusion extends CrumbExclusion {

    @Override
    public boolean process(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        Jenkins j = Jenkins.getInstanceOrNull();
        if (j != null) {
            SecurityRealm sr = j.getSecurityRealm();
            if (sr instanceof OicSecurityRealm) {
                if ("/securityRealm/finishLogin".equals(request.getPathInfo())) {
                    chain.doFilter(request, response);
                    return true;
                }
            }
        }
        return false;
    }
}
