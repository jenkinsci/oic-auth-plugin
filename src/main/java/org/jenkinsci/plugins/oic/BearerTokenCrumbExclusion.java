package org.jenkinsci.plugins.oic;

import hudson.Extension;
import hudson.security.csrf.CrumbExclusion;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

@Extension
public class BearerTokenCrumbExclusion extends CrumbExclusion {

    @Override
    public boolean process(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        if (Boolean.TRUE.equals(request.getAttribute(BearerTokenCrumbExclusion.class.getName()))) {
            chain.doFilter(request, response);
            return true;
        }
        return false;
    }

}
