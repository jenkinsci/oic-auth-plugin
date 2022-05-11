package org.jenkinsci.plugins.oic;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;

import org.eclipse.jetty.server.Request;
import org.junit.Test;

public class EscapeHatchCrumbExclusionTest {
    private EscapeHatchCrumbExclusion crumb = new EscapeHatchCrumbExclusion();

    @Test
    public void process_WithNullPath() throws IOException, ServletException {
        HttpServletResponse response = null;
        FilterChain chain = null;

        Request request = new Request(null, null);
        assertFalse(crumb.process(request, response, chain));
    }

    @Test
    public void process_WithWrongPath() throws IOException, ServletException {
        HttpServletResponse response = null;
        FilterChain chain = null;

        Request request = new Request(null, null);
        request.setPathInfo("fictionalPath");
        assertFalse(crumb.process(request, response, chain));
    }

    @Test
    public void process_WithGoodPath() throws IOException, ServletException {
        HttpServletResponse response = null;
        FilterChain chain = new FilterChain() {

            @Override
            public void doFilter(ServletRequest arg0, ServletResponse arg1) throws IOException, ServletException {
                // do nothing
            }
        };

        Request request = new Request(null, null);
        request.setPathInfo("/securityRealm/escapeHatch");
        assertTrue(crumb.process(request, response, chain));
    }
}