package org.jenkinsci.plugins.oic;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class EscapeHatchCrumbExclusionTest {
    private EscapeHatchCrumbExclusion crumb = new EscapeHatchCrumbExclusion();

    private HttpServletResponse response = null;

    private FilterChain chain = null;

    private MockHttpServletRequest newRequestWithPath(String requestPath) {
        return new MockHttpServletRequest() {
            @Override
            public String getPathInfo() {
                return requestPath;
            }
        };
    }

    @Test
    public void process_WithNullPath() throws IOException, ServletException {
        MockHttpServletRequest request = newRequestWithPath("");
        assertFalse(crumb.process(request, response, chain));
    }

    @Test
    public void process_WithWrongPath() throws IOException, ServletException {
        MockHttpServletRequest request = newRequestWithPath("fictionalPath");
        assertFalse(crumb.process(request, response, chain));
    }

    @Test
    public void process_WithGoodPath() throws IOException, ServletException {
        chain = new FilterChain() {
            @Override
            public void doFilter(ServletRequest arg0, ServletResponse arg1) throws IOException, ServletException {
                // do nothing
            }
        };

        MockHttpServletRequest request = newRequestWithPath("/securityRealm/escapeHatch");
        assertTrue(crumb.process(request, response, chain));
    }
}
