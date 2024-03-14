package org.jenkinsci.plugins.oic;

import java.io.IOException;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;
import org.eclipse.jetty.server.Request;
import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class EscapeHatchCrumbExclusionTest {
    private EscapeHatchCrumbExclusion crumb = new EscapeHatchCrumbExclusion();

    private HttpServletResponse response = null;

    private FilterChain chain = null;

	private Request newRequestWithPath(String requestPath) {
        return new Request(null, null) {
            @Override
            public String getPathInfo() {
                return requestPath;
            }
        };
	}


    @Test
    public void process_WithNullPath() throws IOException, ServletException {
        Request request = new Request(null, null);
        assertFalse(crumb.process(request, response, chain));
    }

    @Test
    public void process_WithWrongPath() throws IOException, ServletException {
        Request request = newRequestWithPath("fictionalPath");
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

        Request request = newRequestWithPath("/securityRealm/escapeHatch");
        assertTrue(crumb.process(request, response, chain));
    }
}
