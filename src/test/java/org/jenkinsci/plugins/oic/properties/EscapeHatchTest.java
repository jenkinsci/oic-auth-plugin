package org.jenkinsci.plugins.oic.properties;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import hudson.util.Secret;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.jenkinsci.plugins.oic.MockHttpServletRequest;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCrypt;

class EscapeHatchTest {
    private EscapeHatch.CrumbExclusionImpl crumb = new EscapeHatch.CrumbExclusionImpl();

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
    void process_WithNullPath() throws IOException, ServletException {
        MockHttpServletRequest request = newRequestWithPath("");
        assertFalse(crumb.process(request, response, chain));
    }

    @Test
    void process_WithWrongPath() throws IOException, ServletException {
        MockHttpServletRequest request = newRequestWithPath("fictionalPath");
        assertFalse(crumb.process(request, response, chain));
    }

    @Test
    void process_WithGoodPath() throws IOException, ServletException {
        chain = (arg0, arg1) -> {
            // do nothing
        };

        MockHttpServletRequest request = newRequestWithPath("/securityRealm/escapeHatch");
        assertTrue(crumb.process(request, response, chain));
    }

    @Test
    void testShouldCheckEscapeHatchWithPlainPassword() throws Exception {
        final String escapeHatchUsername = "aUsername";
        final String escapeHatchPassword = "aSecretPassword";
        var escapeHatch = new EscapeHatch(escapeHatchUsername, null, Secret.fromString(escapeHatchPassword));
        assertEquals(escapeHatchUsername, escapeHatch.getUsername());
        assertNotEquals(escapeHatchPassword, Secret.toString(escapeHatch.getSecret()));
        assertTrue(escapeHatch.check(escapeHatchUsername, escapeHatchPassword));
        assertFalse(escapeHatch.check("otherUsername", escapeHatchPassword));
        assertFalse(escapeHatch.check(escapeHatchUsername, "wrongPassword"));
    }

    @Test
    void testShouldCheckEscapeHatchWithHashedPassword() throws Exception {
        final String escapeHatchUsername = "aUsername";
        final String escapeHatchPassword = "aSecretPassword";
        final String escapeHatchCryptedPassword = BCrypt.hashpw(escapeHatchPassword, BCrypt.gensalt());

        var escapeHatch = new EscapeHatch(escapeHatchUsername, null, Secret.fromString(escapeHatchCryptedPassword));
        assertEquals(escapeHatchUsername, escapeHatch.getUsername());
        assertEquals(escapeHatchCryptedPassword, Secret.toString(escapeHatch.getSecret()));
    }
}
