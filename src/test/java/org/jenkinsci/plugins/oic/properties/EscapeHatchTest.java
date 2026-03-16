package org.jenkinsci.plugins.oic.properties;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import hudson.util.Secret;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCrypt;

class EscapeHatchTest {
    private final EscapeHatch.CrumbExclusionImpl crumb = new EscapeHatch.CrumbExclusionImpl();

    @Test
    void process_WithNullPath() throws IOException, ServletException {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getPathInfo()).thenReturn("");
        assertFalse(crumb.process(request, null, null));
    }

    @Test
    void process_WithWrongPath() throws IOException, ServletException {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getPathInfo()).thenReturn("fictionalPath");
        assertFalse(crumb.process(request, null, null));
    }

    @Test
    void process_WithGoodPath() throws IOException, ServletException {
        FilterChain chain = (arg0, arg1) -> {
            // do nothing
        };
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getPathInfo()).thenReturn("/securityRealm/escapeHatch");
        assertTrue(crumb.process(request, null, chain));
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
