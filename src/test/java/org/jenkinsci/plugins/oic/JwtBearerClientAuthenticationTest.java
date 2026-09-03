package org.jenkinsci.plugins.oic;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import hudson.util.FormValidation;
import java.nio.file.Path;
import jenkins.model.Jenkins;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

@WithJenkins
class JwtBearerClientAuthenticationTest {

    private Jenkins jenkins;

    @BeforeEach
    void setUp(JenkinsRule jenkinsRule) {
        jenkins = jenkinsRule.getInstance();
    }

    @Test
    void constructor_trimsWhitespace() {
        assertEquals(
                "/var/run/secrets/tokens/id-token",
                new JwtBearerClientAuthentication("  /var/run/secrets/tokens/id-token  ").getClientAssertionFilePath());
    }

    @Test
    void constructor_blankString_isNull() {
        assertNull(new JwtBearerClientAuthentication("   ").getClientAssertionFilePath());
        assertNull(new JwtBearerClientAuthentication(null).getClientAssertionFilePath());
    }

    @Test
    void doCheckClientAssertionFilePath() {
        JwtBearerClientAuthentication.DescriptorImpl descriptor = (JwtBearerClientAuthentication.DescriptorImpl)
                jenkins.getDescriptorOrDie(JwtBearerClientAuthentication.class);
        assertNotNull(descriptor);

        // Null or blank → error (field is required for this authentication method)
        assertEquals(FormValidation.Kind.ERROR, descriptor.doCheckClientAssertionFilePath(null).kind);
        assertEquals(FormValidation.Kind.ERROR, descriptor.doCheckClientAssertionFilePath("").kind);
        assertEquals(FormValidation.Kind.ERROR, descriptor.doCheckClientAssertionFilePath("   ").kind);

        // Relative path → error
        assertEquals(FormValidation.Kind.ERROR, descriptor.doCheckClientAssertionFilePath("relative/path").kind);
        assertTrue(descriptor
                .doCheckClientAssertionFilePath("relative/path")
                .getMessage()
                .contains("must be absolute"));

        // Absolute path that does not exist → warning (Kubernetes may mount it at runtime)
        // Build an OS-agnostic absolute path: on Windows "/foo" is not absolute, tmpdir always is
        String nonExistentAbsPath = Path.of(System.getProperty("java.io.tmpdir"), "nonexistent-oic-assertion-path-xyz")
                .toString();
        assertEquals(FormValidation.Kind.WARNING, descriptor.doCheckClientAssertionFilePath(nonExistentAbsPath).kind);
        assertTrue(descriptor
                .doCheckClientAssertionFilePath(nonExistentAbsPath)
                .getMessage()
                .contains("does not currently exist"));

        // Absolute path that exists → ok (tmpdir always exists and is absolute on all OS)
        assertEquals(
                FormValidation.ok(), descriptor.doCheckClientAssertionFilePath(System.getProperty("java.io.tmpdir")));

        // Path containing a null byte — invalid on all OS → error
        assertEquals(FormValidation.Kind.ERROR, descriptor.doCheckClientAssertionFilePath("/tmp/\0null").kind);
        assertTrue(descriptor
                .doCheckClientAssertionFilePath("/tmp/\0null")
                .getMessage()
                .contains("Invalid file path"));
    }
}
