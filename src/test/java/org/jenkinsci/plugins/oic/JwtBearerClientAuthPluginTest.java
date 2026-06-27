package org.jenkinsci.plugins.oic;

import static com.github.tomakehurst.wiremock.client.WireMock.containing;
import static com.github.tomakehurst.wiremock.client.WireMock.notMatching;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestAsserts.assertTestUser;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestHelper.browseLoginPage;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestHelper.configureTestRealm;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestMocks.mockAuthorizationRedirectsToFinishLogin;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestMocks.mockTokenReturnsIdTokenWithGroup;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import com.github.tomakehurst.wiremock.junit5.WireMockExtension;
import java.nio.file.Files;
import java.nio.file.Path;
import jenkins.model.Jenkins;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.api.io.TempDir;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

/**
 * Integration tests for JWT Bearer client authentication (Kubernetes workload identity).
 *
 * <p>Verifies that when {@code clientAssertionFilePath} is configured, the plugin authenticates
 * to the token endpoint using {@code client_assertion} (RFC 7523) instead of {@code client_secret},
 * and that {@code client_id} is not sent in the request body (Keycloak federated JWT rejects
 * requests where the {@code client_id} parameter does not match the JWT {@code sub} claim).
 */
@WithJenkins
class JwtBearerClientAuthPluginTest {

    @RegisterExtension
    static WireMockExtension wireMock = WireMockExtension.newInstance()
            .failOnUnmatchedRequests(true)
            .options(wireMockConfig().dynamicPort())
            .build();

    @TempDir
    Path tempDir;

    private JenkinsRule jenkinsRule;
    private JenkinsRule.WebClient webClient;
    private Jenkins jenkins;

    // Minimal fake K8s service-account JWT (only base64url-safe chars, no URL-encoding needed)
    private static final String FAKE_K8S_JWT =
            "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJzeXN0ZW06c2VydmljZWFjY291bnQ6ZGVmYXVsdDpqZW5raW5zIn0.fakesig";

    private static final String ROTATED_K8S_JWT =
            "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJzeXN0ZW06c2VydmljZWFjY291bnQ6ZGVmYXVsdDpqZW5raW5zIn0.rotatedsig";

    @BeforeEach
    void setUp(JenkinsRule jenkinsRule) {
        this.jenkinsRule = jenkinsRule;
        jenkins = jenkinsRule.getInstance();
        webClient = jenkinsRule.createWebClient();
        webClient.getOptions().setRedirectEnabled(true);
        webClient.getOptions().setThrowExceptionOnFailingStatusCode(false);
    }

    @Test
    void testLoginSendsClientAssertionNotClientSecret() throws Exception {
        Path jwtFile = tempDir.resolve("k8s-sa-token");
        Files.writeString(jwtFile, FAKE_K8S_JWT + "\n"); // trailing newline is stripped by FileJwtClientAuthentication

        mockAuthorizationRedirectsToFinishLogin(wireMock, jenkins);
        mockTokenReturnsIdTokenWithGroup(wireMock);
        configureTestRealm(wireMock, jenkins, sc -> sc.setClientAssertionFilePath(jwtFile.toString()));

        browseLoginPage(webClient, jenkins);
        assertTestUser(webClient);

        // client_assertion_type and client_assertion must be present;
        // client_secret and client_id must be absent (Keycloak federated JWT rejects client_id != sub)
        wireMock.verify(postRequestedFor(urlPathEqualTo("/token"))
                .withRequestBody(containing(
                        "client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer"))
                .withRequestBody(containing("client_assertion=" + FAKE_K8S_JWT))
                .withRequestBody(notMatching(".*client_secret=.*"))
                .withRequestBody(notMatching(".*client_id=.*")));
    }

    @Test
    void testTokenFileIsRereadAfterRotation() throws Exception {
        Path jwtFile = tempDir.resolve("k8s-sa-token");
        Files.writeString(jwtFile, FAKE_K8S_JWT);

        mockAuthorizationRedirectsToFinishLogin(wireMock, jenkins);
        mockTokenReturnsIdTokenWithGroup(wireMock);
        configureTestRealm(wireMock, jenkins, sc -> sc.setClientAssertionFilePath(jwtFile.toString()));

        // First login uses the original JWT
        browseLoginPage(webClient, jenkins);
        wireMock.verify(postRequestedFor(urlPathEqualTo("/token"))
                .withRequestBody(containing("client_assertion=" + FAKE_K8S_JWT)));

        // Kubernetes rotates the token
        Files.writeString(jwtFile, ROTATED_K8S_JWT);

        // Second login (fresh session) must pick up the rotated JWT without restarting Jenkins
        JenkinsRule.WebClient webClient2 = jenkinsRule.createWebClient();
        webClient2.getOptions().setRedirectEnabled(true);
        webClient2.getOptions().setThrowExceptionOnFailingStatusCode(false);
        browseLoginPage(webClient2, jenkins);
        wireMock.verify(postRequestedFor(urlPathEqualTo("/token"))
                .withRequestBody(containing("client_assertion=" + ROTATED_K8S_JWT)));
    }

    @Test
    void setClientAssertionFilePath_trimsWhitespace() throws Exception {
        var realm = new TestRealm(new TestRealm.Builder(wireMock).WithMinimalDefaults());
        realm.setClientAssertionFilePath("  /var/run/secrets/tokens/id-token  ");
        assertEquals("/var/run/secrets/tokens/id-token", realm.getClientAssertionFilePath());
    }

    @Test
    void setClientAssertionFilePath_null_clearsPath() throws Exception {
        var realm = new TestRealm(new TestRealm.Builder(wireMock).WithMinimalDefaults());
        realm.setClientAssertionFilePath("/var/run/secrets/tokens/id-token");
        realm.setClientAssertionFilePath(null);
        assertNull(realm.getClientAssertionFilePath());
    }

    @Test
    void setClientAssertionFilePath_blankString_clearsPath() throws Exception {
        var realm = new TestRealm(new TestRealm.Builder(wireMock).WithMinimalDefaults());
        realm.setClientAssertionFilePath("/var/run/secrets/tokens/id-token");
        realm.setClientAssertionFilePath("   ");
        assertNull(realm.getClientAssertionFilePath());
    }
}
