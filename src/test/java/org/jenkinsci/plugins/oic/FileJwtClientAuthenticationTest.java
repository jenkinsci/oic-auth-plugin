package org.jenkinsci.plugins.oic;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.oauth2.sdk.SerializeException;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class FileJwtClientAuthenticationTest {

    private static final String CLIENT_ID = "my-jenkins-client";
    private static final String FAKE_JWT =
            "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJzeXN0ZW06c2VydmljZWFjY291bnQ6ZGVmYXVsdDpteS1qZW5raW5zIn0.sig";

    @TempDir
    Path tempDir;

    @Test
    void applyTo_addsJwtBearerParameters() throws Exception {
        Path jwtFile = tempDir.resolve("id-token");
        Files.writeString(jwtFile, FAKE_JWT + "\n"); // trailing newline should be stripped

        var auth = new FileJwtClientAuthentication(CLIENT_ID, jwtFile);
        HTTPRequest request = buildPostRequest();

        auth.applyTo(request);

        Map<String, List<String>> params = request.getBodyAsFormParameters();
        assertTrue(
                !params.containsKey("client_id"),
                "client_id must not be sent — Keycloak federated JWT rejects if client_id != sub");
        assertEquals(
                List.of(FileJwtClientAuthentication.JWT_BEARER_ASSERTION_TYPE), params.get("client_assertion_type"));
        assertEquals(List.of(FAKE_JWT), params.get("client_assertion"));
        assertTrue(params.containsKey("grant_type"), "existing params should be preserved");
    }

    @Test
    void applyTo_removesClientSecret() throws Exception {
        Path jwtFile = tempDir.resolve("id-token");
        Files.writeString(jwtFile, FAKE_JWT);

        var auth = new FileJwtClientAuthentication(CLIENT_ID, jwtFile);
        HTTPRequest request = buildPostRequest();
        // Simulate existing client_secret in the request body
        Map<String, List<String>> initial = request.getBodyAsFormParameters();
        initial.put("client_secret", List.of("old-secret"));
        request.setBody(initial.entrySet().stream()
                .map(e -> e.getKey() + "=" + e.getValue().get(0))
                .reduce((a, b) -> a + "&" + b)
                .orElse(""));

        auth.applyTo(request);

        Map<String, List<String>> params = request.getBodyAsFormParameters();
        assertTrue(!params.containsKey("client_secret"), "client_secret should be removed");
    }

    @Test
    void applyTo_readsFileEachTime() throws Exception {
        Path jwtFile = tempDir.resolve("id-token");
        Files.writeString(jwtFile, FAKE_JWT);

        var auth = new FileJwtClientAuthentication(CLIENT_ID, jwtFile);

        HTTPRequest request1 = buildPostRequest();
        auth.applyTo(request1);
        assertEquals(List.of(FAKE_JWT), request1.getBodyAsFormParameters().get("client_assertion"));

        // Simulate token rotation
        String newJwt = FAKE_JWT + ".rotated";
        Files.writeString(jwtFile, newJwt);

        HTTPRequest request2 = buildPostRequest();
        auth.applyTo(request2);
        assertEquals(
                List.of(newJwt),
                request2.getBodyAsFormParameters().get("client_assertion"),
                "Should read the updated JWT from the file");
    }

    @Test
    void applyTo_throwsWhenFileNotFound() throws Exception {
        Path missingFile = tempDir.resolve("nonexistent");
        var auth = new FileJwtClientAuthentication(CLIENT_ID, missingFile);

        assertThrows(UncheckedIOException.class, () -> auth.applyTo(buildPostRequest()));
    }

    @Test
    void applyTo_throwsWhenNotPost() throws Exception {
        Path jwtFile = tempDir.resolve("id-token");
        Files.writeString(jwtFile, FAKE_JWT);
        var auth = new FileJwtClientAuthentication(CLIENT_ID, jwtFile);

        HTTPRequest getRequest = new HTTPRequest(HTTPRequest.Method.GET, new URL("http://example.com/token"));
        assertThrows(SerializeException.class, () -> auth.applyTo(getRequest));
    }

    @Test
    void getFormParameterNames_returnsExpectedNames() throws Exception {
        var auth = new FileJwtClientAuthentication(CLIENT_ID, Path.of("/tmp/token"));
        var names = auth.getFormParameterNames();
        assertTrue(
                !names.contains("client_id"),
                "client_id must not be declared — Keycloak federated JWT rejects if client_id != sub");
        assertTrue(names.contains("client_assertion_type"));
        assertTrue(names.contains("client_assertion"));
    }

    private static HTTPRequest buildPostRequest() throws IOException {
        HTTPRequest request = new HTTPRequest(HTTPRequest.Method.POST, new URL("http://example.com/token"));
        request.setEntityContentType(ContentType.APPLICATION_URLENCODED);
        request.setBody("grant_type=authorization_code&code=abc123");
        return request;
    }
}
