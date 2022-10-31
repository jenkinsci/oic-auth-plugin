package org.jenkinsci.plugins.oic;

import com.google.api.client.auth.oauth2.TokenResponse;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.jackson2.JacksonFactory;
import java.io.IOException;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

/**
 * We'd like to be more permissive by allowing both long literals and Strigns containing to accepted
 * See:
 * https://github.com/jenkinsci/oic-auth-plugin/issues/10
 * https://github.com/google/google-oauth-java-client/issues/62
 */
public class TokenResponseTest {

    private static final String JSON_WITH_LONG_AS_STRING = "{\"access_token\":\"2YotnFZFEjr1zCsicMWpAA\","
            + "\"token_type\":\"example\",\"expires_in\":\"3600\","
            + "\"refresh_token\":\"tGzv3JOkF0XG5Qx2TlKWIA\","
            + "\"example_parameter\":\"example_value\"}";

    private static final String JSON_WITH_LONG_LITERAL = "{\"access_token\":\"2YotnFZFEjr1zCsicMWpAA\","
            + "\"token_type\":\"example\",\"expires_in\":3600,"
            + "\"refresh_token\":\"tGzv3JOkF0XG5Qx2TlKWIA\","
            + "\"example_parameter\":\"example_value\"}";

    private static final String JSON_WITH_ABSENT = "{\"access_token\":\"2YotnFZFEjr1zCsicMWpAA\","
            + "\"token_type\":\"example\","
            + "\"refresh_token\":\"tGzv3JOkF0XG5Qx2TlKWIA\","
            + "\"example_parameter\":\"example_value\"}";

    @Test
    public void parseLongLiteral() throws IOException {
        JsonFactory jsonFactory = new JacksonFactory();
        TokenResponse response = jsonFactory.fromString(JSON_WITH_LONG_LITERAL, TokenResponse.class);
        assertEquals("2YotnFZFEjr1zCsicMWpAA", response.getAccessToken());
        assertEquals("example", response.getTokenType());
        assertEquals(3600L, response.getExpiresInSeconds().longValue());
        assertEquals("tGzv3JOkF0XG5Qx2TlKWIA", response.getRefreshToken());
        assertEquals("example_value", response.get("example_parameter"));
    }

    @Test
    public void parseStringWithLong() throws IOException {
        JsonFactory jsonFactory = new JacksonFactory();
        TokenResponse response = jsonFactory.fromString(JSON_WITH_LONG_AS_STRING, TokenResponse.class);
        assertEquals("2YotnFZFEjr1zCsicMWpAA", response.getAccessToken());
        assertEquals("example", response.getTokenType());
        assertEquals(3600L, response.getExpiresInSeconds().longValue());
        assertEquals("tGzv3JOkF0XG5Qx2TlKWIA", response.getRefreshToken());
        assertEquals("example_value", response.get("example_parameter"));
    }

    @Test
    public void testSetters() throws IOException {
        TokenResponse response = new TokenResponse();
        assertEquals(response, response.setAccessToken("2YotnFZFEjr1zCsicMWpAA"));
        assertEquals(response, response.setTokenType("example"));
        assertEquals(response, response.setExpiresInSeconds(3600L));
        assertEquals(response, response.setRefreshToken("tGzv3JOkF0XG5Qx2TlKWIA"));
        assertEquals(response, response.set("example_parameter", "example_value"));
        assertEquals(response, response.setScope("myScope"));
        assertEquals("2YotnFZFEjr1zCsicMWpAA", response.getAccessToken());
        assertEquals("example", response.getTokenType());
        assertEquals(3600L, response.getExpiresInSeconds().longValue());
        assertEquals("tGzv3JOkF0XG5Qx2TlKWIA", response.getRefreshToken());
        assertEquals("example_value", response.get("example_parameter"));
        assertEquals("myScope", response.getScope());

        TokenResponse cloned = response.clone();
        assertEquals(response.getAccessToken(), cloned.getAccessToken());
        assertEquals(response.getTokenType(), cloned.getTokenType());
        assertEquals(response.getExpiresInSeconds().longValue(), cloned.getExpiresInSeconds().longValue());
        assertEquals(response.getRefreshToken(), cloned.getRefreshToken());
        assertEquals(response.get("example_parameter"), cloned.get("example_parameter"));
        assertEquals(response.getScope(), cloned.getScope());
    }

    @Test
    public void parseAbsent() throws IOException {
        JsonFactory jsonFactory = new JacksonFactory();
        TokenResponse response = jsonFactory.fromString(JSON_WITH_ABSENT, TokenResponse.class);
        assertEquals("2YotnFZFEjr1zCsicMWpAA", response.getAccessToken());
        assertEquals("example", response.getTokenType());
        assertEquals(null, response.getExpiresInSeconds());
        assertEquals("tGzv3JOkF0XG5Qx2TlKWIA", response.getRefreshToken());
        assertEquals("example_value", response.get("example_parameter"));
    }
}
