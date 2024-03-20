package org.jenkinsci.plugins.oic;

import com.google.api.client.json.gson.GsonFactory;
import java.io.IOException;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * We'd like to be more permissive by allowing:
 * - both long literals and Strigns containing to accepted
 */
public class OicTokenResponseTest {

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
        OicTokenResponse response = GsonFactory.getDefaultInstance().fromString(JSON_WITH_LONG_LITERAL, OicTokenResponse.class);
        assertEquals("2YotnFZFEjr1zCsicMWpAA", response.getAccessToken());
        assertEquals("example", response.getTokenType());
        assertEquals(3600L, response.getExpiresInSeconds().longValue());
        assertEquals("tGzv3JOkF0XG5Qx2TlKWIA", response.getRefreshToken());
        assertEquals("example_value", response.get("example_parameter"));
    }

    @Test
    public void parseStringWithLong() throws IOException {
        OicTokenResponse response = GsonFactory.getDefaultInstance().fromString(JSON_WITH_LONG_AS_STRING, OicTokenResponse.class);
        assertEquals("2YotnFZFEjr1zCsicMWpAA", response.getAccessToken());
        assertEquals("example", response.getTokenType());
        assertEquals(3600L, response.getExpiresInSeconds().longValue());
        assertEquals("tGzv3JOkF0XG5Qx2TlKWIA", response.getRefreshToken());
        assertEquals("example_value", response.get("example_parameter"));
    }

    @Test
    public void testSetters() throws IOException {
        OicTokenResponse response = new OicTokenResponse();
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

        OicTokenResponse cloned = response.clone();
        assertEquals(response.getAccessToken(), cloned.getAccessToken());
        assertEquals(response.getTokenType(), cloned.getTokenType());
        assertEquals(response.getExpiresInSeconds().longValue(), cloned.getExpiresInSeconds().longValue());
        assertEquals(response.getRefreshToken(), cloned.getRefreshToken());
        assertEquals(response.get("example_parameter"), cloned.get("example_parameter"));
        assertEquals(response.getScope(), cloned.getScope());

        assertTrue(response.equals(cloned));
        assertTrue(response.hashCode() == cloned.hashCode());
    }

    @Test
    public void parseAbsent() throws IOException {
        OicTokenResponse response = GsonFactory.getDefaultInstance().fromString(JSON_WITH_ABSENT, OicTokenResponse.class);
        assertEquals("2YotnFZFEjr1zCsicMWpAA", response.getAccessToken());
        assertEquals("example", response.getTokenType());
        assertEquals(null, response.getExpiresInSeconds());
        assertEquals("tGzv3JOkF0XG5Qx2TlKWIA", response.getRefreshToken());
        assertEquals("example_value", response.get("example_parameter"));
    }
}
