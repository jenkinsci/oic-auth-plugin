package org.jenkinsci.plugins.oic;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;

import com.google.api.client.json.gson.GsonFactory;
import java.io.IOException;
import org.junit.Test;

public class WellKnownOpenIDConfigurationResponseTest {

    private static final String JSON_FROM_GOOGLE = "{"
            + " \"issuer\": \"https://accounts.google.com\","
            + " \"authorization_endpoint\": \"https://accounts.google.com/o/oauth2/v2/auth\","
            + " \"token_endpoint\": \"https://www.googleapis.com/oauth2/v4/token\","
            + " \"userinfo_endpoint\": \"https://www.googleapis.com/oauth2/v3/userinfo\","
            + " \"revocation_endpoint\": \"https://accounts.google.com/o/oauth2/revoke\","
            + " \"jwks_uri\": \"https://www.googleapis.com/oauth2/v3/certs\","
            + " \"response_types_supported\": ["
            + "  \"code\","
            + "  \"token\","
            + "  \"id_token\","
            + "  \"code token\","
            + "  \"code id_token\","
            + "  \"token id_token\","
            + "  \"code token id_token\","
            + "  \"none\""
            + " ],"
            + " \"subject_types_supported\": ["
            + "  \"public\""
            + " ],"
            + " \"id_token_signing_alg_values_supported\": ["
            + "  \"RS256\""
            + " ],"
            + " \"scopes_supported\": ["
            + "  \"openid\","
            + "  \"email\","
            + "  \"profile\""
            + " ],"
            + " \"token_endpoint_auth_methods_supported\": ["
            + "  \"client_secret_post\","
            + "  \"client_secret_basic\""
            + " ],"
            + " \"claims_supported\": ["
            + "  \"aud\","
            + "  \"email\","
            + "  \"email_verified\","
            + "  \"exp\","
            + "  \"family_name\","
            + "  \"given_name\","
            + "  \"iat\","
            + "  \"iss\","
            + "  \"locale\","
            + "  \"name\","
            + "  \"picture\","
            + "  \"sub\""
            + " ],"
            + " \"code_challenge_methods_supported\": ["
            + "  \"plain\","
            + "  \"S256\""
            + " ]"
            + "}";

    @Test
    public void parseExplicitKeys() throws IOException {
        WellKnownOpenIDConfigurationResponse response = GsonFactory.getDefaultInstance()
                .fromString(JSON_FROM_GOOGLE, WellKnownOpenIDConfigurationResponse.class);

        assertThat(response.getAuthorizationEndpoint(), is("https://accounts.google.com/o/oauth2/v2/auth"));
        assertThat(response.getTokenEndpoint(), is("https://www.googleapis.com/oauth2/v4/token"));
        assertThat(response.getUserinfoEndpoint(), is("https://www.googleapis.com/oauth2/v3/userinfo"));
        assertThat(response.getJwksUri(), is("https://www.googleapis.com/oauth2/v3/certs"));
        assertThat(response.getScopesSupported(), containsInAnyOrder("openid", "email", "profile"));
        assertThat(response.getTokenAuthMethods(), containsInAnyOrder("client_secret_basic", "client_secret_post"));
    }

    @Test
    public void parseWellKnownKeys() throws IOException {
        WellKnownOpenIDConfigurationResponse response = GsonFactory.getDefaultInstance()
                .fromString(JSON_FROM_GOOGLE, WellKnownOpenIDConfigurationResponse.class);
        assertThat(
                response.getKnownKeys().keySet(),
                containsInAnyOrder(
                        "authorization_endpoint",
                        "token_endpoint",
                        "userinfo_endpoint",
                        "jwks_uri",
                        "scopes_supported",
                        "token_endpoint_auth_methods_supported"));
    }

    @Test
    public void testEquals() {
        WellKnownOpenIDConfigurationResponse obj1 = new WellKnownOpenIDConfigurationResponse();
        assertNotEquals(obj1, new Object());
        WellKnownOpenIDConfigurationResponse obj2 = new WellKnownOpenIDConfigurationResponse();
        assertEquals(obj1, obj1);
        assertEquals(obj1, obj2);

        testField(obj1, obj2, "userinfo_endpoint", "some userinfo endpoint");
        testField(obj1, obj2, "authorization_endpoint", "some auth endpoint");
        testField(obj1, obj2, "token_endpoint", "some token_endpoint endpoint");
        testField(obj1, obj2, "jwks_uri", "some jwks_uri endpoint");
        testField(obj1, obj2, "end_session_endpoint", "some end_session_endpoint endpoint");
    }

    private void testField(
            WellKnownOpenIDConfigurationResponse obj1,
            WellKnownOpenIDConfigurationResponse obj2,
            String field,
            String value) {
        obj1.set(field, value);
        obj2.set(field, null);
        assertNotEquals(obj1, obj2);

        obj1.set(field, null);
        obj2.set(field, value);
        assertNotEquals(obj1, obj2);

        obj1.set(field, value + "1");
        obj2.set(field, value);
        assertNotEquals(obj1, obj2);

        obj1.set(field, value);
        obj2.set(field, value + "1");
        assertNotEquals(obj1, obj2);

        obj1.set(field, null);
        obj2.set(field, null);
        assertEquals(obj1, obj2);

        obj1.set(field, value);
        obj2.set(field, value);
        assertEquals(obj1, obj2);
    }

    @Test
    public void testHashcode() {
        WellKnownOpenIDConfigurationResponse obj1 = new WellKnownOpenIDConfigurationResponse();
        assertEquals(701760682, obj1.hashCode());

        obj1.set("userinfo_endpoint", "some endpoint");
        assertEquals(961661960, obj1.hashCode());
    }
}
