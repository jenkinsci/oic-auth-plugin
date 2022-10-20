package org.jenkinsci.plugins.oic;

import java.io.IOException;

import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.jackson2.JacksonFactory;
import org.junit.Test;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.is;

public class WellKnownOpenIDConfigurationResponseTest {

    private final JsonFactory jsonFactory = new JacksonFactory();

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
        WellKnownOpenIDConfigurationResponse response = jsonFactory.fromString(JSON_FROM_GOOGLE, WellKnownOpenIDConfigurationResponse.class);

        assertThat(response.getAuthorizationEndpoint(), is("https://accounts.google.com/o/oauth2/v2/auth"));
        assertThat(response.getTokenEndpoint(), is("https://www.googleapis.com/oauth2/v4/token"));
        assertThat(response.getUserinfoEndpoint(), is("https://www.googleapis.com/oauth2/v3/userinfo"));
        assertThat(response.getJwksUri(), is("https://www.googleapis.com/oauth2/v3/certs"));
        assertThat(response.getScopesSupported(), containsInAnyOrder("openid", "email", "profile"));
        assertThat(response.getTokenAuthMethods(), containsInAnyOrder("client_secret_basic", "client_secret_post"));
    }

    @Test
    public void parseWellKnownKeys() throws IOException {
        WellKnownOpenIDConfigurationResponse response = jsonFactory.fromString(JSON_FROM_GOOGLE, WellKnownOpenIDConfigurationResponse.class);
        assertThat(response.getKnownKeys().keySet(), containsInAnyOrder(
            "authorization_endpoint",
            "token_endpoint",
            "userinfo_endpoint",
            "jwks_uri",
            "scopes_supported",
            "token_endpoint_auth_methods_supported"
        ));
    }

}
