package com.google.api.client.auth.oauth2;

import java.util.Map;
import java.util.Set;
import com.google.api.client.json.GenericJson;
import com.google.api.client.util.Key;

/**
 * OpenID Connect Discovery JSON.
 * https://openid.net/specs/openid-connect-discovery-1_0.html
 *
 * @author Steve Arch
 */
public class WellKnownOpenIDConfigurationResponse extends GenericJson {
    @Key("authorization_endpoint")
    private String authorizationEndpoint;

    @Key("token_endpoint")
    private String tokenEndpoint;

    @Key("userinfo_endpoint")
    private String userinfoEndpoint;

    @Key("jwks_uri")
    private String jwksUri;

    @Key("scopes_supported")
    private Set<String> scopesSupported;

    public String getAuthorizationEndpoint() {
        return authorizationEndpoint;
    }

    public String getTokenEndpoint() {
        return tokenEndpoint;
    }

    public String getUserinfoEndpoint() {
        return userinfoEndpoint;
    }

    public String getJwksUri() {
        return jwksUri;
    }

    public Set<String> getScopesSupported() {
        return scopesSupported;
    }

    /**
     * Mimicks {@link GenericJson#getUnknownKeys()}, but returning the map of known keys
     * @return
     */
    public Map<String, Object> getKnownKeys() {
        Map<String, Object> clone = this.clone();
        for(String key : this.getUnknownKeys().keySet()) {
            clone.remove(key);
        }
        return clone;
    }
}
