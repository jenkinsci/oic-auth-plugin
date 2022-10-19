package org.jenkinsci.plugins.oic;

import java.util.Map;
import java.util.Set;
import com.google.api.client.json.GenericJson;
import com.google.api.client.util.Key;

/**
 * OpenID Connect Discovery JSON.
 * https://openid.net/specs/openid-connect-discovery-1_0.html
 *
 * https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata:
 * "Additional OpenID Provider Metadata parameters MAY also be used. Some are defined by other specifications, such as OpenID Connect Session Management 1.0"
 * http://openid.net/specs/openid-connect-session-1_0.html#OPMetadata
 *
 * @author Steve Arch
 */
public class WellKnownOpenIDConfigurationResponse extends GenericJson {
    @Key("authorization_endpoint")
    private String authorizationEndpoint;

    @Key("token_endpoint")
    private String tokenEndpoint;

    @Key("token_endpoint_auth_methods_supported")
    private Set<String> tokenAuthMethods;

    @Key("userinfo_endpoint")
    private String userinfoEndpoint;

    @Key("jwks_uri")
    private String jwksUri;

    @Key("scopes_supported")
    private Set<String> scopesSupported;

    @Key("end_session_endpoint")
    private String endSessionEndpoint;

    public String getAuthorizationEndpoint() {
        return authorizationEndpoint;
    }

    public String getTokenEndpoint() {
        return tokenEndpoint;
    }

    public Set<String> getTokenAuthMethods() {
        return tokenAuthMethods;
    }

    public String getPreferredTokenAuthMethod() {
        if (tokenAuthMethods != null && !tokenAuthMethods.isEmpty()) {
            // Prefer post since that is what the original plugin implementation used
            if(tokenAuthMethods.contains("client_secret_post")) {
                return "client_secret_post";
            // The RFC recommends basic, so that's our number two choice
            } else if(tokenAuthMethods.contains("client_secret_basic")) {
                return "client_secret_basic";
            } else {
                return tokenAuthMethods.iterator().next();
            }
        } else {
            return "client_secret_post";
        }
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

    public String getEndSessionEndpoint() {
        return endSessionEndpoint;
    }

    /**
     * Mimicks {@link GenericJson#getUnknownKeys()}, but returning the map of known keys
     * @return a map key-values pairs defined in this class
     */
    public Map<String, Object> getKnownKeys() {
        Map<String, Object> clone = this.clone();
        for(String key : this.getUnknownKeys().keySet()) {
            clone.remove(key);
        }
        return clone;
    }
    
    /**
     * Overriding equals()
     */
    @Override
    public int hashCode() {
        return super.hashCode();
    }

    /**
     * Overriding equals()
     */
    @Override
    public boolean equals(Object o) {
        return super.equals(o);
    }
}
