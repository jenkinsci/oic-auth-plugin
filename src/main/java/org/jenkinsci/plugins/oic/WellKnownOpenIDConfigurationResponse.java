package org.jenkinsci.plugins.oic;

import java.util.Map;
import java.util.Set;

import com.google.api.client.json.GenericJson;
import com.google.api.client.util.Key;
import com.google.common.base.Objects;

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

    @Override
    public boolean equals(Object o) {
        if (o == this) {
            return true;
        }
        if (o == null || !(o instanceof WellKnownOpenIDConfigurationResponse)) {
            return false;
        }

        WellKnownOpenIDConfigurationResponse obj = (WellKnownOpenIDConfigurationResponse) o;

        if (!Objects.equal(authorizationEndpoint, obj.getAuthorizationEndpoint())) {
            return false;
        }
        if (!Objects.equal(tokenEndpoint, obj.getTokenEndpoint())) {
            return false;
        }
        if (!Objects.equal(userinfoEndpoint, obj.getUserinfoEndpoint())) {
            return false;
        }
        if (!Objects.equal(jwksUri, obj.getJwksUri())) {
            return false;
        }
        if (!Objects.equal(scopesSupported, obj.getScopesSupported())) {
            return false;
        }
        if (!Objects.equal(endSessionEndpoint, obj.getEndSessionEndpoint())) {
            return false;
        }

        return true;
    }

    @Override
    public int hashCode() {
        return super.hashCode();
    }
}
