package org.jenkinsci.plugins.oic;

import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.SerializeException;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.util.URLUtils;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * A {@link ClientAuthentication} that reads a JWT from a file and uses it as a client assertion.
 *
 * <p>The JWT is read fresh on every token request, allowing Kubernetes service account tokens
 * (which are regularly rotated) to be used without restarting Jenkins.
 *
 * <p>Implements the JWT Bearer client authentication profile defined in
 * <a href="https://www.rfc-editor.org/rfc/rfc7523">RFC 7523</a>.
 */
class FileJwtClientAuthentication extends ClientAuthentication {

    static final String JWT_BEARER_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

    private final Path jwtFilePath;

    FileJwtClientAuthentication(String clientId, Path jwtFilePath) {
        super(ClientAuthenticationMethod.PRIVATE_KEY_JWT, new ClientID(clientId));
        this.jwtFilePath = jwtFilePath;
    }

    @Override
    public Set<String> getFormParameterNames() {
        return Collections.unmodifiableSet(new HashSet<>(Arrays.asList("client_assertion_type", "client_assertion")));
    }

    @Override
    public void applyTo(HTTPRequest httpRequest) {
        if (httpRequest.getMethod() != HTTPRequest.Method.POST) {
            throw new SerializeException("The HTTP request method must be POST");
        }
        ContentType ct = httpRequest.getEntityContentType();
        if (ct == null) {
            throw new SerializeException("Missing HTTP Content-Type header");
        }
        if (!ct.matches(ContentType.APPLICATION_URLENCODED)) {
            throw new SerializeException("The HTTP Content-Type header must be " + ContentType.APPLICATION_URLENCODED);
        }
        try {
            String jwt = Files.readString(jwtFilePath).strip();
            Map<String, List<String>> params;
            try {
                params = new LinkedHashMap<>(httpRequest.getBodyAsFormParameters());
            } catch (ParseException e) {
                throw new SerializeException("Failed to parse HTTP request body parameters: " + e.getMessage());
            }
            params.remove("client_secret");
            params.put("client_assertion_type", Collections.singletonList(JWT_BEARER_ASSERTION_TYPE));
            params.put("client_assertion", Collections.singletonList(jwt));
            httpRequest.setBody(URLUtils.serializeParameters(params));
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to read JWT assertion from file: " + jwtFilePath, e);
        }
    }
}
