package org.jenkinsci.plugins.oic;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.openid.connect.sdk.SubjectType;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import jenkins.security.FIPS140;
import net.minidev.json.JSONObject;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.mockito.MockedStatic;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.mockStatic;

public class OicSecurityRealmFIPSAlgoTest {

    private static MockedStatic<FIPS140> fips140Mock;

    @BeforeClass
    public static void setup() {
        fips140Mock = mockStatic(FIPS140.class);
        fips140Mock.when(FIPS140::useCompliantAlgorithms).thenReturn(true);
    }

    @AfterClass
    public static void breakdown() {
        fips140Mock.close();
    }

    @Test
    public void doCheckAlgorithmFilterInFipsMode() throws IOException, ParseException {
        OIDCProviderMetadata oidcProviderMetadata = getNonCompliantMockObject();
        oidcProviderMetadata.setClientRegistrationAuthnJWSAlgs(compliantJwsAlgo());
        oidcProviderMetadata.setDPoPJWSAlgs(compliantJwsAlgo());
        oidcProviderMetadata.setAuthorizationJWSAlgs(compliantJwsAlgo());
        oidcProviderMetadata.setAuthorizationJWEAlgs(compliantJweAlgo());
        oidcProviderMetadata.setAuthorizationJWEEncs(compliantEncryptionMethod());
        oidcProviderMetadata.setClientRegistrationAuthnJWSAlgs(compliantJwsAlgo());

        int countIDTokenJWSAlgs = oidcProviderMetadata.getIDTokenJWSAlgs().size();
        int countIDTokenJWEAlgs = oidcProviderMetadata.getIDTokenJWEAlgs().size();
        int countIDTokenEncMethod = oidcProviderMetadata.getIDTokenJWEEncs().size();
        OicSecurityRealm.filterNonCompliantAlgorithms(oidcProviderMetadata);

        assertEquals(
                countIDTokenJWSAlgs - nonCompliantSigningAlgo().size(),
                oidcProviderMetadata.getIDTokenJWSAlgs().size());
        assertEquals(
                countIDTokenJWEAlgs - nonCompliantEncryptionAlgo().size(),
                oidcProviderMetadata.getIDTokenJWEAlgs().size());
        assertEquals(
                countIDTokenEncMethod - nonCompliantEncryptionMethod().size(),
                oidcProviderMetadata.getIDTokenJWEEncs().size());
    }

    protected static List<JWSAlgorithm> nonCompliantSigningAlgo() {
        List<JWSAlgorithm> nonCompliantSignAlgos = new ArrayList<>();
        nonCompliantSignAlgos.add(new JWSAlgorithm("EdDSA"));
        nonCompliantSignAlgos.add(new JWSAlgorithm("Ed25519"));
        nonCompliantSignAlgos.add(new JWSAlgorithm("Ed448"));
        return nonCompliantSignAlgos;
    }

    protected static List<JWEAlgorithm> nonCompliantEncryptionAlgo() {

        List<JWEAlgorithm> nonCompliantEncryptionAlgos = new ArrayList<>();
        nonCompliantEncryptionAlgos.add(new JWEAlgorithm("RSA1_5"));
        nonCompliantEncryptionAlgos.add(new JWEAlgorithm("ECDH-1PU"));
        nonCompliantEncryptionAlgos.add(new JWEAlgorithm("ECDH-1PU+A128KW"));
        nonCompliantEncryptionAlgos.add(new JWEAlgorithm("ECDH-1PU+A256KW"));
        return nonCompliantEncryptionAlgos;
    }

    protected static List<EncryptionMethod> nonCompliantEncryptionMethod() {
        List<EncryptionMethod> nonComplEncryptionMethods = new ArrayList<>();
        nonComplEncryptionMethods.add(new EncryptionMethod("XC20P"));
        return nonComplEncryptionMethods;
    }

    protected static List<JWSAlgorithm> compliantJwsAlgo() {
        List<JWSAlgorithm> compliantSignAlgos = new ArrayList<>();
        compliantSignAlgos.add(new JWSAlgorithm("HS256"));
        compliantSignAlgos.add(new JWSAlgorithm("HS384"));
        compliantSignAlgos.add(new JWSAlgorithm("HS512"));
        compliantSignAlgos.add(new JWSAlgorithm("RS384"));
        compliantSignAlgos.add(new JWSAlgorithm("PS384"));
        compliantSignAlgos.add(new JWSAlgorithm("ES512"));
        return compliantSignAlgos;
    }

    protected static List<JWEAlgorithm> compliantJweAlgo() {
        List<JWEAlgorithm> compliantEncryptionAlgos = new ArrayList<>();
        compliantEncryptionAlgos.add(new JWEAlgorithm("RSA-OAEP"));
        compliantEncryptionAlgos.add(new JWEAlgorithm("A192KW"));
        compliantEncryptionAlgos.add(new JWEAlgorithm("A128CGMKW"));
        compliantEncryptionAlgos.add(new JWEAlgorithm("A256CGMKW"));
        return compliantEncryptionAlgos;
    }

    protected static List<EncryptionMethod> compliantEncryptionMethod() {
        List<EncryptionMethod> encryptionMethod = new ArrayList<>();
        encryptionMethod.add(new EncryptionMethod("RSA-OAEP"));
        encryptionMethod.add(new EncryptionMethod("A192KW"));
        encryptionMethod.add(new EncryptionMethod("A128CGMKW"));
        encryptionMethod.add(new EncryptionMethod("A256CGMKW"));
        return encryptionMethod;
    }

    protected static OIDCProviderMetadata getNonCompliantMockObject() throws ParseException {
        OIDCProviderMetadata oidcProviderMetadata = createCompliantMockObject();
        // Add non compliant signing algo
        oidcProviderMetadata.getIDTokenJWSAlgs().addAll(nonCompliantSigningAlgo());
        // Add non-compliant encryption algo
        oidcProviderMetadata.getIDTokenJWEAlgs().addAll(nonCompliantEncryptionAlgo());
        // Add non-compliant encryption method
        oidcProviderMetadata.getIDTokenJWEEncs().addAll(nonCompliantEncryptionMethod());
        return oidcProviderMetadata;
    }

    protected static OIDCProviderMetadata createCompliantMockObject() throws ParseException {
        String json = "{\n" + "  \"issuer\": \"https://your-oidc-provider.com\",\n"
                + "  \"authorization_endpoint\": \"https://your-oidc-provider.com/oauth2/authorize\",\n"
                + "  \"token_endpoint\": \"https://your-oidc-provider.com/oauth2/token\",\n"
                + "  \"userinfo_endpoint\": \"https://your-oidc-provider.com/oauth2/userinfo\",\n"
                + "  \"jwks_uri\": \"https://your-oidc-provider.com/.well-known/jwks.json\",\n"
                + "  \"registration_endpoint\": \"https://your-oidc-provider.com/oauth2/register\",\n" + "  \n"
                + "  \"scopes_supported\": [\n" + "    \"openid\",\n" + "    \"profile\",\n" + "    \"email\",\n"
                + "    \"address\",\n" + "    \"phone\",\n" + "    \"offline_access\"\n" + "  ],\n"
                + "  \"response_types_supported\": [\n" + "    \"code\",\n" + "    \"id_token\",\n"
                + "    \"token id_token\",\n" + "    \"code id_token\",\n" + "    \"code token\",\n"
                + "    \"code token id_token\"\n" + "  ],\n" + "  \"grant_types_supported\": [\n"
                + "    \"authorization_code\",\n" + "    \"implicit\",\n" + "    \"refresh_token\",\n"
                + "    \"client_credentials\"\n" + "  ],\n" + "  \"subject_types_supported\": [\n"
                + "    \"public\",\n" + "    \"pairwise\"\n" + "  ],\n"
                + "  \"id_token_signing_alg_values_supported\": [\n" + "    \"RS256\",\n" + "    \"RS384\",\n"
                + "    \"RS512\",\n" + "    \"ES256\",\n" + "    \"ES384\",\n" + "    \"ES512\",\n"
                + "    \"PS256\",\n" + "    \"PS384\",\n" + "    \"PS512\",\n" + "    \"HS256\",\n"
                + "    \"HS384\",\n" + "    \"HS512\" \n" + "  ],\n"
                + "  \"id_token_encryption_alg_values_supported\": [\n" + "    \"RSA-OAEP\", \n"
                + "    \"ECDH-ES\"\n" + "  ],\n" + "  \"id_token_encryption_enc_values_supported\": [\n"
                + "    \"A128CBC-HS256\",\n" + "    \"A192CBC-HS384\",\n" + "    \"A256CBC-HS512\",\n"
                + "    \"A128GCM\",\n" + "    \"A192GCM\",\n" + "    \"A256GCM\"\n" + "  ],\n"
                + "  \"userinfo_signing_alg_values_supported\": [\n" + "    \"RS256\",\n" + "    \"RS384\",\n"
                + "    \"RS512\",\n" + "    \"ES256\",\n" + "    \"ES384\",\n" + "    \"ES512\",\n"
                + "    \"PS256\",\n" + "    \"PS384\",\n" + "    \"PS512\",\n" + "    \"HS256\",\n"
                + "    \"HS384\",\n" + "    \"HS512\"\n" + "  ],\n"
                + "  \"userinfo_encryption_alg_values_supported\": [\n" + "    \"RSA-OAEP\",\n"
                + "    \"ECDH-ES\"\n" + "  ],\n" + "  \"userinfo_encryption_enc_values_supported\": [\n"
                + "    \"A128CBC-HS256\",\n" + "    \"A192CBC-HS384\",\n" + "    \"A256CBC-HS512\",\n"
                + "    \"A128GCM\",\n" + "    \"A192GCM\",\n" + "    \"A256GCM\"\n" + "  ],\n"
                + "  \"request_object_signing_alg_values_supported\": [\n" + "    \"RS256\",\n"
                + "    \"RS384\",\n" + "    \"RS512\",\n" + "    \"ES256\",\n" + "    \"ES384\",\n"
                + "    \"ES512\",\n" + "    \"PS256\",\n" + "    \"PS384\",\n" + "    \"PS512\",\n"
                + "    \"HS256\",\n" + "    \"HS384\",\n" + "    \"HS512\"\n" + "  ],\n"
                + "  \"request_object_encryption_alg_values_supported\": [\n" + "    \"RSA-OAEP\",\n"
                + "    \"ECDH-ES\"\n" + "  ],\n" + "  \"request_object_encryption_enc_values_supported\": [\n"
                + "    \"A128CBC-HS256\",\n" + "    \"A192CBC-HS384\",\n" + "    \"A256CBC-HS512\",\n"
                + "    \"A128GCM\",\n" + "    \"A192GCM\",\n" + "    \"A256GCM\"\n" + "  ],\n"
                + "  \"token_endpoint_auth_methods_supported\": [\n" + "    \"client_secret_basic\",\n"
                + "    \"client_secret_post\",\n" + "    \"private_key_jwt\"\n" + "  ],\n"
                + "  \"token_endpoint_auth_signing_alg_values_supported\": [\n" + "    \"RS256\",\n"
                + "    \"RS384\",\n" + "    \"RS512\",\n" + "    \"ES256\",\n" + "    \"ES384\",\n"
                + "    \"ES512\",\n" + "    \"PS256\",\n" + "    \"PS384\",\n" + "    \"PS512\",\n"
                + "    \"HS256\",\n" + "    \"HS384\",\n" + "    \"HS512\"\n" + "  ],\n"
                + "  \"claims_supported\": [\n" + "    \"sub\",\n" + "    \"name\",\n"
                + "    \"preferred_username\",\n" + "    \"email\",\n" + "    \"email_verified\",\n"
                + "    \"given_name\",\n" + "    \"family_name\",\n" + "    \"profile\",\n" + "    \"picture\",\n"
                + "    \"locale\",\n" + "    \"phone_number\",\n" + "    \"address\",\n" + "    \"birthdate\",\n"
                + "    \"gender\"\n" + "  ],\n" + "  \"claim_types_supported\": [\n" + "    \"normal\"\n"
                + "  ],\n" + "  \"claims_parameter_supported\": true,\n"
                + "  \"request_parameter_supported\": true,\n" + "  \"request_uri_parameter_supported\": true,\n"
                + "  \"require_request_uri_registration\": false,\n"
                + "  \"revocation_endpoint\": \"https://your-oidc-provider.com/oauth2/revoke\",\n"
                + "  \"revocation_endpoint_auth_methods_supported\": [\n" + "    \"client_secret_basic\",\n"
                + "    \"client_secret_post\",\n" + "    \"private_key_jwt\"\n" + "  ],\n"
                + "  \"revocation_endpoint_auth_signing_alg_values_supported\": [\n" + "    \"RS256\",\n"
                + "    \"RS384\",\n" + "    \"RS512\",\n" + "    \"ES256\",\n" + "    \"ES384\",\n"
                + "    \"ES512\",\n" + "    \"PS256\",\n" + "    \"PS384\",\n" + "    \"PS512\"\n" + "  ],\n"
                + "  \"introspection_endpoint\": \"https://your-oidc-provider.com/oauth2/introspect\",\n"
                + "  \"introspection_endpoint_auth_methods_supported\": [\n" + "    \"client_secret_basic\",\n"
                + "    \"client_secret_post\",\n" + "    \"private_key_jwt\"\n" + "  ],\n"
                + "  \"introspection_endpoint_auth_signing_alg_values_supported\": [\n" + "    \"RS256\",\n"
                + "    \"RS384\",\n" + "    \"RS512\",\n" + "    \"ES256\",\n" + "    \"ES384\",\n"
                + "    \"ES512\",\n" + "    \"PS256\",\n" + "    \"PS384\",\n" + "    \"PS512\"\n" + "  ],\n"
                + "  \"code_challenge_methods_supported\": [\n" + "    \"plain\",\n" + "    \"S256\"\n" + "  ],\n"
                + "  \"tls_client_certificate_bound_access_tokens\": true,\n"
                + "  \"backchannel_logout_supported\": true,\n"
                + "  \"backchannel_logout_session_supported\": true,\n"
                + "  \"frontchannel_logout_supported\": true,\n"
                + "  \"frontchannel_logout_session_supported\": true,\n"
                + "  \"end_session_endpoint\": \"https://your-oidc-provider.com/logout\"\n" + "}";
        JSONObject jsonObject = JSONObjectUtils.parse(json);
        jsonObject.put("issuer", new Issuer("https://op.example.com").getValue());
        jsonObject.put(
                "subject_types_supported",
                Arrays.asList(SubjectType.PUBLIC.toString(), SubjectType.PAIRWISE.toString()));
        jsonObject.put(
                "jwks_uri", URI.create("https://op.example.com/jwks.json").toString());

        return OIDCProviderMetadata.parse(jsonObject);
    }
}
