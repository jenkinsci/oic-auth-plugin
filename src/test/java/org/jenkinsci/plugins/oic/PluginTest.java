package org.jenkinsci.plugins.oic;

import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.github.tomakehurst.wiremock.junit.WireMockRule;
import com.google.api.client.auth.openidconnect.IdToken;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.client.json.webtoken.JsonWebSignature;
import hudson.model.User;
import hudson.tasks.Mailer;
import jenkins.model.Jenkins;
import org.acegisecurity.Authentication;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.Url;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Callable;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static org.jenkinsci.plugins.oic.TestRealm.EMAIL_FIELD;
import static org.jenkinsci.plugins.oic.TestRealm.FULL_NAME_FIELD;
import static org.jenkinsci.plugins.oic.TestRealm.GROUPS_FIELD;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

/**
 * goes trough a login scenario, the openid provider is mocked and always returns state. We aren't checking
 * if if openid connect or if the openid connect implementation works. Rather we are only
 * checking if the jenkins interaction works and if the plugin code works.
 */
@Url("https://jenkins.io/blog/2018/01/13/jep-200/")
public class PluginTest {
    private static final JsonFactory JSON_FACORY = new JacksonFactory();

    private static final String TEST_USER_USERNAME = "testUser";
    private static final String TEST_USER_EMAIL_ADDRESS = "test@jenkins.oic";
    private static final String TEST_USER_FULL_NAME = "Oic Test User";
    private static final String[] TEST_USER_GROUPS = new String[]{"group1", "group2"};

    @Rule public WireMockRule wireMockRule = new WireMockRule(new WireMockConfiguration().dynamicPort(),true);
    @Rule public JenkinsRule jenkinsRule = new JenkinsRule();

    private JenkinsRule.WebClient webClient;
    private Jenkins jenkins;

    @Before
    public  void setUp() {
        jenkins = jenkinsRule.getInstance();
        webClient = jenkinsRule.createWebClient();
    }

    @Test public void testLogin() throws Exception {
        KeyPair keyPair = createKeyPair();

        wireMockRule.stubFor(get(urlPathEqualTo("/authorization")).willReturn(
            aResponse()
                    .withStatus(302)
                    .withHeader("Content-Type", "text/html; charset=utf-8")
                    .withHeader("Location", jenkins.getRootUrl()+"securityRealm/finishLogin?state=state&code=code")
                    .withBody("")
        ));
        Map<String, Object> keyValues = new HashMap<>();
        keyValues.put(EMAIL_FIELD, TEST_USER_EMAIL_ADDRESS);
        keyValues.put(FULL_NAME_FIELD, TEST_USER_FULL_NAME);
        keyValues.put(GROUPS_FIELD, TEST_USER_GROUPS);

        wireMockRule.stubFor(post(urlPathEqualTo("/token")).willReturn(
            aResponse()
                .withHeader("Content-Type", "text/html; charset=utf-8")
                .withBody("{" +
                            "\"id_token\": \""+createIdToken(keyPair.getPrivate(), keyValues)+"\"," +
                            "\"access_token\":\"AcCeSs_ToKeN\"," +
                            "\"token_type\":\"example\"," +
                            "\"expires_in\":3600," +
                            "\"refresh_token\":\"ReFrEsH_ToKeN\"," +
                            "\"example_parameter\":\"example_value\"" +
                        "}")
        ));


        jenkins.setSecurityRealm(new TestRealm(wireMockRule));

        assertEquals("Shouldn't be authenticated", getAuthentication().getPrincipal(), Jenkins.ANONYMOUS.getPrincipal());

        webClient.goTo(jenkins.getSecurityRealm().getLoginUrl());

        Authentication authentication = getAuthentication();
        assertEquals("Should be logged-in as "+ TEST_USER_USERNAME, TEST_USER_USERNAME, authentication.getPrincipal());
        User user = User.get(String.valueOf(authentication.getPrincipal()));
        assertEquals("Full name should be "+TEST_USER_FULL_NAME, TEST_USER_FULL_NAME, user.getFullName());
        assertEquals("Email should be "+ TEST_USER_EMAIL_ADDRESS, TEST_USER_EMAIL_ADDRESS, user.getProperty(Mailer.UserProperty.class).getAddress());
        assertTrue("User should be part of group "+ TEST_USER_GROUPS[0], user.getAuthorities().contains(TEST_USER_GROUPS[0]));
        assertTrue("User should be part of group "+ TEST_USER_GROUPS[1], user.getAuthorities().contains(TEST_USER_GROUPS[1]));
    }

    @Test public void testLoginWithMinimalConfiguration() throws Exception {
        KeyPair keyPair = createKeyPair();

        wireMockRule.stubFor(get(urlPathEqualTo("/authorization")).willReturn(
            aResponse()
                    .withStatus(302)
                    .withHeader("Content-Type", "text/html; charset=utf-8")
                    .withHeader("Location", jenkins.getRootUrl()+"securityRealm/finishLogin?state=state&code=code")
                    .withBody("")
        ));
        Map<String, Object> keyValues = new HashMap<>();
        keyValues.put(EMAIL_FIELD, TEST_USER_EMAIL_ADDRESS);
        keyValues.put(FULL_NAME_FIELD, TEST_USER_FULL_NAME);
        keyValues.put(GROUPS_FIELD, TEST_USER_GROUPS);

        wireMockRule.stubFor(post(urlPathEqualTo("/token")).willReturn(
            aResponse()
                .withHeader("Content-Type", "text/html; charset=utf-8")
                .withBody("{" +
                            "\"id_token\": \""+createIdToken(keyPair.getPrivate(), keyValues)+"\"," +
                            "\"access_token\":\"AcCeSs_ToKeN\"," +
                            "\"token_type\":\"example\"," +
                            "\"expires_in\":3600," +
                            "\"refresh_token\":\"ReFrEsH_ToKeN\"," +
                            "\"example_parameter\":\"example_value\"" +
                        "}")
        ));


        jenkins.setSecurityRealm(new TestRealm(wireMockRule, null, null, null));

        assertEquals("Shouldn't be authenticated", getAuthentication().getPrincipal(), Jenkins.ANONYMOUS.getPrincipal());

        webClient.goTo(jenkins.getSecurityRealm().getLoginUrl());

        Authentication authentication = getAuthentication();
        assertEquals("Should be logged-in as "+ TEST_USER_USERNAME, TEST_USER_USERNAME, authentication.getPrincipal());
        User user = User.get(String.valueOf(authentication.getPrincipal()));
        assertEquals("Full name should be "+TEST_USER_FULL_NAME, TEST_USER_FULL_NAME, user.getFullName());
        assertEquals("Email should be null"+ TEST_USER_EMAIL_ADDRESS, null, user.getProperty(Mailer.UserProperty.class).getAddress());
        assertTrue("User should be not be part of any group", user.getAuthorities().isEmpty());
    }
    
    @Test public void testLoginUsingUserInfoEndpoint() throws Exception {
        wireMockRule.resetAll();

        KeyPair keyPair = createKeyPair();

        wireMockRule.stubFor(get(urlPathEqualTo("/authorization")).willReturn(
                aResponse()
                        .withStatus(302)
                        .withHeader("Content-Type", "text/html; charset=utf-8")
                        .withHeader("Location", jenkins.getRootUrl()+"securityRealm/finishLogin?state=state&code=code")
                        .withBody("")
        ));
        wireMockRule.stubFor(post(urlPathEqualTo("/token")).willReturn(
                aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("{" +
                                "\"id_token\": \""+createIdToken(keyPair.getPrivate(),Collections.<String,Object>emptyMap())+"\"," +
                                "\"access_token\":\"AcCeSs_ToKeN\"," +
                                "\"token_type\":\"example\"," +
                                "\"expires_in\":3600," +
                                "\"refresh_token\":\"ReFrEsH_ToKeN\"," +
                                "\"example_parameter\":\"example_value\"" +
                                "}")
        ));
        wireMockRule.stubFor(get(urlPathEqualTo("/userinfo")).willReturn(
                aResponse()
                    .withHeader("Content-Type", "application/json")
                    .withBody("{\n" +
                            "   \"sub\": \""+TEST_USER_USERNAME+"\",\n" +
                            "   \""+FULL_NAME_FIELD+"\": \""+TEST_USER_FULL_NAME+"\",\n" +
                            "   \""+EMAIL_FIELD+"\": \""+TEST_USER_EMAIL_ADDRESS+"\",\n" +
                            "   \""+GROUPS_FIELD+"\": "+toJsonArray(TEST_USER_GROUPS)+"\n" +
                            "  }")
        ));


        jenkins.setSecurityRealm(new TestRealm(wireMockRule, "http://localhost:" + wireMockRule.port() + "/userinfo"));

        assertEquals("Shouldn't be authenticated", getAuthentication().getPrincipal(), Jenkins.ANONYMOUS.getPrincipal());

        webClient.goTo(jenkins.getSecurityRealm().getLoginUrl());

        Authentication authentication = getAuthentication();
        assertEquals("Should be logged-in as "+ TEST_USER_USERNAME, authentication.getPrincipal(), TEST_USER_USERNAME);
        User user = User.get(String.valueOf(authentication.getPrincipal()));
        assertEquals("Full name should be "+TEST_USER_FULL_NAME, TEST_USER_FULL_NAME, user.getFullName());
        assertEquals("Email should be "+ TEST_USER_EMAIL_ADDRESS, TEST_USER_EMAIL_ADDRESS, user.getProperty(Mailer.UserProperty.class).getAddress());
        assertTrue("User should be part of group "+ TEST_USER_GROUPS[0], user.getAuthorities().contains(TEST_USER_GROUPS[0]));
        assertTrue("User should be part of group "+ TEST_USER_GROUPS[1], user.getAuthorities().contains(TEST_USER_GROUPS[1]));
    }

    @Test public void testNestedFieldLookup() throws Exception {
        KeyPair keyPair = createKeyPair();

        wireMockRule.stubFor(get(urlPathEqualTo("/authorization")).willReturn(
            aResponse()
                .withStatus(302)
                .withHeader("Content-Type", "text/html; charset=utf-8")
                .withHeader("Location", jenkins.getRootUrl()+"securityRealm/finishLogin?state=state&code=code")
                .withBody("")
        ));
        Map<String, Object> nested = new HashMap<>();
        nested.put("email", TEST_USER_EMAIL_ADDRESS);
        nested.put("groups", TEST_USER_GROUPS);
        Map<String, Object> keyValues = new HashMap<>();
        keyValues.put("nested", nested);
        keyValues.put(FULL_NAME_FIELD, TEST_USER_FULL_NAME);

        wireMockRule.stubFor(post(urlPathEqualTo("/token")).willReturn(
            aResponse()
                .withHeader("Content-Type", "text/html; charset=utf-8")
                .withBody("{" +
                    "\"id_token\": \""+createIdToken(keyPair.getPrivate(), keyValues)+"\"," +
                    "\"access_token\":\"AcCeSs_ToKeN\"," +
                    "\"token_type\":\"example\"," +
                    "\"expires_in\":3600," +
                    "\"refresh_token\":\"ReFrEsH_ToKeN\"," +
                    "\"example_parameter\":\"example_value\"" +
                    "}")
        ));


        jenkins.setSecurityRealm(new TestRealm(wireMockRule, null, "nested.email", "nested.groups"));

        assertEquals("Shouldn't be authenticated", getAuthentication().getPrincipal(), Jenkins.ANONYMOUS.getPrincipal());

        webClient.goTo(jenkins.getSecurityRealm().getLoginUrl());

        Authentication authentication = getAuthentication();
        assertEquals("Should be logged-in as "+ TEST_USER_USERNAME, authentication.getPrincipal(), TEST_USER_USERNAME);
        User user = User.get(String.valueOf(authentication.getPrincipal()));
        assertEquals("Full name should be "+TEST_USER_FULL_NAME, TEST_USER_FULL_NAME, user.getFullName());
        assertEquals("Email should be "+ TEST_USER_EMAIL_ADDRESS, TEST_USER_EMAIL_ADDRESS, user.getProperty(Mailer.UserProperty.class).getAddress());
        assertTrue("User should be part of group "+ TEST_USER_GROUPS[0], user.getAuthorities().contains(TEST_USER_GROUPS[0]));
        assertTrue("User should be part of group "+ TEST_USER_GROUPS[1], user.getAuthorities().contains(TEST_USER_GROUPS[1]));
    }

    @Test public void testNestedFieldLookupFromUserInfoEndpoint() throws Exception {
        wireMockRule.resetAll();

        KeyPair keyPair = createKeyPair();

        wireMockRule.stubFor(get(urlPathEqualTo("/authorization")).willReturn(
            aResponse()
                .withStatus(302)
                .withHeader("Content-Type", "text/html; charset=utf-8")
                .withHeader("Location", jenkins.getRootUrl()+"securityRealm/finishLogin?state=state&code=code")
                .withBody("")
        ));
        wireMockRule.stubFor(post(urlPathEqualTo("/token")).willReturn(
            aResponse()
                .withHeader("Content-Type", "application/json")
                .withBody("{" +
                    "\"id_token\": \""+createIdToken(keyPair.getPrivate(),Collections.<String,Object>emptyMap())+"\"," +
                    "\"access_token\":\"AcCeSs_ToKeN\"," +
                    "\"token_type\":\"example\"," +
                    "\"expires_in\":3600," +
                    "\"refresh_token\":\"ReFrEsH_ToKeN\"," +
                    "\"example_parameter\":\"example_value\"" +
                    "}")
        ));
        wireMockRule.stubFor(get(urlPathEqualTo("/userinfo")).willReturn(
            aResponse()
                .withHeader("Content-Type", "application/json")
                .withBody("{\n" +
                    "   \"sub\": \""+TEST_USER_USERNAME+"\",\n" +
                    "   \""+FULL_NAME_FIELD+"\": \""+TEST_USER_FULL_NAME+"\",\n" +
                    "   \"nested\": {\n" +
                    "     \"email\": \""+TEST_USER_EMAIL_ADDRESS+"\",\n" +
                    "     \"groups\": "+toJsonArray(TEST_USER_GROUPS)+"\n" +
                    "   }\n" +
                    "  }")
        ));


        jenkins.setSecurityRealm(new TestRealm(wireMockRule, "http://localhost:" + wireMockRule.port() + "/userinfo", "nested.email", "nested.groups"));

        assertEquals("Shouldn't be authenticated", getAuthentication().getPrincipal(), Jenkins.ANONYMOUS.getPrincipal());

        webClient.goTo(jenkins.getSecurityRealm().getLoginUrl());

        Authentication authentication = getAuthentication();
        assertEquals("Should be logged-in as "+ TEST_USER_USERNAME, authentication.getPrincipal(), TEST_USER_USERNAME);
        User user = User.get(String.valueOf(authentication.getPrincipal()));
        assertEquals("Full name should be "+TEST_USER_FULL_NAME, TEST_USER_FULL_NAME, user.getFullName());
        assertEquals("Email should be "+ TEST_USER_EMAIL_ADDRESS, TEST_USER_EMAIL_ADDRESS, user.getProperty(Mailer.UserProperty.class).getAddress());
        assertTrue("User should be part of group "+ TEST_USER_GROUPS[0], user.getAuthorities().contains(TEST_USER_GROUPS[0]));
        assertTrue("User should be part of group "+ TEST_USER_GROUPS[1], user.getAuthorities().contains(TEST_USER_GROUPS[1]));
    }

    private String toJsonArray(String[] array) {
        StringBuilder builder = new StringBuilder();
        builder.append("[");
        for(String entry : array) {
            builder.append("\"").append(entry).append("\",");
        }
        if(builder.lastIndexOf(",") != -1) {
            builder.deleteCharAt(builder.length()-1);
        }
        builder.append("]");
        return builder.toString();
    }

    private KeyPair createKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        return keyGen.generateKeyPair();
    }

    private String createIdToken(PrivateKey privateKey, Map<String, Object> keyValues) throws Exception {
        JsonWebSignature.Header header = new JsonWebSignature.Header()
            .setAlgorithm("RS256");
        IdToken.Payload payload = new IdToken.Payload()
            .setIssuer("issuer")
            .setSubject(TEST_USER_USERNAME)
            .setAudience(Collections.singletonList("clientId"))
            .setAudience(System.currentTimeMillis() / 60 + 5)
            .setIssuedAtTimeSeconds(System.currentTimeMillis() / 60);
        for(Map.Entry<String, Object> keyValue : keyValues.entrySet()) {
            payload.set(keyValue.getKey(), keyValue.getValue());
        }

        return JsonWebSignature.signUsingRsaSha256(privateKey, JSON_FACORY, header, payload);
    }

    /**
     * Gets the authentication object from the web client.
     *
     * @return the authentication object
     */
    private Authentication getAuthentication() {
        try {
            return webClient.executeOnServer(new Callable<Authentication>() {
                public  Authentication call() throws Exception {
                    return jenkins.getAuthentication();
                }
            });
        } catch (Exception e) {
            // safely ignore all exceptions, the method never throws anything
            return null;
        }

    }

}