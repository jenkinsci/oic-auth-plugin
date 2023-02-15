package org.jenkinsci.plugins.oic;

import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.github.tomakehurst.wiremock.junit.WireMockRule;
import com.google.api.client.auth.openidconnect.IdToken;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.client.json.webtoken.JsonWebSignature;
import com.google.api.client.json.webtoken.JsonWebToken;
import com.google.api.client.util.ArrayMap;
import com.google.gson.JsonElement;
import hudson.model.User;
import hudson.tasks.Mailer;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import jenkins.model.Jenkins;
import org.acegisecurity.Authentication;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.Url;
import org.kohsuke.stapler.Stapler;

import static com.github.tomakehurst.wiremock.client.WireMock.absent;
import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.containing;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.matching;
import static com.github.tomakehurst.wiremock.client.WireMock.notMatching;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.verify;
import static com.google.gson.JsonParser.parseString;
import static org.jenkinsci.plugins.oic.TestRealm.AUTO_CONFIG_FIELD;
import static org.jenkinsci.plugins.oic.TestRealm.EMAIL_FIELD;
import static org.jenkinsci.plugins.oic.TestRealm.FULL_NAME_FIELD;
import static org.jenkinsci.plugins.oic.TestRealm.GROUPS_FIELD;
import static org.jenkinsci.plugins.oic.TestRealm.MANUAL_CONFIG_FIELD;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * goes trough a login scenario, the openid provider is mocked and always returns state. We aren't checking
 * if if openid connect or if the openid connect implementation works. Rather we are only
 * checking if the jenkins interaction works and if the plugin code works.
 */
@Url("https://jenkins.io/blog/2018/01/13/jep-200/")
public class PluginTest {
    private static final JsonFactory JSON_FACTORY = new JacksonFactory();

    private static final String TEST_USER_USERNAME = "testUser";
    private static final String TEST_USER_EMAIL_ADDRESS = "test@jenkins.oic";
    private static final String TEST_USER_FULL_NAME = "Oic Test User";
    private static final String[] TEST_USER_GROUPS = new String[]{"group1", "group2"};
    private static final List<Map<String,String>> TEST_USER_GROUPS_MAP = new ArrayList<>();
    private static final String OPENID_CONNECT_USER_PROPERTY = "OpenID Connect user property";

    @Rule public WireMockRule wireMockRule = new WireMockRule(new WireMockConfiguration().dynamicPort(),true);
    @Rule public JenkinsRule jenkinsRule = new JenkinsRule();

    private JenkinsRule.WebClient webClient;
    private Jenkins jenkins;

    @BeforeClass
    public static void oneTimeSetUp() {
        TEST_USER_GROUPS_MAP.add(ArrayMap.<String,String>of("id", "id1", "name", "group1" ));
        TEST_USER_GROUPS_MAP.add(ArrayMap.<String,String>of("id", "id2", "name", "group2" ));
    }

    @Before
    public void setUp() {
        jenkins = jenkinsRule.getInstance();
        webClient = jenkinsRule.createWebClient();
    }

    @Test public void testLoginWithDefaults() throws Exception {
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
        assertEquals("Should be logged-in as " + TEST_USER_USERNAME, TEST_USER_USERNAME, authentication.getPrincipal());
        User user = User.get(String.valueOf(authentication.getPrincipal()));
        assertEquals("Full name should be " +TEST_USER_FULL_NAME, TEST_USER_FULL_NAME, user.getFullName());
        assertEquals("Email should be " + TEST_USER_EMAIL_ADDRESS, TEST_USER_EMAIL_ADDRESS, user.getProperty(Mailer.UserProperty.class).getAddress());
        assertTrue("User should be part of group " + TEST_USER_GROUPS[0], user.getAuthorities().contains(TEST_USER_GROUPS[0]));
        assertTrue("User should be part of group " + TEST_USER_GROUPS[1], user.getAuthorities().contains(TEST_USER_GROUPS[1]));

        verify(getRequestedFor(urlPathEqualTo("/authorization"))
                .withQueryParam("scope", equalTo("openid email"))
                .withQueryParam("nonce", matching(".+")));
        verify(postRequestedFor(urlPathEqualTo("/token"))
                .withRequestBody(notMatching(".*&scope=.*")));
    }

    @Test public void testLoginWithScopesInTokenRequest() throws Exception {
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


        TestRealm oidcSecurityRealm = new TestRealm(wireMockRule);
        oidcSecurityRealm.setSendScopesInTokenRequest(true);
        jenkins.setSecurityRealm(oidcSecurityRealm);
        webClient.goTo(jenkins.getSecurityRealm().getLoginUrl());

        verify(getRequestedFor(urlPathEqualTo("/authorization"))
                .withQueryParam("scope", equalTo("openid email")));
        verify(postRequestedFor(urlPathEqualTo("/token"))
                .withRequestBody(containing("&scope=openid+email&")));
    }

    @Test public void testLoginWithPkceEnabled() throws Exception {
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


        TestRealm oidcSecurityRealm = new TestRealm(wireMockRule);
        oidcSecurityRealm.setPkceEnabled(true);
        jenkins.setSecurityRealm(oidcSecurityRealm);
        webClient.goTo(jenkins.getSecurityRealm().getLoginUrl());

        verify(getRequestedFor(urlPathEqualTo("/authorization"))
                .withQueryParam("code_challenge_method", equalTo("S256"))
                .withQueryParam("code_challenge", matching(".+")));
    }

    @Test public void testLoginWithNonceDisabled() throws Exception {
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

        TestRealm oidcSecurityRealm = new TestRealm(wireMockRule);
        oidcSecurityRealm.setNonceDisabled(true);
        jenkins.setSecurityRealm(oidcSecurityRealm);
        webClient.goTo(jenkins.getSecurityRealm().getLoginUrl());

        verify(getRequestedFor(urlPathEqualTo("/authorization"))
                .withQueryParam("nonce", absent()));
    }

    @Test public void testLoginUsingUserInfoEndpointWithGroupsMap() throws Exception {
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
                            "   \""+GROUPS_FIELD+"\": "+toJsonArray(TEST_USER_GROUPS_MAP)+"\n" +
                            "  }")
        ));

        System.out.println("jsonarray : " + toJsonArray(TEST_USER_GROUPS_MAP ));
        jenkins.setSecurityRealm(new TestRealm(wireMockRule, "http://localhost:" + wireMockRule.port() + "/userinfo", "email", "groups[].name"));
        assertEquals("Shouldn't be authenticated", getAuthentication().getPrincipal(), Jenkins.ANONYMOUS.getPrincipal());

        webClient.goTo(jenkins.getSecurityRealm().getLoginUrl());

        Authentication authentication = getAuthentication();
        assertEquals("Should be logged-in as "+ TEST_USER_USERNAME, authentication.getPrincipal(), TEST_USER_USERNAME);
        User user = User.get(String.valueOf(authentication.getPrincipal()));
        assertEquals("Full name should be "+TEST_USER_FULL_NAME, TEST_USER_FULL_NAME, user.getFullName());
        assertEquals("Email should be "+ TEST_USER_EMAIL_ADDRESS, TEST_USER_EMAIL_ADDRESS, user.getProperty(Mailer.UserProperty.class).getAddress());
        assertTrue("User should be part of group "+ TEST_USER_GROUPS_MAP.get(0).get("name"), user.getAuthorities().contains(TEST_USER_GROUPS_MAP.get(0).get("name")));
        assertTrue("User should be part of group "+ TEST_USER_GROUPS_MAP.get(1).get("name"), user.getAuthorities().contains(TEST_USER_GROUPS_MAP.get(1).get("name")));
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
        assertEquals("Should be logged-in as " + TEST_USER_USERNAME, TEST_USER_USERNAME, authentication.getPrincipal());
        User user = User.get(String.valueOf(authentication.getPrincipal()));
        assertEquals("Full name should be " +TEST_USER_FULL_NAME, TEST_USER_FULL_NAME, user.getFullName());
        assertTrue("User should be not be part of any group", user.getAuthorities().isEmpty());
    }

    @Test public void testLoginWithAutoConfiguration() throws Exception {
        KeyPair keyPair = createKeyPair();

        wireMockRule.stubFor(get(urlPathEqualTo("/authorization"))
            .willReturn(aResponse().withStatus(302).withHeader("Content-Type", "text/html; charset=utf-8")
                .withHeader("Location", jenkins.getRootUrl() + "securityRealm/finishLogin?state=state&code=code")
                .withBody("")));
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

        configureWellKnown(null, null);

        jenkins.setSecurityRealm(new TestRealm(wireMockRule, null, EMAIL_FIELD, GROUPS_FIELD, AUTO_CONFIG_FIELD));

        assertEquals("Shouldn't be authenticated", getAuthentication().getPrincipal(), Jenkins.ANONYMOUS.getPrincipal());

        webClient.goTo(jenkins.getSecurityRealm().getLoginUrl());

        Authentication authentication = getAuthentication();
        assertEquals("Should be logged-in as " + TEST_USER_USERNAME, TEST_USER_USERNAME, authentication.getPrincipal());
        User user = User.get(String.valueOf(authentication.getPrincipal()));
        assertEquals("Full name should be " + TEST_USER_FULL_NAME, TEST_USER_FULL_NAME, user.getFullName());
        assertEquals("Email should be " + TEST_USER_EMAIL_ADDRESS, TEST_USER_EMAIL_ADDRESS, user.getProperty(Mailer.UserProperty.class).getAddress());
        assertTrue("User should be part of group " + TEST_USER_GROUPS[0], user.getAuthorities().contains(TEST_USER_GROUPS[0]));
        assertTrue("User should be part of group " + TEST_USER_GROUPS[1], user.getAuthorities().contains(TEST_USER_GROUPS[1]));
    }

    @Test public void testLoginWithAutoConfiguration_WithNoScope() throws Exception {
        KeyPair keyPair = createKeyPair();

        wireMockRule.stubFor(get(urlPathEqualTo("/authorization"))
            .willReturn(aResponse().withStatus(302).withHeader("Content-Type", "text/html; charset=utf-8")
                .withHeader("Location", jenkins.getRootUrl() + "securityRealm/finishLogin?state=state&code=code")
                .withBody("")));
        Map<String, Object> keyValues = new HashMap<>();
        keyValues.put(EMAIL_FIELD, TEST_USER_EMAIL_ADDRESS);
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

        wireMockRule.stubFor(get(urlPathEqualTo("/userinfo")).willReturn(
                aResponse()
                    .withHeader("Content-Type", "application/json")
                    .withBody("{\n" +
                            "   \"sub\": \""+TEST_USER_USERNAME+"\",\n" +
                            "   \""+FULL_NAME_FIELD+"\": \""+TEST_USER_FULL_NAME+"\",\n" +
                            "   \""+EMAIL_FIELD+"\": \""+TEST_USER_EMAIL_ADDRESS+"\"\n" +
                            "  }")
        ));

        configureWellKnown(null, null);

        jenkins.setSecurityRealm(new TestRealm(wireMockRule, null, EMAIL_FIELD, GROUPS_FIELD, AUTO_CONFIG_FIELD));

        assertEquals("Shouldn't be authenticated", getAuthentication().getPrincipal(), Jenkins.ANONYMOUS.getPrincipal());

        configureWellKnown(null, null);

        jenkins.setSecurityRealm(new TestRealm(wireMockRule, null, EMAIL_FIELD, GROUPS_FIELD, AUTO_CONFIG_FIELD));

        assertEquals("Shouldn't be authenticated", getAuthentication().getPrincipal(), Jenkins.ANONYMOUS.getPrincipal());

        webClient.goTo(jenkins.getSecurityRealm().getLoginUrl());

        Authentication authentication = getAuthentication();
        assertEquals("Should be logged-in as " + TEST_USER_USERNAME, TEST_USER_USERNAME, authentication.getPrincipal());
        User user = User.get(String.valueOf(authentication.getPrincipal()));
        assertEquals("Full name should be " + TEST_USER_FULL_NAME, TEST_USER_FULL_NAME, user.getFullName());
        assertEquals("Email should be " + TEST_USER_EMAIL_ADDRESS, TEST_USER_EMAIL_ADDRESS, user.getProperty(Mailer.UserProperty.class).getAddress());
        assertTrue("User should be not be part of any group", user.getAuthorities().isEmpty());
    }

    @Test public void testConfigurationWithAutoConfiguration_withScopeOverride() throws Exception {
        configureWellKnown(null, "[\"openid\",\"profile\",\"scope1\",\"scope2\",\"scope3\"]");
        TestRealm oicsr = new TestRealm.Builder(wireMockRule).WithMinimalDefaults()
            .WithAutomanualconfigure("auto")
            .build();
        assertEquals("All scopes of WellKnown should be used" ,"openid profile scope1 scope2 scope3", oicsr.getScopes());

        oicsr.setOverrideScopes("openid profile scope2 other");
        assertEquals("Predefined scopes of WellKnown should be used" ,"openid profile scope2", oicsr.getScopes());

        oicsr.setScopes("openid profile other");
        oicsr.setOverrideScopes("");
        oicsr.setWellKnownOpenIDConfigurationUrl(oicsr.getWellKnownOpenIDConfigurationUrl());
        assertEquals("All scopes of WellKnown should be used" ,"openid profile scope1 scope2 scope3", oicsr.getScopes());
    }

    @Test public void testreadResolve_withNulls() throws Exception {
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

        configureWellKnown(null, null);

        TestRealm realm = new TestRealm(wireMockRule, null, null, null, AUTO_CONFIG_FIELD);
        jenkins.setSecurityRealm(realm);

        assertEquals(realm, realm.readResolve());
    }

    @Test
    public void testreadResolve_withNonNulls() throws Exception {
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

        configureWellKnown("http://localhost/endSession", null);

        TestRealm realm = new TestRealm(wireMockRule, null, null, null, AUTO_CONFIG_FIELD);
        jenkins.setSecurityRealm(realm);

        assertEquals(realm, realm.readResolve());
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
        assertEquals("Should be logged-in as " + TEST_USER_USERNAME, authentication.getPrincipal(), TEST_USER_USERNAME);
        User user = User.get(String.valueOf(authentication.getPrincipal()));
        assertEquals("Full name should be " + TEST_USER_FULL_NAME, TEST_USER_FULL_NAME, user.getFullName());
        assertEquals("Email should be " + TEST_USER_EMAIL_ADDRESS, TEST_USER_EMAIL_ADDRESS, user.getProperty(Mailer.UserProperty.class).getAddress());
        assertTrue("User should be part of group " + TEST_USER_GROUPS[0], user.getAuthorities().contains(TEST_USER_GROUPS[0]));
        assertTrue("User should be part of group " + TEST_USER_GROUPS[1], user.getAuthorities().contains(TEST_USER_GROUPS[1]));
    }

    @Test public void testLoginUsingUserInfoWithJWT() throws Exception {
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
                    .withHeader("Content-Type", "application/jwt")
                    .withBody(createUserInfoJWT(keyPair.getPrivate(),"{\n" +
                            "   \"sub\": \""+TEST_USER_USERNAME+"\",\n" +
                            "   \""+FULL_NAME_FIELD+"\": \""+TEST_USER_FULL_NAME+"\",\n" +
                            "   \""+EMAIL_FIELD+"\": \""+TEST_USER_EMAIL_ADDRESS+"\",\n" +
                            "   \""+GROUPS_FIELD+"\": \""+TEST_USER_GROUPS[0]+"\"\n" +
                            "  }"))
        ));


        jenkins.setSecurityRealm(new TestRealm(wireMockRule, "http://localhost:" + wireMockRule.port() + "/userinfo"));

        assertEquals("Shouldn't be authenticated", getAuthentication().getPrincipal(), Jenkins.ANONYMOUS.getPrincipal());

        webClient.goTo(jenkins.getSecurityRealm().getLoginUrl());

        Authentication authentication = getAuthentication();
        assertEquals("Should be logged-in as " + TEST_USER_USERNAME, authentication.getPrincipal(), TEST_USER_USERNAME);
        User user = User.get(String.valueOf(authentication.getPrincipal()));
        assertEquals("Full name should be " + TEST_USER_FULL_NAME, TEST_USER_FULL_NAME, user.getFullName());
        assertEquals("Email should be " + TEST_USER_EMAIL_ADDRESS, TEST_USER_EMAIL_ADDRESS, user.getProperty(Mailer.UserProperty.class).getAddress());
        assertTrue("User should be part of group " + TEST_USER_GROUPS[0], user.getAuthorities().contains(TEST_USER_GROUPS[0]));
    }

    @Test public void testShouldLogUserWithoutGroupsWhenUserGroupIsMissing() throws Exception {
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
                            "   \""+EMAIL_FIELD+"\": \""+TEST_USER_EMAIL_ADDRESS+"\"\n" +
                            "  }")
        ));


        jenkins.setSecurityRealm(new TestRealm(wireMockRule, "http://localhost:" + wireMockRule.port() + "/userinfo"));

        assertEquals("Shouldn't be authenticated", getAuthentication().getPrincipal(), Jenkins.ANONYMOUS.getPrincipal());

        webClient.goTo(jenkins.getSecurityRealm().getLoginUrl());

        Authentication authentication = getAuthentication();
        User user = User.get(String.valueOf(authentication.getPrincipal()));
        assertTrue("User shouldn't be part of any group", user.getAuthorities().isEmpty());
    }

    @Test public void testShouldLogUserWithoutGroupsWhenUserGroupIsNull() throws Exception {
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
                            "   \""+GROUPS_FIELD+"\": null\n" +
                            "  }")
        ));


        jenkins.setSecurityRealm(new TestRealm(wireMockRule, "http://localhost:" + wireMockRule.port() + "/userinfo"));

        assertEquals("Shouldn't be authenticated", getAuthentication().getPrincipal(), Jenkins.ANONYMOUS.getPrincipal());

        webClient.goTo(jenkins.getSecurityRealm().getLoginUrl());

        Authentication authentication = getAuthentication();
        User user = User.get(String.valueOf(authentication.getPrincipal()));
        assertTrue("User shouldn't be part of any group", user.getAuthorities().isEmpty());
    }

    @Test public void testShouldLogUserWithoutGroupsWhenUserGroupIsNotAStringList() throws Exception {
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
                            "   \""+GROUPS_FIELD+"\": {\"not\": \"a group\"}\n" +
                            "  }")
        ));


        jenkins.setSecurityRealm(new TestRealm(wireMockRule, "http://localhost:" + wireMockRule.port() + "/userinfo"));

        assertEquals("Shouldn't be authenticated", getAuthentication().getPrincipal(), Jenkins.ANONYMOUS.getPrincipal());

        webClient.goTo(jenkins.getSecurityRealm().getLoginUrl());

        Authentication authentication = getAuthentication();
        User user = User.get(String.valueOf(authentication.getPrincipal()));
        assertTrue("User shouldn't be part of any group", user.getAuthorities().isEmpty());
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
        assertEquals("Should be logged-in as " + TEST_USER_USERNAME, authentication.getPrincipal(), TEST_USER_USERNAME);
        User user = User.get(String.valueOf(authentication.getPrincipal()));
        assertEquals("Full name should be " +TEST_USER_FULL_NAME, TEST_USER_FULL_NAME, user.getFullName());
        assertEquals("Email should be " + TEST_USER_EMAIL_ADDRESS, TEST_USER_EMAIL_ADDRESS, user.getProperty(Mailer.UserProperty.class).getAddress());
        assertTrue("User should be part of group " + TEST_USER_GROUPS[0], user.getAuthorities().contains(TEST_USER_GROUPS[0]));
        assertTrue("User should be part of group " + TEST_USER_GROUPS[1], user.getAuthorities().contains(TEST_USER_GROUPS[1]));
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
        assertEquals("Should be logged-in as " + TEST_USER_USERNAME, authentication.getPrincipal(), TEST_USER_USERNAME);
        User user = User.get(String.valueOf(authentication.getPrincipal()));
        assertEquals("Full name should be " +TEST_USER_FULL_NAME, TEST_USER_FULL_NAME, user.getFullName());
        assertEquals("Email should be " + TEST_USER_EMAIL_ADDRESS, TEST_USER_EMAIL_ADDRESS, user.getProperty(Mailer.UserProperty.class).getAddress());
        assertTrue("User should be part of group " + TEST_USER_GROUPS[0], user.getAuthorities().contains(TEST_USER_GROUPS[0]));
        assertTrue("User should be part of group " + TEST_USER_GROUPS[1], user.getAuthorities().contains(TEST_USER_GROUPS[1]));
    }

    @Test public void testFieldLookupFromIdTokenWhenNotInUserInfoEndpoint() throws Exception {
        wireMockRule.resetAll();

        KeyPair keyPair = createKeyPair();

        wireMockRule.stubFor(get(urlPathEqualTo("/authorization")).willReturn(
            aResponse()
                .withStatus(302)
                .withHeader("Content-Type", "text/html; charset=utf-8")
                .withHeader("Location", jenkins.getRootUrl()+"securityRealm/finishLogin?state=state&code=code")
                .withBody("")
        ));

        Map<String, Object> keyValues = new HashMap<>();
        keyValues.put("sub", TEST_USER_USERNAME);
        keyValues.put(EMAIL_FIELD, TEST_USER_EMAIL_ADDRESS);
        keyValues.put(FULL_NAME_FIELD, TEST_USER_FULL_NAME);
        keyValues.put(GROUPS_FIELD, TEST_USER_GROUPS);

        wireMockRule.stubFor(post(urlPathEqualTo("/token")).willReturn(
            aResponse()
                .withHeader("Content-Type", "application/json")
                .withBody("{" +
                    "\"id_token\": \""+createIdToken(keyPair.getPrivate(), keyValues)+"\"," +
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
                                "   \"sub\": \"\",\n" +
                                "   \""+FULL_NAME_FIELD+"\": null,\n" +
                                "   \"groups\": \"["+TEST_USER_GROUPS[0]+", "+TEST_USER_GROUPS[1]+"]\"\n" +
                                "  }")
        ));


        jenkins.setSecurityRealm(new TestRealm(wireMockRule, "http://localhost:" + wireMockRule.port() + "/userinfo", "email", "groups"));
        webClient.goTo(jenkins.getSecurityRealm().getLoginUrl());

        Authentication authentication = getAuthentication();
        assertEquals("Should read field (ex:username) from IdToken when empty in userInfo", authentication.getPrincipal(), TEST_USER_USERNAME);
        User user = User.get(String.valueOf(authentication.getPrincipal()));
        assertEquals("Should read field (ex:full name) from IdToken when null in userInfo", TEST_USER_FULL_NAME, user.getFullName());
        assertEquals("Should read field (ex:email) from IdToken when not in userInfo", TEST_USER_EMAIL_ADDRESS, user.getProperty(Mailer.UserProperty.class).getAddress());
    }

    @Test public void testGroupListFromStringInfoEndpoint() throws Exception {
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
                                "     \"groups\": \"["+TEST_USER_GROUPS[0]+", "+TEST_USER_GROUPS[1]+"]\"\n" +
                                "   }\n" +
                                "  }")
        ));


        jenkins.setSecurityRealm(new TestRealm(wireMockRule, "http://localhost:" + wireMockRule.port() + "/userinfo", "nested.email", "nested.groups"));

        assertEquals("Shouldn't be authenticated", getAuthentication().getPrincipal(), Jenkins.ANONYMOUS.getPrincipal());

        webClient.goTo(jenkins.getSecurityRealm().getLoginUrl());

        Authentication authentication = getAuthentication();
        assertEquals("Should be logged-in as "+ TEST_USER_USERNAME, authentication.getPrincipal(), TEST_USER_USERNAME);
        User user = User.get(String.valueOf(authentication.getPrincipal()));

        assertEquals("Full name should be " +TEST_USER_FULL_NAME, TEST_USER_FULL_NAME, user.getFullName());
        assertEquals("Email should be " + TEST_USER_EMAIL_ADDRESS, TEST_USER_EMAIL_ADDRESS, user.getProperty(Mailer.UserProperty.class).getAddress());
        assertTrue("User should be part of group " + TEST_USER_GROUPS[0], user.getAuthorities().contains(TEST_USER_GROUPS[0]));
        assertTrue("User should be part of group " + TEST_USER_GROUPS[1], user.getAuthorities().contains(TEST_USER_GROUPS[1]));
        assertEquals("User should be in 2 groups", 2, user.getAuthorities().size());
    }

    @Test public void testOicUserPropertyDescriptor() throws Exception {
        wireMockRule.resetAll();

        KeyPair keyPair = createKeyPair();

        wireMockRule.stubFor(get(urlPathEqualTo("/authorization")).willReturn(
            aResponse()
                .withStatus(302)
                .withHeader("Content-Type", "text/html; charset=utf-8")
                .withHeader("Location", jenkins.getRootUrl() + "securityRealm/finishLogin?state=state&code=code")
                .withBody("")));
        Map<String, Object> keyValues = new HashMap<>();
        keyValues.put(EMAIL_FIELD, TEST_USER_EMAIL_ADDRESS);
        keyValues.put(FULL_NAME_FIELD, TEST_USER_FULL_NAME);
        keyValues.put(GROUPS_FIELD, TEST_USER_GROUPS);

        wireMockRule.stubFor(
            post(urlPathEqualTo("/token")).willReturn(aResponse().withHeader("Content-Type", "text/html; charset=utf-8")
                .withBody("{" + "\"id_token\": \"" + createIdToken(keyPair.getPrivate(), keyValues) + "\","
                    + "\"access_token\":\"AcCeSs_ToKeN\"," + "\"token_type\":\"example\"," + "\"expires_in\":3600,"
                    + "\"refresh_token\":\"ReFrEsH_ToKeN\"," + "\"example_parameter\":\"example_value\"" + "}")));

        jenkins.setSecurityRealm(new TestRealm(wireMockRule, null, EMAIL_FIELD, GROUPS_FIELD, MANUAL_CONFIG_FIELD));

        assertEquals("Shouldn't be authenticated", getAuthentication().getPrincipal(), Jenkins.ANONYMOUS.getPrincipal());

        webClient.goTo(jenkins.getSecurityRealm().getLoginUrl());

        Authentication authentication = getAuthentication();
        assertEquals("Should be logged-in as " + TEST_USER_USERNAME, TEST_USER_USERNAME, authentication.getPrincipal());
        User user = User.get(String.valueOf(authentication.getPrincipal()));
        assertEquals("Full name should be " + TEST_USER_FULL_NAME, TEST_USER_FULL_NAME, user.getFullName());

        assertEquals("Email should be " + TEST_USER_EMAIL_ADDRESS, TEST_USER_EMAIL_ADDRESS, user.getProperty(Mailer.UserProperty.class).getAddress());
        assertEquals("User should be in 2 groups", 2, user.getAuthorities().size());

        OicUserProperty.Descriptor descriptor = new OicUserProperty.Descriptor();
        OicUserProperty newProperty = (OicUserProperty) descriptor.newInstance(user);
        assertEquals("Should be logged-in as " + TEST_USER_USERNAME, TEST_USER_USERNAME, newProperty.getUserName());

        assertEquals("Display name should be " + OPENID_CONNECT_USER_PROPERTY, OPENID_CONNECT_USER_PROPERTY, descriptor.getDisplayName());
    }

    private void configureWellKnown(String endSessionUrl, String scopesSupported) {
        String authUrl = "http://localhost:" + wireMockRule.port() + "/authorization";
        String tokenUrl = "http://localhost:" + wireMockRule.port() + "/token";
        String userInfoUrl = "http://localhost:" + wireMockRule.port() + "/userinfo";
        String jwksUrl = "null";
        String endSessionUrlStr = endSessionUrl == null ? "null" : endSessionUrl ;

        wireMockRule.stubFor(get(urlPathEqualTo("/well.known")).willReturn(
            aResponse()
                .withHeader("Content-Type", "text/html; charset=utf-8")
                .withBody(String.format("{\"authorization_endpoint\": \"%s\", \"token_endpoint\":\"%s\", "
                + "\"userinfo_endpoint\":\"%s\",\"jwks_uri\":\"%s\", \"scopes_supported\": " + scopesSupported + ", "
                + "\"end_session_endpoint\":\"%s\"}", authUrl, tokenUrl, userInfoUrl, jwksUrl, endSessionUrl))
        ));
    }

    @Test public void testLogoutShouldBeJenkinsOnlyWhenNoProviderLogoutConfigured() throws Exception {
        final TestRealm oicsr = new TestRealm.Builder(wireMockRule).build();
        jenkins.setSecurityRealm(oicsr);

    String[] logoutURL = new String[1];
    jenkinsRule.executeOnServer(() -> {
            logoutURL[0] = oicsr.getPostLogOutUrl2(Stapler.getCurrentRequest(), Jenkins.ANONYMOUS2);
            return null;
        });
    assertEquals("/jenkins/", logoutURL[0]);
    }

    @Test public void testLogoutShouldBeProviderURLWhenProviderLogoutConfigured() throws Exception {
        final TestRealm oicsr = new TestRealm.Builder(wireMockRule)
        .WithLogout(Boolean.TRUE, "http://provider/logout")
                .build();
        jenkins.setSecurityRealm(oicsr);

    String[] logoutURL = new String[1];
    jenkinsRule.executeOnServer(() -> {
            logoutURL[0] = oicsr.getPostLogOutUrl2(Stapler.getCurrentRequest(), Jenkins.ANONYMOUS2);
            return null;
        });
    assertEquals("http://provider/logout?id_token_hint=null&state=null", logoutURL[0]);
    }

    @Test public void testLogoutShouldBeProviderURLWithRedirectWhenProviderLogoutConfiguredWithPostlogoutRedirect() throws Exception {
        final TestRealm oicsr = new TestRealm.Builder(wireMockRule)
        .WithLogout(Boolean.TRUE, "http://provider/logout")
                .WithPostLogoutRedirectUrl("http://see.it/?cat&color=white")
                .build();
        jenkins.setSecurityRealm(oicsr);

        String[] logoutURL = new String[1];
        jenkinsRule.executeOnServer(() -> {
            logoutURL[0] = oicsr.getPostLogOutUrl2(Stapler.getCurrentRequest(), Jenkins.ANONYMOUS2);
            return null;
        });
        assertEquals("http://provider/logout?id_token_hint=null&state=null&post_logout_redirect_uri=http%3A%2F%2Fsee.it%2F%3Fcat%26color%3Dwhite", logoutURL[0]);
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

    private String toJsonArray(List<Map<String,String>> list) {
        StringBuilder builder = new StringBuilder();
        builder.append("[");

        for(Map<String,String> entry : list) {
            builder.append("{");
            for ( String key :entry.keySet() ) {
                builder.append("\"").append(key).append("\": ");
                builder.append("\"").append(entry.get(key)).append("\",");
            }
            if(builder.lastIndexOf(",") != -1) {
                builder.deleteCharAt(builder.length()-1);
            }
            builder.append("},");
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
            .setNonce("nonce");
        for(Map.Entry<String, Object> keyValue : keyValues.entrySet()) {
            payload.set(keyValue.getKey(), keyValue.getValue());
        }

        return JsonWebSignature.signUsingRsaSha256(privateKey, JSON_FACTORY, header, payload);
    }

    private String createUserInfoJWT(PrivateKey privateKey, String userInfo) throws Exception {

        JsonWebSignature.Header header = new JsonWebSignature.Header()
            .setAlgorithm("RS256");

        JsonWebToken.Payload payload = new JsonWebToken.Payload();
        for(Map.Entry<String, JsonElement> keyValue : parseString(userInfo).getAsJsonObject().entrySet()) {
            payload.set(keyValue.getKey(), keyValue.getValue().getAsString());
        }

        return JsonWebSignature.signUsingRsaSha256(privateKey, JSON_FACTORY, header, payload);
    }

    /**
     * Gets the authentication object from the web client.
     *
     * @return the authentication object
     */
    private Authentication getAuthentication() {
        try {
            return webClient.executeOnServer(new Callable<Authentication>() {
                @Override
                public Authentication call() throws Exception {
                    return jenkins.getAuthentication();
                }
            });
        } catch (Exception e) {
            // safely ignore all exceptions, the method never throws anything
            return null;
        }

    }

}
