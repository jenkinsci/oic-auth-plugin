package org.jenkinsci.plugins.oic;

import java.io.IOException;
import java.lang.reflect.Field;

import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.StaplerRequest;

import com.github.tomakehurst.wiremock.junit.WireMockRule;

public class TestRealm extends OicSecurityRealm {

    public static final String CLIENT_ID = "clientId";
    public static final String EMAIL_FIELD = "email";
    public static final String FULL_NAME_FIELD = "fullName";
    public static final String GROUPS_FIELD = "groups";
    public static final String MANUAL_CONFIG_FIELD = "manual";
    public static final String AUTO_CONFIG_FIELD = "auto";

    public TestRealm(WireMockRule wireMockRule) throws IOException {
        this(wireMockRule, null);
    }

    public TestRealm(WireMockRule wireMockRule, String userInfoServerUrl) throws IOException {
        this(wireMockRule, userInfoServerUrl, EMAIL_FIELD, GROUPS_FIELD, MANUAL_CONFIG_FIELD);
    }

    public TestRealm(WireMockRule wireMockRule, String userInfoServerUrl, String emailFieldName, String groupFieldName, String automanualconfigure) throws IOException {
        super(
             CLIENT_ID,
            "secret",
            "http://localhost:" + wireMockRule.port() + "/well.known",
            "http://localhost:" + wireMockRule.port() + "/token",
            "http://localhost:" + wireMockRule.port() + "/authorization",
             userInfoServerUrl,
            null,
            null,
            null,
             FULL_NAME_FIELD,
             emailFieldName,
            null,
             groupFieldName,
            false,
            false,
            null,
            null,
            false,
            null,
            null,
            null,
            automanualconfigure
        );
    }

    public TestRealm(WireMockRule wireMockRule, String userInfoServerUrl, String emailFieldName, String groupFieldName,
                     String automanualconfigure, boolean escapeHatchEnabled, String escapeHatchUsername,
                     String escapeHatchSecret, String escapeHatchGroup) throws IOException {
        super(
             CLIENT_ID,
            "secret",
            "http://localhost:" + wireMockRule.port() + "/well.known",
            "http://localhost:" + wireMockRule.port() + "/token",
            "http://localhost:" + wireMockRule.port() + "/authorization",
             userInfoServerUrl,
            null,
            null,
            null,
             FULL_NAME_FIELD,
             emailFieldName,
            null,
             groupFieldName,
            false,
            false,
            null,
            null,
            escapeHatchEnabled, 
            escapeHatchUsername, 
            escapeHatchSecret, 
            escapeHatchGroup, 
            automanualconfigure
        );
    }
    
    

    @Override
    public HttpResponse doFinishLogin(StaplerRequest request) {
        try {
            Field field = OicSession.class.getDeclaredField("state");
            field.setAccessible(true);
            field.set(OicSession.getCurrent(), "state");
        } catch (Exception e) {
            throw new RuntimeException("can't fudge state",e);
        }
        return super.doFinishLogin(request);
    }
}
