package org.jenkinsci.plugins.oic;

import com.github.tomakehurst.wiremock.junit.WireMockRule;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.StaplerRequest;

import java.io.IOException;
import java.lang.reflect.Field;

public class TestRealm extends OicSecurityRealm {

    public static final String CLIENT_ID = "clientId";
    public static final String EMAIL_FIELD = "email";
    public static final String FULL_NAME_FIELD = "fullName";
    public static final String GROUPS_FIELD = "groups";

    public TestRealm(WireMockRule wireMockRule) throws IOException {
        this(wireMockRule, null);
    }

    public TestRealm(WireMockRule wireMockRule, String userInfoServerUrl) throws IOException {
        this(wireMockRule, userInfoServerUrl, EMAIL_FIELD, GROUPS_FIELD);
    }

    public TestRealm(WireMockRule wireMockRule, String userInfoServerUrl, String emailFieldName, String groupFieldName) throws IOException {
        super(
             CLIENT_ID,
            "secret",
            null,
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
            "manual"
        );
    }

    @Override
    public HttpResponse doFinishLogin(StaplerRequest request) throws IOException {
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
