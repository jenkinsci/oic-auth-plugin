package org.jenkinsci.plugins.oic;

import hudson.security.SecurityRealm;
import io.jenkins.plugins.casc.misc.ConfiguredWithCode;
import io.jenkins.plugins.casc.misc.JenkinsConfiguredWithCodeRule;
import org.junit.ClassRule;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class ConfigurationAsCodeTest {
    @ClassRule
    @ConfiguredWithCode("ConfigurationAsCode.yml")
    public static JenkinsConfiguredWithCodeRule j = new JenkinsConfiguredWithCodeRule();

    @Test
    public void testConfig() {
        SecurityRealm realm = j.jenkins.getSecurityRealm();

        assertTrue(realm instanceof OicSecurityRealm);
        OicSecurityRealm oicSecurityRealm = (OicSecurityRealm) realm;

        assertEquals("http://localhost", oicSecurityRealm.getAuthorizationServerUrl());
        assertEquals("clientId", oicSecurityRealm.getClientId());
        assertEquals("clientSecret", oicSecurityRealm.getClientSecret().getPlainText());
        assertTrue(oicSecurityRealm.isDisableSslVerification());
        assertEquals("emailFieldName", oicSecurityRealm.getEmailFieldName());
        assertTrue(oicSecurityRealm.isEscapeHatchEnabled());
        assertEquals("escapeHatchGroup", oicSecurityRealm.getEscapeHatchGroup());
        assertEquals("escapeHatchSecret", oicSecurityRealm.getEscapeHatchSecret().getPlainText());
        assertEquals("escapeHatchUsername", oicSecurityRealm.getEscapeHatchUsername());
        assertEquals("fullNameFieldName", oicSecurityRealm.getFullNameFieldName());
        assertEquals("groupsFieldName", oicSecurityRealm.getGroupsFieldName());
        assertTrue(oicSecurityRealm.isLogoutFromOpenidProvider());
        assertEquals("scopes", oicSecurityRealm.getScopes());
        assertEquals("http://localhost", oicSecurityRealm.getTokenServerUrl());
        assertEquals("userNameField", oicSecurityRealm.getUserNameField());
    }
}
