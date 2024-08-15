package org.jenkinsci.plugins.oic;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import jenkins.model.Jenkins;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class OicCrumbExclusionTest {

    @Mock
    Jenkins jenkins;

    @Mock
    MockedStatic<Jenkins> staticJenkins;

    @Mock
    OicSecurityRealm oicSecurityRealm;

    @Mock
    FilterChain chain;

    @Mock
    HttpServletRequest request;

    @Mock
    HttpServletResponse response;

    private void withJenkins() {
        staticJenkins.when(Jenkins::getInstanceOrNull).thenReturn(jenkins);
    }

    private void withRequestPath(String path) {
        lenient().when(request.getPathInfo()).thenReturn(path);
    }

    private void withOicSecurityRealm() {
        when(jenkins.getSecurityRealm()).thenReturn(oicSecurityRealm);
    }

    @Test
    void exclusion_applies_when_realm_is_OIC_and_path_is_finishLogin() throws Exception {
        withJenkins();
        withRequestPath("/securityRealm/finishLogin");
        withOicSecurityRealm();

        OicCrumbExclusion oicCrumbExclusion = new OicCrumbExclusion();
        assertTrue("path should be excluded", oicCrumbExclusion.process(request, response, chain));
        Mockito.verify(chain, times(1)).doFilter(request, response);
    }

    @Test
    void exclusion_does_not_apply_when_realm_is_OIC_and_path_is_not_finishLogin() throws Exception {
        withJenkins();
        withRequestPath("/securityRealm/anything");
        withOicSecurityRealm();

        OicCrumbExclusion oicCrumbExclusion = new OicCrumbExclusion();
        assertFalse("path should not be excluded", oicCrumbExclusion.process(request, response, chain));
        Mockito.verify(chain, times(0)).doFilter(request, response);
    }

    @Test
    void exclusion_does_not_apply_when_realm_is_not_OIC_and_path_is_finishLogin() throws Exception {
        withJenkins();
        withRequestPath("/securityRealm/finishLogin");

        OicCrumbExclusion oicCrumbExclusion = new OicCrumbExclusion();
        assertFalse("path should not be excluded", oicCrumbExclusion.process(request, response, chain));
        Mockito.verify(chain, times(0)).doFilter(request, response);
    }

    @Test
    void exclusion_does_not_apply_when_realm_is_not_OIC_and_path_is_not_finishLogin() throws Exception {
        withJenkins();
        withRequestPath("/securityRealm/anything");

        OicCrumbExclusion oicCrumbExclusion = new OicCrumbExclusion();
        assertFalse("path should not be excluded", oicCrumbExclusion.process(request, response, chain));
        Mockito.verify(chain, times(0)).doFilter(request, response);
    }

    @Test
    void exclusion_does_not_apply_when_jenkins_is_not_set() throws Exception {
        OicCrumbExclusion oicCrumbExclusion = new OicCrumbExclusion();
        assertFalse("path should not be excluded", oicCrumbExclusion.process(request, response, chain));
        Mockito.verify(chain, times(0)).doFilter(request, response);
    }
}
