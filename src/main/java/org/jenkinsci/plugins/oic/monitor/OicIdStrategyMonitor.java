package org.jenkinsci.plugins.oic.monitor;

import com.google.common.annotations.VisibleForTesting;
import hudson.Extension;
import hudson.ExtensionList;
import hudson.model.AdministrativeMonitor;
import hudson.security.SecurityRealm;
import java.io.IOException;
import jenkins.model.Jenkins;
import org.jenkinsci.plugins.oic.Messages;
import org.jenkinsci.plugins.oic.OicSecurityRealm;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.HttpResponses;
import org.kohsuke.stapler.interceptor.RequirePOST;

@Extension
@Restricted(NoExternalUse.class)
public class OicIdStrategyMonitor extends AdministrativeMonitor {

    // if null, means not evaluated yet
    Boolean missingIdStrategy;

    public OicIdStrategyMonitor() {}

    @VisibleForTesting
    protected static OicIdStrategyMonitor get() {
        return ExtensionList.lookupSingleton(OicIdStrategyMonitor.class);
    }

    @Override
    public String getDisplayName() {
        return Messages.OicSecurityRealm_monitor_DisplayName();
    }

    @Override
    public boolean isActivated() {
        if (!Boolean.FALSE.equals(missingIdStrategy)) {
            SecurityRealm securityRealm = Jenkins.get().getSecurityRealm();
            if (securityRealm instanceof OicSecurityRealm) {
                missingIdStrategy = ((OicSecurityRealm) securityRealm).isMissingIdStrategy();
            } else {
                missingIdStrategy = Boolean.FALSE;
            }
        }
        return missingIdStrategy;
    }

    @RequirePOST
    public HttpResponse doForward() throws IOException {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        return HttpResponses.redirectViaContextPath("configureSecurity");
    }
}
