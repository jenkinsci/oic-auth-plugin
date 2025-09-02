package org.jenkinsci.plugins.oic;

import java.lang.management.ManagementFactory;
import java.util.List;

class DebugUtils {

    static boolean isDebugging() {
        List<String> inputArguments = ManagementFactory.getRuntimeMXBean().getInputArguments();
        for (String arg : inputArguments) {
            if (arg.startsWith(" -agentlib:jdwp")) {
                return true;
            }
        }
        return false;
    }
}
