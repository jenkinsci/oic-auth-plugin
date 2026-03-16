package org.jenkinsci.plugins.oic.plugintest;

import java.util.List;
import java.util.Map;

public class PluginTestConstants {
    public static final String TEST_USER_USERNAME = "testUser";
    public static final String TEST_USER_EMAIL_ADDRESS = "test@jenkins.oic";
    public static final String TEST_USER_FULL_NAME = "Oic Test User";
    public static final String[] TEST_USER_GROUPS = new String[] {"group1", "group2"};
    public static final String[] TEST_USER_GROUPS_REFRESHED = new String[] {"group1", "group2", "group3"};
    public static final List<Map<String, String>> TEST_USER_GROUPS_MAP =
            List.of(Map.of("id", "id1", "name", "group1"), Map.of("id", "id2", "name", "group2"));
    public static final String TEST_ENCODED_AVATAR =
            "iVBORw0KGgoAAAANSUhEUgAAABsAAAAaCAYAAABGiCfwAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAH8SURBVEhL7ZbPK0RRFMe/z/w05Mc0Mo0mZeFXGM1IFDFEfjWKks1sSIkipDSrt1M2FpY2FpSllK2yV/4DWYlSLGzw7rvufe/Rm5n3a4rJwmdz77nz3vnee865Z56QSCQoikSJNhaFvy823Ulwsf6BWFTWVpxRsFionGJ7TEZtBSCmCEoE5ykvWGxtmMDvUefRIDDf/UtibXUUEx3ZzpcHCSpKNcOGgsQyk0QZbx/ecHDxhOdXCQEvsJpU1+1wLDYVk9FYq54qc/yAtcN7HF0+K/ZMnKChxj6cjsT8Hop1lqsvPojq+F1SR0EQsDMuKXMrHIkt9smoLtMME+L1wFCL9VWwFQtXUqR7nd2nzRECt0szDLAV2xq1dqAnXAmke8yLxVIsXk+RbLZPvJ7Ffh5y43dMxVjOHSU9F37h9cWkx1RsNi6zctaMHLxuthPdmMtUjLJrkp9nVyQSEbX5NwEvxf68BJ/H2Flr1I9wtRtLI0GU+oz32xQGzm6yfzN8ciUpsxZkLMTxs01UlbmUUJvBW9t4e/bp8sSiQYq5LutSF08flQ5ycvWirRjDc8cbwhd5YdydIUo3t6KpzgeJdZGNVMg0jJyAD5CZ1vWd+kzWNwg/+tFC4RVoxTtzN7DnYS0uR4z/VYgpCeVsRz/FPYu0eO5W5v9fVz9CEcWAT+xkgmHqzLIIAAAAAElFTkSuQmCC";
}
