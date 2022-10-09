# Changelog

<https://github.com/jenkinsci/oic-auth-plugin/releases/>

### 1.6 

Special release
for [\#46](https://github.com/jenkinsci/oic-auth-plugin/issues/46)
which shouldn't, but might break things - *please report any issues you
have with this version
here: <https://github.com/jenkinsci/oic-auth-plugin/issues/62>*

**In case of any troubles revert to 1.5 and report your issues**

### 1.5

-   Support for configuring by well known
    url (/.well-known/openid-configuration) see
    also <https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig>
-   fixed issue introduced with Jenkins 2.150.2 with logout occurring
    immediately after login
    see: <https://github.com/jenkinsci/oic-auth-plugin/issues/54>
-   Masking client secret to avoid over the shoulder leaking of secret.
-   Nested field mapping - permitting the use of values of non top-level
    keys,
    see <https://github.com/jenkinsci/oic-auth-plugin/pull/36> and <https://github.com/jenkinsci/oic-auth-plugin/blob/6e643be0883b3843876f3522eabb87867677cc83/src/main/java/org/jenkinsci/plugins/oic/OicSecurityRealm.java#L630>
-   Returning a 401 instead of throwing an NullPointerException when
    there's no session at the end of the authentication interaction

### 1.4

-   We can now also look for groups in the UserInfo endpoint when it's
    configured
-   Added documentation about how scripted clients should authenticate
    given this plugin is active
-   Now honoring Jenkins proxy settings
    see [JenkinsBehindProxy](https://wiki.jenkins.io/display/JENKINS/JenkinsBehindProxy)

### 1.3

-   Bugfix for regression, breaks on absent expires\_in

### 1.2

-   Local Login / escape hatch
-   Fix JEP-200 compatibility
-   Added test harness
-   Using role-based permissions
-   Fix for 1.1 breaking on existing configuration and configuration
    saving issues
-   Add groups at login if provided in the idToken as an array of
    strings
-   Exception with Azure authority needs testing
-   Patched TokenResponse of the google oauth-client for better
    compatibility with openid provider implementations
-   On Logout have the option to log out of OpenId Provider
-   Friendlier error when the user declines authorization

### 1.1

-   fix save not resetting userNameField and scopes to default values
    bug / User name field value not being updated
-   Add new setting to disable sslVerification - for testing purposes
    enhancement
-   Support OIDC UserInfo Endpoint enhancement

### 1.0

initial release