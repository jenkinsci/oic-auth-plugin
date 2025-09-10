# GitLab Provider

[Gitlab][1] can be used as as an OpenID Connect identity provider.

## Provider configuration

An application must be setup on GitLab as describe in the documentation
of [OAuth 2.0 authentication identity provider][2]. The application must
be configured with:

- scopes: openid profile email 
- redirect URI: `https://<name>/<jenkins>/securityRealm/finishLogin`.

In order to obtain the client id and secret:

- the OAuth 2 Client ID is provided in the Application ID field.
- the OAuth 2 Client Secret is accessed by selecting Copy in the Secret field


## Plugin configuration

GitLab provides a well known configuration endpoint which can be used
for automating endpoint configuration. It also supports PKCE
verification for additional security.

Except for those parameters and the choice of user information, default parameters value are suitable.

### User information

The following user information is used by the plugin:

| field | description |
| ----- | ----------- |
| sub | The user's GitLab username |
| email | he user's primary email address |
| name | The user's full name |
| groups | Paths for the groups the user is a member of |

The flag for overriding scope must be set for requesting only needed
scopes.

### JCasC

```yaml
jenkins:
  securityRealm:
    oic:
      wellKnownOpenIDConfigurationUrl: https://gitlab.com/.well-known/openid-configuration
      automanualconfigure: auto
      clientId: identifier-client-id
      clientSecret: identifuer-client-secret
      overrideScopes: openid profile email
      userNameField: preferred_username
      fullNameFieldName: name
      emailFieldName: email
      groupFieldName: groups
      properties:
      - "pkce"
```

[1]: https://docs.gitlab.com/ee/integration/openid_connect_provider.html
[2]: https://docs.gitlab.com/ee/integration/oauth_provider.html
