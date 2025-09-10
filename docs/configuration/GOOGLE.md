# Google Provider

The [Google's OAuth 2.0 APIs][1] implementation for authentication
conforms to the OpenID Connect specification.


## Provider configuration

A project must be setup in the [Google API Console][2] which will be
associated to your Jenkins instance. In the identifiers section, create
new "OAuth Client ID" identifier

- application type: `Web application`
- name: any name which is meaningful for you
- authorized redirection URI: `https://<name>/<jenkins>/securityRealm/finishLogin`

After, clicking on the creation button, a popup window provides the
client Id and the associated client secret to be used in the
configuration of the plugin.

Additional configurations are available as indicated in [Google's documentation][1] such as the customization of the consent screen.

## Plugin configuration

Google provides a well known configuration endpoint which can be used
for automating endpoint configuration. It also supports PKCE
verification for additional security.

Except for those parameters and the choice of user information, default parameters value are suitable.

### User information

The following user information is used by the plugin:

| field | scope | description |
| ----- | ----- | ----------- |
| sub | (always) | An identifier for the user, unique among all Google accounts. |
| email | email | The user's email address. |
| name | profile | The user's full name, in a displayable form. |
| hd | (optional) | The domain associated with the Google Workspace or Cloud organization of the user. |

The flag for overriding scope must be set for requesting only needed
scopes.

### JCasC

```yaml
jenkins:
  securityRealm:
    oic:
      wellKnownOpenIDConfigurationUrl: https://accounts.google.com/.well-known/openid-configuration
      automanualconfigure: auto
      clientId: identifier-client-id
      clientSecret: identifuer-client-secret
      overrideScopes: openid profile name email
      userNameField: sub
      fullNameFieldName: name
      emailFieldName: email
      properties:
      - "pkce"
```

[1]: https://developers.google.com/identity/openid-connect/openid-connect
[2]: https://console.developers.google.com/
