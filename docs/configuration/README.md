# Plugin configuration

The OpenID Connect authentication plugin tries to support a wide range
of OpenID providers. The configuration reflects the various ways the
plugin accomodates their differences and provide a way to select the
information to extract.

There are specifics instructions for well known providers:

* [Google Provider](GOOGLE.md)


## Provider configuration

The OpenID Conenct spec describes a well known configuration location
which will also help discovering your settings
(<https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig>)

From 1.5 and onward the well known configuration location may be used to
populate the configuration simplifying the configuration greatly. 

## JCasC configuration reference

JCasC configuration can be defined with the following fields:

```yaml
jenkins:
  securityRealm:
    oic:
      # Endpoints
      automanualconfigure: <string:enum>
      wellKnownOpenIDConfigurationUrl: <url>
      tokenServerUrl: <url>
      authorizationServerUrl: <url>
      # Credentials
      clientId: <string>
      clientSecret: <string:secret>
      tokenAuthMethod: <string:enum>
      # claims
      scopes: <string:space separated words>
      userNameField: <string:jmes path>
      groupsFieldName: <string:jmes path>
      fullNameFieldName: <string: jmes path>
      emailFieldName: <string:jmes path>
      # advanced configuration
      logoutFromOpenidProvider: <boolean>
      rootURLFromRequest: <boolean>
      sendScopesInTokenRequest: <boolean>
      # Security
      disableSslVerification: <boolean>
      nonceDisabled: <boolean>
      pkceEnabled: <boolean>
      tokenFieldToCheckKey: <string:jmes path>
      tokenFieldToCheckValue: string
      # escape hatch 
      escapeHatchEnabled: <boolean>
      escapeHatchUsername: escapeHatchUsername
      escapeHatchSecret: <string:secret>
      escapeHatchGroup: <string>
```
