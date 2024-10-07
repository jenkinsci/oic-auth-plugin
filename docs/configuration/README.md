# Plugin configuration

The OpenID Connect authentication plugin tries to support a wide range
of OpenID providers. The configuration reflects the various ways the
plugin accomodates their differences and provide a way to select the
information to extract.

There are specifics instructions for well known providers:

* [Google Provider](GOOGLE.md)
* [Gitlab Provider](GITLAB.md)
* [Microsoft AD FS](ADFS.md)

This page contains the reference of plugin's configuration.

## Provider configuration

The OpenID Connect spec describes a well known configuration location
which will also help discovering your settings
(<https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig>)

From 1.5 and onward the well known configuration location may be used to
populate the configuration simplifying the configuration greatly.
The switch between modes is controled by the `automanualconfigure` field

| field | format | description |
| ----- | ------ | ----------- |
| automanualconfigure | enum | Crontols endpoint configuration mode<br />- `auto`:  activate automatic configuration <br />- `manual`: activate manual configuration |
| clientId | string | Id of the openid client obtained from the provider |
| clientSecret | secret | Secret associated to the client |

### Automatic configuration

In automatic mode, the [well-known](https://datatracker.ietf.org/doc/html/rfc5785)
configuration endpoint is regularly fetched and parse to fill the fields
required in manual configuration. By default, all scopes are requested
but this can be overriden by the `overrideScopes` config parameter.

| field | format | description |
| ----- | ------ | ----------- |
| wellKnownOpenIDConfigurationUrl | url | Providers' well-known configuration endpoint |
| overrideScopes | string | Space separated list of scopes to request (default: request all) |

When configuring from the interface, the automatic mode will fill in the
fields expected in manual mode. This can be useful for prefilling the
fields but adapting the configuration of the endpoints.

### Manual configuration

The manual configuration mut provide the authorization and token endpoints.
The scopes can be configured but default to `openid profile`.
If the JWKS endpoint is configured, JWS' signatures will be verified
(unless disabled).

| field | format | description |
| ----- | ------ | ----------- |
| automanualconfigure | enum | Always `manual` in manual mode |
| authorizationServerUrl | url | URL the user is redirected to at login |
| tokenServerUrl | url | URL used by jenkins to request the tokens |
| endSessionEndpoint | url | URL to logout from provider (used if activated) |
| jwksServerUrl | url | URL of provider's jws certificates (unused if disabled) |
| scopes | string | Space separated list of scopes to request (default: request all) |
| tokenAuthMethod | enum | method used for authenticating when requesting token(s)<br />- `client_secret_basic`: for client id/secret as basic authentication user/pass<br />- `client_secret_post`: for client id/secret sent in post request
| userInfoServerUrl | url | URL to get user's details |

### Advanced configuration

Providers have some variation in their implementation of OpenID Connect
or some oddities they required.

| field | format | description |
| ----- | ------ | ----------- |
| logoutFromOpenidProvider | boolean | Enable the logout from provider when user logout from Jenkisn. |
| sendScopesInTokenRequest | boolean | Some providers expects scopes to be sent in token request |
| rootURLFromRequest | boolean | When computing Jenkins redirect, the root url is either deduced from configured root url or request |

### Security configuration

Most security feature are activated by default if possible.

| field | format | description |
| ----- | ------ | ----------- |
| disableSslVerification | boolean | disable SSL verification (in case of self signed certificates by example) |
| nonceDisabled | boolean | Disable nonce verification |
| pkceEnable | boolean | Enable PKCE challenge |
| disableTokenVerification | boolean | Disable IdToken and UserInfo verification (not recommended) |
| tokenFieldToCheckKey | jmespath | field(s) to check to authorize user |
| tokenFieldToCheckValue | string | tokenFieldToCheckValue expected value |

## User information

Content of idtoken or user info to use for identifying the user.
They are called claims in OpenID Connect terminology.

| field | format | description |
| ----- | ------ | ----------- |
| userNameField | jmes path | claim to use as user login (default: `sub`) |
| fullNameFieldName | jmes path | claim to use as name of user |
| emailFieldName | jmes path | claim to use for populating user email |
| groupsFieldName |jmes path | groups the user belongs to |


## JCasC configuration reference

JCasC configuration can be defined with the following fields:

```yaml
jenkins:
  securityRealm:
    oic:
      serverConfiguration:
        # Automatic config of endpoint
        wellKnown:
          wellKnownOpenIDConfigurationUrl: <url>
          scopesOverride: <string:space separated words>
        # Manual config of endpoint
        manual:
          authorizationServerUrl: <url>
          endSessionEndpoint: <url>
          issuer: <string>
          jwksServerUrl: <url>
          tokenAuthMethod: <string:enum>
          tokenServerUrl: <url>
          scopes: <string:space separated words>
          userInfoServerUrl: <url>
          useRefreshTokens: <boolean>
      # Credentials
      clientId: <string>
      clientSecret: <string:secret>
      # claims
      userNameField: <string:jmes path>
      groupsFieldName: <string:jmes path>
      fullNameFieldName: <string: jmes path>
      emailFieldName: <string:jmes path>
      # advanced configuration
      logoutFromOpenidProvider: <boolean>
      rootURLFromRequest: <boolean>
      sendScopesInTokenRequest: <boolean>
      postLogoutRedirectUrl: <url>
      # Security
      allowTokenAccessWithoutOicSession: <boolean>
      allowedTokenExpirationClockSkewSeconds: <integer>
      disableSslVerification: <boolean>
      nonceDisabled: <boolean>
      pkceEnabled: <boolean>
      disableTokenVerification: <boolean>
      tokenFieldToCheckKey: <string:jmes path>
      tokenFieldToCheckValue: <string>
      tokenExpirationCheckDisabled: <boolean>
      # escape hatch
      escapeHatchEnabled: <boolean>
      escapeHatchUsername: escapeHatchUsername
      escapeHatchSecret: <string:secret>
      escapeHatchGroup: <string>
```
