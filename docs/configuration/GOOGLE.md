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


## Plugin configuration

Google provides a well known configuration endpoint which can be used
for automating endpoint configuration. It also supports PKCE
verification for additional security.

```yaml
jenkins:
  securityRealm:
    oic:
      wellKnownOpenIDConfigurationUrl: https://accounts.google.com/.well-known/openid-configuration
	  automanualconfigure: auto
      clientId: identifier-client-id
      clientSecret: identifuer-client-secret
      scopes: openid profile name mail 
      userNameField: sub
      fullNameFieldName: name
      emailFieldName: email
      pkceEnabled: true
```

[1]: https://developers.google.com/identity/openid-connect/openid-connect
[2]: https://console.developers.google.com/
