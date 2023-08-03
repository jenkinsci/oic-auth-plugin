# Authelia OIDC Provider

This is an example configuration for Authelia as OIDC Provider

> Note: This is a community provided example and not maintained/supported by the plugin authors.

## Authelia Configuration

```yaml
identity_providers:
  oidc:
    hmac_secret: some_secret
    issuer_private_key: some_private_key
    clients:
      - id: jenkins
        description: Jenkins
        secret: some_client_secret
        public: false
        authorization_policy: one_factor
        consent_mode: implicit
        redirect_uris:
          - https://jenkins.example.com/securityRealm/finishLogin
        scopes:
          - openid
          - offline_access
          - profile
          - groups
          - email
        userinfo_signing_algorithm: none
```

## Jenkins Configuration (JCasC)

```yaml
  securityRealm:
    oic:
      automanualconfigure: auto
      clientId: jenkins
      clientSecret: some_client_secret
      tokenAuthMethod: client_secret_post
      scopes: openid offline_access profile groups email
      userNameField: preferred_username
      fullNameFieldName: name
      groupsFieldName: groups
      emailFieldName: email
      wellKnownOpenIDConfigurationUrl: https://auth.example.com/.well-known/openid-configuration
      authorizationServerUrl: https://auth.example.com/api/oidc/authorization
      tokenServerUrl: https://auth.example.com/api/oidc/token
      userInfoServerUrl: https://auth.example.com/api/oidc/userinfo
      escapeHatchEnabled: false
```

## Matrix Based Authorization Strategy (JCasC)

Optional Step - Example

```yaml
jenkins:
  authorizationStrategy:
    globalMatrix:
      permissions:
        # Super Admins
        - "GROUP:Overall/Administer:super_admins"
        # Admins
        - "GROUP:Job/Build:admins"
        - "GROUP:Job/Read:admins"
        - "GROUP:Metrics/View:admins"
        - "GROUP:Overall/Read:admins"
        - "GROUP:View/Read:admins"
        # Developers
        - "GROUP:Job/Read:developers"
        - "GROUP:Metrics/View:developers"
        - "GROUP:Overall/Read:developers"
        - "GROUP:View/Read:developers"
```

> I've seen a blog that was mentioning to prepend groups with `/`. eg `/developers`.
> But it was for Keycloak and did not work for Authelia.
