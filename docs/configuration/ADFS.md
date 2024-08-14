# ADFS Provider

[ADFS][1] can be used as as an OpenID Connect identity provider.

## Provider configuration

[This][2] stack overflow step though is a great resource, followed by [This IBM resource][3] for granting the correct permissions.

Where the IBM resource adds 2 individual permissions, 3 are needed and can be performed in one command - e.g.
`Set-AdfsApplicationPermission -TargetIdentifier fe56f061-c689-45e8-af8d-b8fdf5d1e60f -AddScope 'openid','aza','allatclaims'`

Extra claims (for example users display name) can be added using a similar approach to the groups.

## Plugin configuration

ADFS provides a well known configuration endpoint which can be used for automating endpoint configuration.
It also supports PKCE verification for additional security.

### User information

Without any extra claims, the user field should be set to `upn`


[1]: https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/ad-fs-overview
[2]: https://stackoverflow.com/questions/55494354/user-groups-as-claims-through-openid-connect-over-adfs/55570286#55570286
[3]: https://community.ibm.com/community/user/security/blogs/laurent-lapiquionne1/2020/07/21/how-to-configure-igi-service-center-to-authent
