# Using AWS Cognito

## Cognito App Client Config
* Obtain the client id and secret from your AWS Cognito App client.
    * Required Authentication flow: `ALLOW_USER_PASSWORD_AUTH`
    * Make sure to reduce the **Attribute read and write permissions** according to the least privilege principle
    * **Hosted UI** 
      * **Allowed callback URLs**: `<REDIRECT_URL>`, `https://<JENKINS_HOST>/securityRealm/finishLogin`
      * **Allowed sign-out URLs**: `<REDIRECT_URL>`, `https://<JENKINS_HOST>/OicLogout`

## oic-auth Plugin Config

Open the well-known json configuration `https://cognito-idp.<REGION>.amazonaws.com/<USERPOOL_ID>/.well-known/openid-configuration` for the manual configuration
* Manual configuration:
  * **Token server url** - See `token_endpoint` from json file
  * **Token Authentication Method** - POST
  * **Authorization server url** - See `authorization_endpoint` from json file
  * **UserInfo server url** - See `userinfo_endpoint` from json file
  * **Scopes** - See what is supported in `scopes_supported` from json file
  * **Scopes** - See what is supported in `scopes_supported` from json file
  * Enable `Logout from OpenID Provider`
    * **End session URL for OpenID Provider** - `<COGNITO_DOMAIN>/logout`
* Advanced configuration
  * **User name field name** - `username`
  * **Email field name** - `email`
  * **Groups field name** - `cognito:groups`
  * **Post logout redirect URL** - `<REDIRECT_URL>`
  * Activate **Enable AWS Cognito Logout**
