# oic-auth

A Jenkins plugin which lets you login to Jenkins using your own, self-hosted or public openid connect server.

[![Plugin Version](https://img.shields.io/jenkins/plugin/v/oic-auth.svg)](https://plugins.jenkins.io/oic-auth)
[![Change Log](https://img.shields.io/github/release/jenkinsci/oic-auth-plugin.svg?label=changelog)](https://github.com/jenkinsci/oic-auth-plugin/releases/latest)
[![Install Number](https://img.shields.io/jenkins/plugin/i/oic-auth.svg?color=blue)](https://plugins.jenkins.io/oic-auth)
[![Build Status](https://ci.jenkins.io/buildStatus/icon?job=Plugins/oic-auth-plugin/master)](https://ci.jenkins.io/job/Plugins/oic-auth-plugin/master)

![OpenID connect](/docs/images/openid-connect-logo.jpg)

## Open Tickets (bugs and feature requests)

[https://github.com/jenkinsci/oic-auth-plugin/issues](https://github.com/jenkinsci/oic-auth-plugin/issues?q=is%3Aopen+is%3Aissue)

## Configuration

Configuration of this plugin takes a bit of effort as it requires some
knowledge of the openid connect standard as well as the non-standard
configuration of the various identity providers out there. Should you
configure this plugin against a identity provider then please share your
experiences and found caveats through a blog post or by adding it to the
documentation.

Also note that the spec describes a well known configuration location
which will also help discovering your settings
(<https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig>)

From 1.5 and onward the well known configuration location may be used to
populate the configuration simplifying the configuration greatly. See
also the following screenshot utilizing the google well known endpoint
for a minimal configuration example: 

![global-config](/docs/images/global-config.png)

### Using g-suite / google

Obtain the client id and secret from the developer console: https://console.cloud.google.com/apis/credentials by creating Oauth client id.

Use those to fill the respective fields in the configuration of Jenkins.

Choose automatic configuration:

Well-known configuration: https://accounts.google.com/.well-known/openid-configuration

see also: <https://developers.google.com/identity/protocols/OpenIDConnect>

### Using the plugin with Azure AD

See this blog post <http://www.epiclabs.io/configure-jenkins-use-azure-ad-authentication-openid-connect/>

## Interacting with Jenkins as a non front-end user

TLDR: use an API token instead as described here: 
[Authenticating scripted clients](https://www.jenkins.io/doc/book/system-administration/authenticating-scripted-clients/)

Using basic auth for authentication won't work. This is because jenkins
has no knowledge of the password due to the way openid connect works:
Identifying a user is a three way interaction between the user, Jenkins
and the openid provider.

The plugin asks the configured openid provider to confirm the identity
of the user is and does this in a way that both Jenkins and the provider
are 'talking' about the same user. The openid connect provider will
likely challenge the user to prove it's identity and might do this by
requesting a username and password but this is entirely up to the
provider. This part is between the user and the openid connect provider,
Jenkins (using this plugin) delegates proving ones identity to the
provider and will go with whatever conclusion the provider draws. This
has the benefit that with openid connect the service your trying to
access (in our case Jenkins) never sees a user password, so even if
Jenkins is compromised an attacker can't intercept passwords or other
secrets. Using basic auth would require one to send their password to
Jenkins which would defeat this.


Scripted clients can still interact with Jenkins even when the openid
connect plugin is active: they will have to use an API
token. 
[Authenticating scripted clients](https://wiki.jenkins.io/display/JENKINS/Authenticating+scripted+clients) describes
how to obtain one. 
