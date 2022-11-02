# oic-auth

A Jenkins plugin which lets you login to Jenkins using your own, self-hosted or public openid connect server.

[![Plugin Version](https://img.shields.io/jenkins/plugin/v/oic-auth.svg)](https://plugins.jenkins.io/oic-auth)
[![Change Log](https://img.shields.io/github/release/jenkinsci/oic-auth-plugin.svg?label=changelog)](https://github.com/jenkinsci/oic-auth-plugin/releases/latest)
[![Install Number](https://img.shields.io/jenkins/plugin/i/oic-auth.svg?color=blue)](https://plugins.jenkins.io/oic-auth)
[![MIT license](https://img.shields.io/github/license/jenkinsci/oic-auth-plugin)](https://github.com/jenkinsci/oic-auth-plugin/blob/master/LICENSE)
[![Build Status](https://ci.jenkins.io/job/Plugins/job/oic-auth-plugin/job/master/badge/icon)](https://ci.jenkins.io/job/Plugins/job/oic-auth-plugin/job/master/)
[![Contributors](https://img.shields.io/github/contributors/jenkinsci/oic-auth-plugin.svg)](https://github.com/jenkinsci/oic-auth-plugin/graphs/contributors)
[![Crowdin](https://badges.crowdin.net/e/b7f2178f29b3eb9adff1da2429d20de3/localized.svg)](https://jenkins.crowdin.com/oic-auth-plugin)
[![codecov](https://codecov.io/gh/jenkinsci/oic-auth-plugin/branch/master/graph/badge.svg?token=rORWUCOfim)](https://codecov.io/gh/jenkinsci/oic-auth-plugin)

![OpenID connect](/docs/images/openid-connect-logo.jpg)
<details>
<summary><h2>Table of content</h2></summary>

- [User guide](#user-guide)
  - [Installation](#installation)
  - [Configuration quickstart](#configuration-quickstart)
  - [Interacting with Jenkins as a non front-end user](#interacting-with-jenkins-as-a-non-front-end-user)
- [OpenID Connect Authentication plugin](#openid-connect-authentication-plugin)
  - [Open Tickets (bugs and feature requests)](#open-tickets-bugs-and-feature-requests)
  - [Changelog](#changelog)
  - [Contributing](#contributing)

</details>

## User guide

[OpenID Connect](https://openid.net/connect/) is an authentication
and authorization protocol that allow users to use single sign-on (SSO)
to access an application (Jenkins in this case) using Identity Providers.
In practice, with this plugin, Jenkins administrators can
configure a provider which will authenticate users, provide basic
information (email, username, groups) and let Jenkins grant rights accordingly.

After installing the plugin, the Jenkins administrator can choose
"OpenID Connect" as [Security Realm](https://www.jenkins.io/doc/book/security/managing-security/#access-control).
The configuration involves the configuration of the provider and
the related authorisation strategy.

### Installation

OpenID Connect Authentication plugin is installed as other plugins:

- either using [Jenkins plugin management](https://www.jenkins.io/doc/book/managing/plugins/#installing-a-plugin)
  from the web UI or the command line
- or using [Jenkins Configuration as Code (JCasC)](https://www.jenkins.io/doc/book/managing/casc/#configuration-as-code)

In either case, choosing the plugin as Security Realm means that other
authentication methods (Jenkins Database, LDAP, ...) will no
longer be available and any missconfiguration or service availability
issue will lock out the users. An *escape hatch* can be activated at
configuration time to define a admin credential which can be used to
recover access to Jenkins.

### Configuration quickstart

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

#### Using g-suite / google

Obtain the client id and secret from the developer console:
https://console.cloud.google.com/apis/credentials by creating Oauth client id.

Use those to fill the respective fields in the configuration of Jenkins.

Choose automatic configuration:

Well-known configuration: https://accounts.google.com/.well-known/openid-configuration

see also: <https://developers.google.com/identity/protocols/OpenIDConnect>

#### Using the plugin with Azure AD

See this blog post <http://www.epiclabs.io/configure-jenkins-use-azure-ad-authentication-openid-connect/>

### Interacting with Jenkins as a non front-end user

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

## OpenID Connect Authentication plugin

This plugin relies on the users and people of goodwill to improve and make
the plugin evolve in the most useful way. All feedbacks and help are welcome.
We can provide help and support but it is limited to the fair use of
volunteers' free time.

### Open Tickets (bugs and feature requests)

[GitHub issues](https://github.com/jenkinsci/oic-auth-plugin/issues?q=is%3Aopen+is%3Aissue)
is our main communication channel for issues and feature request.
We will look at issues entered through [Jenkins Jira](https://issues.jenkins.io/issues/?jql=project+%3D+JENKINS+AND+component+%3D+oic-auth-plugin)
but the response time may currently be spotty at best.

Before adding an issue, please search if the same issue has already be reported
and avoid duplicating it. If it is a new issue and it not purley related
to your environment, please provide relevant information (such as the version
of Jenkins and the plugin).

If an issue or a feature request is unclear, it will be tagged
with **Need more info** label. Without answer after a month, the
issue will be closed.

### Changelog

Changelog file has been removed and CHANGELOG content can be review in the
[GitHub release](https://github.com/jenkinsci/oic-auth-plugin/releases)
panel of the plugin's repository. They also available in the
[Jenkins plugin](https://plugins.jenkins.io/oic-auth/#releases) panel.

### Contributing

Contributions are welcome, we are looking for:

- developpers to implement the features, improve the code and whatever
  hackers do for a living
- anybody wanting to help sorting the issues, improve,
  [translate](https://jenkins.crowdin.com/u/projects/25)
  document, participate in pull request review or test before release
- just anybody who wants to drop by and take an interest

Please refer to the separate [CONTRIBUTING](docs/CONTRIBUTING.md) document for details on how to proceed!

