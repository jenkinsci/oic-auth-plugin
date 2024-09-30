# Testing changes

As well as the unit tests run as part of the build, there are additional tests that can be run to confirm there are no regressions

## Acceptance Test Harness

The [Jenkins acceptance test harness](https://github.com/jenkinsci/acceptance-test-harness) contains a test against a real OpenID Provider (OP).
At the time of writing this is limited to a dynamically created [KeyCloak instance](https://www.keycloak.org/).

Assuming you have an environment prepared to run the [ATH](https://github.com/jenkinsci/acceptance-test-harness?tab=readme-ov-file#running-tests) you can run these the tests against a local version of the plugin.

1. create a local build of your changes with `mvn package`
2. switch to the directory containing the ATH clone
    1. run the plugins specific test using with `LOCAL_JARS=/full/path/to/oic-auth-plugin/target/oic-auth.hpi mvn test -Dtest=OicAuthPluginTest`

## OpenID Conformance Tests

The [OpenID Foundation](https://openid.net/) maintains a set of [conformance tests](https://openid.net/how-to-certify-your-implementation/) for both OpenID Providers (OPs) and OpenID Relying Parties (RPs).
Details for how to run the majority of the tests (RP) for this plugin is detailed [here](https://openid.net/certification/connect_rp_testing/) with specifics for logout based tests [here](https://openid.net/certification/connect_rp_logout_testing/).
It is recommended to create a static client for the tests.

## Developer Testing against OPs

Several OpenID Providers (OPs) are freely available in order to setup and test changes locally.
Notable providers are [KeyCloak](https://www.keycloak.org/), [Dex](https://dexidp.io/), and [Google](https://developers.google.com/identity/openid-connect/openid-connect).
