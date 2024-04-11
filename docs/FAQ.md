# Frequently Asked Questions

## Odd issues

Issues that were reported and solved without clear root cause.

### Crumb issues

*Symptom*: Jenkins reports multiple crumb issues and is unable to logout user.

*Providers*: OKTA

*Details*

Logs contains warnings about crumb and CSRF issues:

```
2023-02-24 15:47:05.103+0000 [id=127]   WARNING hudson.security.csrf.CrumbFilter#doFilter: Found invalid crumb 0b13bbc28c54659d3ea7f105cb9e49bb50898d77ec94f821fad1bf28dca956f6. If you are calling this URL with a script, please use the API Token instead. More information: https://www.jenkins.io/redirect/crumb-cannot-be-used-for-script
2023-02-24 15:47:05.107+0000 [id=127]   WARNING hudson.security.csrf.CrumbFilter#doFilter: No valid crumb was included in request for /manage/descriptorByName/org.jenkinsci.plugins.oic.OicSecurityRealm/checkPostLogoutRedirectUrl by 00u8erxt6sBAIguA65d7. Returning 403.
```

*Workaround*

This was solved by installin the [Strict Crumb Issuer](https://plugins.jenkins.io/strict-crumb-issuer/) plugin.
Relevant JCasC configuration is the following:

```jenkins:
  crumbIssuer:
    strict:
      checkOnlyLocalPath: true
      checkSameSource: true
      hoursValid: 8
  disableRememberMe: false
```
