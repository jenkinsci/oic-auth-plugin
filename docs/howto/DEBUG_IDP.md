# Debug tokens from IDP

## When/why?

When it's not really well documented on IDP's side which specific fields shuold be looked for in mapping.

Jenkins might throw an NPE without any clarification which exact field it was unable to lookup in incoming token/s.

## Enabling debug logging

Go to System Log and create a new logger with these classpaths and log levels:

- org.pac4j - ALL
- org.jenkinsci.plugins.oic - ALL
- org.jenkinsci.plugins.oic.ssl - ALL

Refresh log's page and seek into either `userinfo` responce's fields or inward token/s and update your mapping.
