# Groups from Identity Provider (IDP)

When a user logs in using OpenID Connect, the plugin can be configured to extract group
information from the openid token and/or the userinfo endpoint of the provider.

General steps are:

  1. Create groups in IDP and associate them to users - configure plugin to extract groups
  2. Create group with same name in Jenkins and associate rights
  3. When user connects, it gets the rights of group configured in step 2

There is a special group named `Authenticated Users` which applies rights to user that were able
to authenticate but without any specific group.

## Groups from IDP

The actual creation of groups and how it is associated to user is outside the scope of this HOWTO.
Please refer to the documentation of your provider.

Throughout the configuration of the plugin, you can check which groups (*authorities*) were assigned to you
by visiting the whoami url of your jenkins `https://<root url>/whoAmI/` (case is important).

> **Who Am I?**
> Name: `<username>`
> IsAuthenticated?:	true
> Authorities:	
> - "Jenkins user"
> - "Jenkins admin"

If you do not see anything of your groups, it means that the plugin was not able to
collect the information: either the configuration is wrong or the information is not provided.

### Inspect IdToken or UserInfo

The plugin doesn't currently propose a way to inspect raw information from provider.

Either you provider or a tool should be able to present the data in json
format.

Sample:

```json
{
  "exp": 1713262211,
  ... standard information ...
  "sub": "<user>",
  "realm_access": {
    "roles": [
      "foo users",
      "bar users"
    ]
  },
  "name": "<full name>",
  "preferred_username": "<login name>",
  "email": "<mail address>"
}
```

### Configure group field

The `Group` field of the plugin's configuration can be expressed as a [JMES Path](https://jmespath.org/).
JMES is a way to express how to collect fields from a JSON document.

The online tool provided on the website can used for debugging the field configuration:

- paste the data in the big box (it should be a valid json)
- adapt the line at the top with the expression
- inspect the output at the bottom: correct output should be a list of strings containing your groups' name

Example: `realm_access.roles` with the data of the precedent section

## Create Jenkins groups

OpenID Connect doesn't provide a API for collecting groups name. The groups
must be created manually in the "Security" section of configuration.

The actual configuration depends on the "Authorization" strategy.
The follwoing instructions apply to Matrix-based and Project-based security.

For each group you want to associate with rights:

- create a group by clicking on the `Add Group ...` button
- the name of the group in the popup windows should be the same as the provider's (with case and spaces)
- tick the columns on the lines of the new group

Finally, save the configuration.

