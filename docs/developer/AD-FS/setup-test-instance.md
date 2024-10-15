# Active Directory Federation Service (AD FS) Testing

Microsoft's [Active Directory Federation Service](https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/ad-fs-overview) (AD FS) is a component of Windows Server.
Setting up a local test instance requires familiarity with Windows (preferable Windows Server), TLS certificates and either access to either register DNS suffices or provide local entries in `/etc/hosts` files.
A static IP address is simpler to prevent having to update the windows server configuration on each restart, however DHCP can be used if you are prepared to DNS or update local settings, and windows server settings.
Whilst Microsoft maintains a [lab guide](https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/operations/set-up-an-ad-fs-lab-environment) I found this to be overly complext for a single machine setup and also missed some extra setup, so this guide is the result.

> **Warning**
> This guide provides an AD FS server that can be used for simple integration testing.
> It is **not** suitable for setting up a production instance.

## Create A Windows Server Instance

Virtual Hard Drives(VHDs) and ISOs for evaluation version of Windows server can be obtained from the [Microsoft Evaluate Center](https://www.microsoft.com/en-us/evalcenter/evaluate-windows-server-2022).
This guide will walk through the setup of Windows 2022 using an ISO as it is the most recent production instance at the time of writing and applicable to all installation types.

1. Download the Evaluation Windows Server [ISO](https://www.microsoft.com/en-gb/evalcenter/download-windows-server-2022)
2. Start a machine (VM with 4GB of RAM) booting from the CD.
3. Select language and keyboard options and proceed to installation.
4. Choose the Windows Server 2022 Standard Evaluation (Desktop Experience).  
![Operating System Choice](setup-images/OS_install-choice.png)
5. Review and accept the licence agreement.
6. Select the "Custom" install type.  
![Operating System Install Type](setup-images/OS_custom-install-choice.png)
7. Choose where to install the OS (use the whole disk)
8. Be patient whilst the OS is installed  
![alt text](setup-images/OS_installing.png)
9. Enter an Administrator password.  
![Operating System Password Request](setup-images/OS_password.png)
10. Choose Finish
11. Login. (Note the keyboard layout here may not match what was requested and default to `English US` causing the password to be incorrect, this can be changed in the bottom right).  
![alt text](setup-images/OS_login.png)

12. You should now be logged in and presented with the `Server Manager` dashboard.  
![Server Manager Dashboard](setup-images/OS_server-manager-dashboard.png).


> **NOTE**
> if you have a machine with both IPv6 and IPv4 I have observed some general network connectivity issues with this setup in Hyper-V.  if you do not need IPv6 for testing and you have networking issues, then disable ipV6 from the adapter.  
> ![Disable IPv6](setup-images/OS_disable-ipv6.png)


Congratulations, Windows Server 2022 is now installed!

## Install Services

AD FS is not Active Directory (AD), however we will use AD as the authentication provider for AD FS so it and DNS will be installed here as well as AD FS.

1. In Server Manager click "Add roles and features".  
![Roles and features](setup-images/roles_roles-and-features.png)
2. choose "Role based or feature-based installation".  
![installation type](setup-images/roles_installation-type.png)
3. in the destination select the current server.  
![server selection](setup-images/roles_server-selection.png)
4. Check "Active Directory Domain Services".  
![Active Directory Domain Services](setup-images/roles_adds-role-adds.png)
5. Click "Add Features" on the following dialog.  
![Add Features for AD](setup-images/roles_add-features-adds.png)
6. Check "Active Directory Federation Services".  
![Active Directory Federation Services](setup-images/roles_add-role-adfs.png)
7. Check "DNS Server".  
![DNS Server](setup-images/roles_add-role-dns.png)
8. Click "Add Features" on the following dialog.  
![Add Features for DNS](setup-images/roles_add-features-dns.png)
9. Click "Next".  
![Roles Next](setup-images/roles_server-role-next.png)
10. Click "Next" when presented with Select Features.  
![Features Next](setup-images/roles_features-next.png)
11. Click "Next" when presented with the Active Directory Domain Services.  
![AD DS Next option](setup-images/roles_adds-next.png)
12. Click "Next" when presented with the Active Directory Federation Services (AD FS).  
![AD FS Next option](setup-images/roles_adfs-next.png)
13. Click "Next" when presented with the DNS Server.  
![DNS Server Next option](setup-images/roles_dns-next.png)
14. Check "Restart the destination server automatically if required" then choose "Install".  
![Restart and Install](setup-images/roles_confirm-restart-and-install.png)
15. The installation will now start.  
![installing](setup-images/roles_installing.png)
16. Wait for the installation to complete, you can then close the wizard.  
![alt text](setup-images/roles_install-complete.png)

## Configure Active Directory

1. In Server Manager DashBoard Select the Notification flag to show the post deployment options.
2. In the notification about the "Configuration required for Active Directory Domain Services" click "Promote this server to a domain controller"  
![AD DS Promote to DC](adds-images/adds_promote-to-dc.png)
3. In the deployment configuration check "Add a new forest" and enter `adfs.test` as the root domain name, then click "Next".  
![New AD Forest](adds-images/adds_create-new-domain.png)
4. In the domain controller options leave the defaults and enter a DSRM Password and click "Next".  
![Domain Controller Options](adds-images/adds_dc-options.png)
5. Ignore the warning to create a DNS delegation and click "Next".  
![Ignore DNS Delegation](adds-images/adds_ignore-dns-delegation.png)
6. Accept the default NetBIOS name and choose "Next".  
![Additional Options](adds-images/adds_additional-options.png)
7. Accept the default paths and choose "Next".  
![Paths](adds-images/adds_paths.png)
8. Accept the options for review by choosing "Next".  
![Review Options](adds-images/adds_review-options.png)
9. Wait for the prerequisites checks to complete and click "Install".  
![Install](adds-images/adds_prerequisites-check.png)
> **Note**
> If you are using DHCP you will have a warning about the use of non static IP addresses.  This can be ignored, however you will need to update DNS settings each time the machine gets a new IP Address.
10. The install will start, after a short while you will be signed out and Windows restarted. 
The restart will take longer than normal when reconfiguring the system.

> **Note**
> Use the "Active Directory Users and Groups" snap in to create users and groups for testing.
To test groups the Group Type should be a "Security Group"

## Configure Active Directory Federation Services

The fun part.....

1. Create a self signed certificate and store it in the local machine certificate store with the following powershell script
```powershell
New-SelfSignedCertificate -DnsName @("$env:computername.$env:userdnsdomain") -CertStoreLocation 'Cert:\LocalMachine\My'
```
2. In Server Manager DashBoard Select the Notification flag to show the post deployment options.
3. In the notification about the "Configuration required for Active Directory Federation Services" click "Configure the federation service on this server".  
![Configure the federation service](adfs-images/ADFS_configure_adfs.png)
4. In the wizard select "create the first federation server in a federation server farm".  
![Create first federation server farm](adfs-images/ADFS_create-first-server.png)
5. When asked for a user with permissions to perform the configuration continue as the Administrator and click "Next".  
![Connect as User](adfs-images/ADFS_configuration-user.png)
6. Select the SSL certificate you generated earlier (this should be the only option), the federation service name will be selected from the certificate.  
![Server SSL Certificacte](adfs-images/ADFS_ssl-cert-choice.png)
7. Optionally choose a nice name for the Display Name and click "Next"  
![Server display name](adfs-images/ADFS_display-name.png)
8. When promoted for an account to use, use the local Administrator account by choosing "Select".  
![Select Account](adfs-images/ADFS_select-account-1.png)
9. Enter `Administrator` and then click "Check Names" dialog.
The check should succeed (the text will become underlined), and then click "OK".  
![Find Account](adfs-images/ADFS_search-account-1.png)  
![OK](adfs-images/ADFS_search-account-2.png)
10. Enter the password for the administrator account (this is what you login with) and choose "Next".  
![Complete Service Account](adfs-images/ADFS_select-account-2.png)
11. Choose "Create a database on this server using Windows Internal Database" and click "Next".  
![Internal Database](adfs-images/ADFS_database.png)
12. In the Review Options page click "Next".  
![Review Options](adfs-images/ADFS_review_options.png)
13. All tests should pass, Click "Configure" to continue.  
![Pre-Requisites check](adfs-images/ADFS_pre-requisites-check.png)
14. The install may generate some warnings, these can most probably be ignored.
Choose Close, and reboot the machine.  
![Huh](adfs-images/ADFS_post_install_warnings.png)


### Create a new OpenID Connect Client in AD FS

1. Login, and start the "AD FS Management" tool.  
![AD FS Management](adfs-client-images/ADFS_post-install-start-tool.png)
2. Create a new Application Group by selecting the menu Actions -> Add Application Group.  
![Create a new Application Group](adfs-client-images/ADFS_create-application-gropup.png)
3. Enter a name and description for the group and choose "Server Application accessing a web API" before clicking "Next".  
![Create Application Group Options](adfs-client-images/ADFS_create-application-group-1.png)
4. Enter the redirect URL for the Jenkins instance you will be connected to as observed by your web browser (not the ADFS Server) this will be `${JENKINS_ROOT_URL}/securityRealm/finishLogin` (e.g. for `mvn hpi:run` this will be `http://localhost:8080/jenkins/securityRealm/finishLogin`) and click "Add". **Note down the client ID, you will need this to configure Jenkins later!**.  Once you have noted down the client identifier click "Next".  
![Create client and redirect URI](adfs-client-images/ADFS_create-client-and-redirect-uri.png)
5. Choose "Generate a shared secret" and record this along with the cient ID. You will need this to configure Jenkins later! Then click "Next".  
![Create shared secret](adfs-client-images/ADFS_create-shared-secret.png)
6. In Configure Web API "Identifier" enter `client id` that was created earlier and click "Add", then "Next".  
![Configure Web API](adfs-client-images/ADFS_configure-web-api.png)
7. Check that the Access Control policy is set to Grant access to everyone, then click "Next".  
![Allow everyone to access](adfs-client-images/ADFS_access-controll-permit-everyone.png)
8. Check the following claims and click "Next"
* allatclaims
* aza
* email
* openid
* profile  
![Select Claims](adfs-client-images/ADFS_select-claims.png)
9. Review the options, and then click "Next".  
![Review Options](adfs-images/ADFS_review-options.png)
10. The Application group should have been created correctly and the wizard can now be closed.  
![Wizard Complete](adfs-client-images/ADFS_complete-wizard.png)

#### Expose Groups as Claims

1. In the AD FS Management tool, Select "Application Groups" in the tree on the left, then double click on the "Jenkins Application Group" in the main panel.  
![Application Group](adfs-groups-images/ADFS_groups-application-group.png)
2. Select the "Jenkins Application Group - Web API" entry in the "Web API" section and click "Edit".  
![Edit WebAPI](adfs-groups-images/ADFS_groups-edit-web-api.png)
3. Switch to the "Issuance Transform Rules" tab and then click "Add Rule".  
![transform rules](adfs-groups-images/ADFS_groups_transform-rules-1.png)
4. Select "Send LDAP Attributes as Claims" and click "Next".  
![LDAP Claim rule](adfs-groups-images/ADFS_groups_transform-rules-2.png)
5. Enter "Add Groups" as the rule name, and choose "Active Directory" as the `Attribute Store`.  
![Rule Name and Store](adfs-groups-images/ADFS_groups_transform-rules-3.png)
6. Use "Token-Groups - Unqualified Names" as the `LDAP Attribute` and in the `Outgoing Claim Type` enter the text "groups" (this should not match any exiting claim type) and choose Finish.  
![Add Rule mapping](adfs-groups-images/ADFS_groups_transform-rules-4.png)
7. Click "OK" to save the changes.  
![Save](adfs-groups-images/ADFS_groups_transform-rules-5.png)
8. Click "OK" to close the dialog.  
![Save](adfs-groups-images/ADFS_groups_transform-rules-6.png)


#### Fixup missing Permissions

> **Note**
> even though we did everything in the UI and granted scopes, there are still some missing permissions.
Without setting this you will have trouble authenticating (`The client 'your-client-id' is forbidden to access the resource 'http://schemas.microsoft.com/ws/2009/12/identityserver/selfscope'`) or will be missing profile information.

<!-- see https://community.ibm.com/community/user/security/blogs/laurent-lapiquionne1/2020/07/21/how-to-configure-igi-service-center-to-authent --> 

Start powershell and run the following script: (enter the client ID for the client we previously created when prompted)

```powershell
$clientid = Read-Host -Prompt 'Input your Client ID we created earlier for Jenkins'
Grant-AdfsApplicationPermission -ClientRoleIdentifier $clientid -ServerRoleIdentifier http://schemas.microsoft.com/ws/2009/12/identityserver/selfscope
Get-AdfsApplicationPermission -ServerRoleIdentifiers "http://schemas.microsoft.com/ws/2009/12/identityserver/selfscope"
$objId=Get-AdfsApplicationPermission -ServerRoleIdentifiers "http://schemas.microsoft.com/ws/2009/12/identityserver/selfscope" | Where-Object -Property ClientRoleIdentifier -eq $clientid | Select -ExpandProperty "ObjectIdentifier"
Set-AdfsApplicationPermission -TargetIdentifier $objId -AddScope ('openid', 'aza')

```

## Configure Jenkins to use this client

> **Note**
> The machine where Jenkins is running as well as the machine where you run your web browser (if using `mvn hpi:run` this will be the same machine) unless you have DNS delegated to the server you just setup (which is unlikely) you will need to configure your machine to be able to resolve requests to the servers name (e.g. `WIN-H49FDPE074E.adfs.test` to the servers IP Address).
On Windows you can add this to `%SystemRoot%\system32\drivers\etc\hosts`, on unix-like systems you can etc `/etc/hosts`

> **Note**
> to trust the certificate of the AD FS server you will need to create a custom truststore containing the certificate and use that when starting Jenkins.
It is recommended to create a copy of the JDKs truststore and modifying the copy rather than the original truststore.
e.g. `keytool -import -alias myservername.adfs.test -file myserver.cert -storetype pkcs12 -keystore my.truststore`
The resulting trust store can then be used by passing the `javax.net.ssl.trustStore` property containing the path to the truststore to the JVM used for Jenkins.

1. Start Jenkins and go to the Security configuration.
2. Enter the `Client id` and `Client secret` created when creating the client in AD FS.
3. The Well known configuration will be `https://WIN-H49FDPE074E.adfs.test/adfs/.well-known/openid-configuration`
4. The "User name field name" field should be set to `upn`
5. The "Full name field name" field should be set to `something`
6. The "Email field name" should be set to `something`
7. The "Groups field name" should be set to `something`

## Setting the token lifetime

In order to test refresh tokens (without having to wait 24 hours) you can set the token lifetime via the following powershell: 
```powershell
Set-AdfsWebApiApplication -TokenLifetime 1 -TargetName "Jenkins Application Group - Web API"
```
