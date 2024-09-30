# Active Directory Federation Service Testing

Microsoft's [Active Directory Federation Service](https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/ad-fs-overview) (AD FS) is a component of Windows Server.
Setting up a local test instance requires familiarity with Windows (preferable Windows Server), TLS certificates and either access to either register DNS suffices or provide local entries in `/etc/hosts` files.
A static IP address is simpler to prevent having to update the windows server configuration on each restart, however DHCP can be used if you are prepared to DNS or update local settings, and windows server settings.
Whilst Microsoft maintains a [lab guide](https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/operations/set-up-an-ad-fs-lab-environment) I found this to be overly complext for a single machine setup and also missed some extra setup, so this guide is the result.

## Create A Windows Server Instance

Virtual Hard Drives(VHDs) and ISOs for evaluation version of Windows server can be obtained from the [Microsoft Evaluate Center](https://www.microsoft.com/en-us/evalcenter/evaluate-windows-server-2022).
This guide will walk through the setup of Windows 2022 using an ISO as it is the most recent production instance at the time of writing and applicable to all installation types.

1. Download the Evaluation Windows Server [ISO](https://www.microsoft.com/en-gb/evalcenter/download-windows-server-2022)
2. Start a machine (VM with 4GB of RAM) booting from the CD.
3. Select language and keyboard options and proceed to installation.
4. Choose the Windows Server 2022 Standard Evaluation (Desktop Experience) ![Operating System Choice](setup-images/OS_install-choice.png)
5. Review and accept the licence agreement.
6. Select the "Custom" install type 
![Operating System Install Type](setup-images/OS_custom-install-choice.png)
7. Choose where to install the OS (use the whole disk)
8. Be patient whilst the OS is installed ![alt text](setup-images/OS_installing.png)
9. Enter an Administrator password. ![Operating System Password Request](setup-images/OS_password.png)
10. Choose Finish
11. Login. (Note the keyboard layout here may not match what was requested and default to `English US` causing the password to be incorrect, this can be changed in the bottom right).
![alt text](setup-images/OS_login.png)

12. You should now be logged in and presented with the `Server Manager` dashboard. ![Server Manager Dashboard](setup-images/OS_server-manager-dashboard.png).


Congratulations, Windows Server 2022 is now installed!


### Install AD Services

AD FS is not AD, however we will use AD as the authentication provider for AD FS so will install it now.



### Install Certificate Services

not needed??

### Install AD FS....

blah...

### Configure ADFS wibble...

The fun part.....


## Create a new OpenID Connect Client in AD FS

click click

allow the client access to some stuff

`powershell command here` 

Profit!

## Configure Jenkins to use this client

standard stuff, use the well-known endoint...  `examaple.com`