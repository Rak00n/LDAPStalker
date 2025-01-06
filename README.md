This tool interacts with Windows LDAP server and fetches all accessible data from it.

Sometimes it's not clear what changes are made during AD deployment. What accounts are created and what attributes are populated?

This tool was developed to troubleshoot intricate AD configurations and monitor changes which are made by additional software (MS Sharepoint, MS Exhange...)

```bash
LDAPStalker.exe -action print -dcip 192.168.56.106 -dcPort 389 -domain "test.local" -user "administrator" -password "Y0urD0m@in@dminP@$$w0rd"
```

