This tool interacts with Windows LDAP server and fetches all accessible data from it.

Sometimes it's not clear what changes are made during AD deployment. What accounts are created and what attributes are populated?

This tool was developed to troubleshoot intricate AD configurations and monitor changes which are made by additional software (MS Sharepoint, MS Exhange...)

Print current LDAP state:
```bash
LDAPStalker.exe -action print -dcip 192.168.56.106 -dcPort 389 -domain "test.local" -user "administrator" -password "Y0urD0m@in@dminP@$$w0rd"
```

Start Monitoring LDAP for changes:
```azure
LDAPStalker.exe -action monitor -dcip 192.168.56.106 -dcPort 389 -domain test.local -user administrator -password "Y0urD0m@in@dminP@$$w0rd"

Waiting for stable LDAP state...
2025-01-06 17:15:45 Reached stable state. Waiting for changes...
2025-01-06 17:16:08 CN=user,CN=Users,DC=test,DC=local  -> attribute created: description: newTestDescription
2025-01-06 17:16:08 CN=user,CN=Users,DC=test,DC=local  -> attribute created: physicalDeliveryOfficeName: newOffice
2025-01-06 17:16:08 CN=user,CN=Users,DC=test,DC=local  -> attribute changed: whenChanged : 20250106141518.0Z -> 20250106141604.0Z
2025-01-06 17:16:08 CN=user,CN=Users,DC=test,DC=local  -> attribute changed: uSNChanged : 65734 -> 65735
2025-01-06 17:16:22 CN=user,CN=Users,DC=test,DC=local  -> attribute changed: whenChanged : 20250106141604.0Z -> 20250106141620.0Z
2025-01-06 17:16:22 CN=user,CN=Users,DC=test,DC=local  -> attribute changed: uSNChanged : 65735 -> 65737
2025-01-06 17:16:22 CN=user,CN=Users,DC=test,DC=local  -> attribute removed: description
```
