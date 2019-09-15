# HoneySPN

## OPTION 1

`Ipmo ActiveDirectory`

If you don't have RSAT installed, you can just import the ActiveDirectory PS Cmdlets dll.

<code>$SecPassword = ConvertTo-SecureString 'Password_you_want_as_honeySPN' -AsPlainText -Force

New-ADUser -Name "MSSQL_Confidential" -AccountPassword $SecPassword -ChangePasswordAtLogon $false -City "Leamington Spa" -Company "Nettitude" -Country "UK" -Enabled $true -Department "Service Accounts" -Description "Account used for privileged access to confidential data" -DisplayName "MSSQL_Confidential" -PasswordNeverExpires $true -SamAccountName "MSSQL_Confidential" -Path "OU=ServiceAccounts,dc=MAC_ACCOUNTS,dc=MAC,dc=local" </code>

You could also add -AllowReversiblePasswordEncryption $true to make it REALLY attractive to attackers.

## OPTION 2

We can use SetSPN.exe to register the SPN in the 'old school' way:
```setspn -A MSSQLSvc/SQLServer.ServerName.Mac.local:1433 mac.local\MSSQL_Confidential  ```

Or use PowerShell to call SetSPN and check whether it exit'd with a code of 0 - eg Not an Error.
```
$process = $proc = Start-Process setspn.exe -ArgumentList "-U", "-S", "MSSQLSvc/SQLServer:1433", "MAC.local\MSSQL_Confidential" -Wait -PassThru
if ($process.ExitCode -ne 0)
{
    throw "setspn.exe error with exit code $($process.ExitCode)!"
}
```
## OPTION 3

You can also do this entirely in PS, using DBA_Tools from PS Gallery:
Source: https://dbatools.io/

Make the user in the normal fashion then in PowerShell:

`Install-Module dbatools`
Then use sytax similar to:
```Set-DbaSpn -SPN MSSQLSvc/SQLServer.MAC.local -ServiceAccount Mac.local\MSSQL_Confidential -NoDelegation```

## OPTION 4

Or just use the GUI in an MMC:

* Make a new user either in Powershell or DSA.msc
* Add in Advanced Settings in View, so you can get to Attribute Editor.
* Set AdminCount to 1
* Set ServicePrincipalName to MSSQLSvc/SQLServer.MAC.local
