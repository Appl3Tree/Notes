# Module 16: Active Directory Persistence

## Keeping Domain Access

### Domain Group Memberships

_Built-in privileged security groups_

| Group Name        | Description                                                                                                                                                                     |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Domain Admins     | Grants full control of the domain, is a member of the built-in administrators group on all domain controllers in a domain, and are administrators on the domain-joined machines |
| Enterprise Admins | Grants full control of all domains in a forest and is a member of the built-in administrators group on all domain controllers in a forest                                       |
| Administrators    | Grants full control of all the domain controllers in a domain                                                                                                                   |

_Group scope definitions_

| Scope Name   | Definition                                                                      |
| ------------ | ------------------------------------------------------------------------------- |
| Universal    | Can be assigned in any domain in the same forest or trusting forests            |
| Global       | Can be assigned in any domain in the same forest or trusting domains or forests |
| Domain Local | Can only be assigned in the current domain                                      |

_Listing account management audit policy settings_

```powershell
PS C:\Windows\system32> auditpol /get /category:"Account Management"
System audit policy
Category/Subcategory                      Setting
Account Management
  Computer Account Management             Success
  Security Group Management               Success
  Distribution Group Management           No Auditing
  Application Group Management            No Auditing
  Other Account Management Events         No Auditing
  User Account Management                 Success
```

There are three conditions that will trigger an alert from this audit policy:

1. A security group is created, changed, or deleted
2. A security group has a member added or removed
3. A security group is changed to a distribution group or vice versa

_Event IDs for group membership changes_

| Event ID | Description                                                  |
| -------- | ------------------------------------------------------------ |
| 4728     | A member was added to a security-enabled global group        |
| 4729     | A member was removed from a security-enabled global group    |
| 4732     | A member was added to a security-enabled local group         |
| 4733     | A member was removed from a security-enabled local group     |
| 4756     | A member was added to a security-enabled universal group     |
| 4757     | A member was removed from a security-enabled universal group |

_XPath XML filter for all security group changes_

{% code overflow="wrap" lineNumbers="true" %}
```xml
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">*[System[(EventID=4728 or EventID=4729 or EventID=4732 or EventID=4733 or EventID=4756 or EventID=4757)]]</Select>
  </Query>
</QueryList>
```
{% endcode %}

_XPath XML filter for targeted security group changes_

{% code overflow="wrap" lineNumbers="true" %}
```xml
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">*[System[(EventID=4728 or EventID=4729 or EventID=4732 or EventID=4733 or EventID=4756 or EventID=4757)]]
    And
    *[EventData[Data[@Name='TargetUserName'] and (Data='Domain Admins' or Data='Administrators' or Data='Enterprise Admins')]]
    </Select>
  </Query>
</QueryList>
```
{% endcode %}

_XPath filter for all security group changes for three named groups_

{% code overflow="wrap" lineNumbers="true" %}
```powershell
$FilterXML = @'
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">*[System[(EventID=4728 or EventID=4729 or EventID=4732 or EventID=4733 or EventID=4756 or EventID=4757)]]
    and
 *[EventData[Data[@Name='TargetUserName'] and (Data='Administrators' or Data='Domain Admins' or Data='Enterprise Admins')]]
    </Select>
  </Query>
</QueryList>
'@
$Logs = Get-WinEvent -FilterXml $FilterXML
ForEach ($L in $Logs) {
   [xml]$XML = $L.toXml()
   $TimeStamp = $XML.Event.System.TimeCreated.SystemTime
   $MemberName = $XML.Event.EventData.Data[0].'#text'
   $GroupName = $XML.Event.EventData.Data[2].'#text'
   $SubjectUserName = $XML.Event.EventData.Data[6].'#text'
 [PSCustomObject]@{'TimeStamp' = $TimeStamp; 'MemberName' = $MemberName; 'GroupName' = $GroupName; 'SubjectUserName' = $SubjectUserName; 'ChangeType' = "($EventID) $ChangeType" }
}
```
{% endcode %}

_Function to provide event descriptions_

{% code overflow="wrap" lineNumbers="true" %}
```powershell
Function Get-ChangeType ([System.String]$Id) {
    Begin {
        $ChangeTable = @{
            '4728' = '(4728) A member was added to a security-enabled global group.'
            '4729' = '(4729) A member was removed from a security-enabled global group.'
            '4732' = '(4732) A member was added to a security-enabled local group.'
            '4733' = '(4733) A member was removed from a security-enabled local group.'
            '4756' = '(4756) A member was added to a security-enabled universal group.'
            '4757' = '(4757) A member was removed from a security-enabled universal group.'
        }
    }
    Process {
        $Value = $ChangeTable[$Id]
        If (!$Value) {
            $Value = $Id
        }
    }
    End {
        return $Value
    }
}
```
{% endcode %}

_Complete output from the security group audit script_

```powershell
PS C:\Users\offsec\Desktop\Persistence> .\Get-SecurityGroupChanges.ps1

TimeStamp       : 2022-01-19T18:46:30.146129500Z
MemberName      : CN=John Doe,OU=Staff,DC=corp,DC=com
GroupName       : Enterprise Admins
SubjectUserName : Administrator
ChangeType      : (4756) A member was added to a security-enabled universal group.
TimeStamp       : 2022-01-19T18:42:45.830841000Z
MemberName      : cn=dadmin,ou=Staff,DC=corp,DC=com
GroupName       : Domain Admins
SubjectUserName : Administrator
ChangeType      : (4728) A member was added to a security-enabled global group.
```

### Domain User Modifications

_Listing the account management sub-categories_

```powershell
PS C:\Windows\system32> auditpol /get /category:"Account Management"
System audit policy
Category/Subcategory                      Setting
Account Management
  Computer Account Management             Success
  Security Group Management               Success
  Distribution Group Management           No Auditing
  Application Group Management            No Auditing
  Other Account Management Events         No Auditing
  User Account Management                 Success
```

_XPath XML filter for user account management events_

{% code overflow="wrap" lineNumbers="true" %}
```xml
<QueryList>
  <Query Id="0" Path="Security">
    <Select
Path="Security">*[System[Provider[@Name='Microsoft-Windows-Security-Auditing'] and Task = 13824]]
    and 
    *[EventData[Data[@Name='SubjectUserName'] and
(Data='dadmin')]]
    </Select>
  </Query>
</QueryList>
```
{% endcode %}

_Function to provide user account management event descriptions_

{% code overflow="wrap" lineNumbers="true" %}
```powershell
Function Get-ChangeType ([System.String]$EventId) {
    Begin {
        $ChangeTable = @{
            '4720' = “($EventId) A user account was created.”
            '4722' = “($EventId) A user account was enabled.”
            '4723' = “($EventId) An attempt was made to change an account''s password.”
            '4724' = “($EventId) An attempt was made to reset an account''s password.”
            '4738' = “($EventId) A user account was changed.”
            '4740' = “($EventId) A user account was locked out.”
            '4765' = “($EventId) SID History was added to an account.”
            '4766' = “($EventId) An attempt to add SID History to an account failed.”
            '4767' = “($EventId) A user account was unlocked.”
            '4780' = “($EventId) The ACL was set on accounts which are members of administrators groups.”
            '4781' = “($EventId) The name of an account was changed.”
            '4794' = “($EventId) An attempt was made to set the Directory Services Restore Mode administrator password.”
            '4798' = “($EventId) A user''s local group membership was enumerated.”
            '5376' = “($EventId) Credential Manager credentials were backed up.”
            '5377' = “($EventId) Credential Manager credentials were restored from a backup.”
            '5379' = 'Credential Manager credentials were read'
        }
    }
    Process {
        $Value = $ChangeTable[$EventId]
        If (!$Value) {
            $Value = $EventId
        }
    }
    End {
        return $Value
    }
}
```
{% endcode %}

_Running the user change audit script_

{% code overflow="wrap" %}
```powershell
PS C:\Users\offsec\Desktop\Persistence> .\Get-UserChanges.ps1

TimeStamp                      SubjectUserName TargetUserName ChangeType
---------                      --------------- -------------- ----------
2022-03-09T19:57:30.859931700Z dadmin          notahacker     (4724) An attempt was made to reset an account's passw...
2022-03-09T19:57:30.859864400Z dadmin          notahacker     (4738) A user account was changed.
...
```
{% endcode %}

### Golden Tickets

_Typical kerberos ticket_

{% code overflow="wrap" %}
```powershell
PS C:\Users\offsec.CORP> klist

Current LogonId is 0:0xf5cad

Cached Tickets: (6)

#0>     Client: offsec @ CORP.COM
        Server: krbtgt/CORP.COM @ CORP.COM
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40e10000 -> forwardable renewable initial pre_authent name_canonicalize
        Start Time: 3/9/2022 12:30:03 (local)
        End Time:   3/9/2022 22:30:03 (local)
        Renew Time: 3/16/2022 12:30:03 (local)
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0x1 -> PRIMARY
        Kdc Called: DC01
...
```
{% endcode %}

_Function to retrieve key values from the GPOReport_

{% code overflow="wrap" lineNumbers="true" %}
```powershell
Function Get-KerberosSettings {
    Begin {
        [xml]$XML = Get-GPOReport -Name 'Default Domain Policy' -ReportType xml
    }
    Process {
        $Kerberos = $XML.GPO.Computer.ExtensionData.Extension.Account | Where-Object { $_.Type -eq 'Kerberos' }
    }
    End {
        return [PSCustomObject]@{'MaxClockSkew' = $Kerberos[0].SettingNumber; 'MaxRenewAge' = $Kerberos[1].SettingNumber; 
            'MaxServiceAge' = $Kerberos[2].SettingNumber; 'MaxTicketAge' = $Kerberos[3].SettingNumber; 'TicketValidateClient' = $Kerberos[4].SettingBoolean
        }
    }
}
```
{% endcode %}

_Executing the Get-Kerberos Settings function_

```powershell
PS C:\Users\offsec\Desktop\Persistence> . .\Get-KerberosSettings.ps1

PS C:\Users\offsec\Desktop\Persistence> Get-KerberosSettings

MaxClockSkew         : 5
MaxRenewAge          : 7
MaxServiceAge        : 600
MaxTicketAge         : 10
TicketValidateClient : true
```

_A cached golden ticket_

```powershell
PS C:\Users\offsec.CORP\Desktop\Persistence> klist

Current LogonId is 0:0xa54c6

Cached Tickets: (1)

#0>     Client: dadmin @ corp.com
        Server: krbtgt/corp.com @ corp.com
        KerbTicket Encryption Type: RSADSI RC4-HMAC(NT)
        Ticket Flags 0x40e00000 -> forwardable renewable initial pre_authent
        Start Time: 3/9/2022 12:39:54 (local)
        End Time:   3/6/2032 12:39:54 (local)
        Renew Time: 3/6/2032 12:39:54 (local)
        Session Key Type: RSADSI RC4-HMAC(NT)
        Cache Flags: 0x1 -> PRIMARY
        Kdc Called:
```

Kerberos tickets are assigned to logon sessions, identified by logon IDs. Executing `klist`without any parameters only displays cached tickets for the current session

_Running the klist command_

```powershell
PS C:\Users\offsec\Desktop\Persistence> klist
Current LogonId is 0:0x1fa47a
...
```

_Running the klist sessions command_

```powershell
PS C:\Users\offsec.CORP\Desktop\Persistence> klist sessions    

Current LogonId is 0:0xa54c6
[0] Session 2 0:0xa5996 CORP\offsec Negotiate:RemoteInteractive
[1] Session 2 0:0xa54c6 CORP\offsec Kerberos:RemoteInteractive
[2] Session 2 0:0xa06a5 Window Manager\DWM-2 Negotiate:Interactive              
...
[12] Session 0 0:0x3e7 CORP\CLIENT03$ Negotiate:(0)
```

_Runnin the klist command with a targetd logon ID_

{% code overflow="wrap" %}
```powershell
PS C:\Users\offsec.CORP\Desktop\Persistence> klist -li 0x3e7

Current LogonId is 0:0xa54c6
Targeted LogonId is 0:0x3e7

Cached Tickets: (6)

#0>     Client: client03$ @ CORP.COM
        Server: krbtgt/CORP.COM @ CORP.COM
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x60a10000 -> forwardable forwarded renewable pre_authent name_canonicalize
        Start Time: 3/9/2022 12:19:05 (local)
        End Time:   3/9/2022 22:19:02 (local)
        Renew Time: 3/16/2022 12:19:02 (local)
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0x2 -> DELEGATION
        Kdc Called: dc01.corp.com
...
```
{% endcode %}

Unfortunately, the klist command doesn't offer a method to retrieve cached tickets for every session on the computer in one go.

_PowerShell one-liner to dump all cached tickets_

{% code overflow="wrap" %}
```powershell
PS C:\Users\offsec.CORP\Desktop\Persistence> (klist sessions 2>&1) | ? {$_ -like '* Session*'} | % {(($_ -split ' ')[3]).substring(2)} | ForEach-Object {klist -li $_}
```
{% endcode %}

_Function to provide all logon IDs_

{% code overflow="wrap" lineNumbers="true" %}
```powershell
Function Get-LogonIds {
    Begin {
        $Klist = klist sessions
    }
    Process {
        $Sessions = $Klist | ? { $_ -like '* Session*' } | % { (($_ -split ' ')[3]).substring(2) }
    }
    End {
        return $Sessions
    }
}
```
{% endcode %}

_Function to retrieve session tickets_

{% code overflow="wrap" lineNumbers="true" %}
```powershell
Function Get-Tickets {
    [cmdletbinding()]
    param (
        [parameter(mandatory = $false, ValueFromPipeline = $true)]
        [System.String]$LogonId
    )
    Begin {
        $CachedTickets = @()
        $Klist = klist
        $Current = ((($klist) -split 'Current LogonId is')[2] -split ':')[1]
    }
    Process {
        try {
            if ($LogonId -eq $Current -or $LogonId -eq '') {
                $Klist = klist
                $LogonId = $Current
            }
            else {
			$Klist = klist -li $LogonId
            }           
            $Tickets = 5..$Klist.count | ForEach-Object { $Klist[$_] } | Where-Object { $_ }
            if ($Klist -notcontains 'Cached Tickets: (0)') {
                0..$(($Tickets | Select-String "^#\d>").Count - 1) | ForEach-Object {
                    $Index = $_ * 10
                    $Properties = [ordered]@{
                        'LogonId'        = $LogonId
                        'Ticket'         = $_
                        'Client'         = $($Tickets[0 + $Index] -split ':')[1].Trim()
                        'Server'         = $($Tickets[1 + $Index] -split ':')[1].Trim()
                        'EncryptionType' = $($Tickets[2 + $Index] -split ':')[1].Trim()
                        'TicketFlags'    = $($Tickets[3 + $Index] -split 'Ticket Flags')[1].Trim()
                        'StartTime'      = $($Tickets[4 + $Index] -split 'Start Time:')[1].Trim()
                        'EndTime'        = $($Tickets[5 + $Index] -split 'End Time:')[1].Trim()
                        'RenewTime'      = $($Tickets[6 + $Index] -split 'Renew Time:')[1].Trim()
                        'SessionKeyType' = $($Tickets[7 + $Index] -split ':')[1].Trim()
                        'CacheFlags'     = $($Tickets[8 + $Index] -split ':')[1].Trim()
                        'KdcCalled'      = $($Tickets[9 + $Index] -split ':')[1].Trim()
                    }                    
                    if ($Properties) {
                        $CachedTickets += New-Object -TypeName PSObject -Property $Properties
                    }
                }
            }
        }
        catch {
            if ($_ -like "*Error calling API*") {
                $_ | Out-null
            }
        }
    }
    End {
        return $CachedTickets
    }
}
```
{% endcode %}

_Running the Get-LogonIds and Get-Tickets together_

{% code overflow="wrap" lineNumbers="true" %}
```powershell
PS C:\Users\offsec.CORP\Desktop\Persistence> . .\Get-LogonIds.ps1

PS C:\Users\offsec.CORP\Desktop\Persistence> . .\Get-Tickets.ps1

PS C:\Users\offsec.CORP\Desktop\Persistence> Get-LogonIds | Get-Tickets


LogonId        : 0xa54c6
Ticket         : 0
Client         : dadmin @ corp.com
Server         : krbtgt/corp.com @ corp.com
EncryptionType : RSADSI RC4-HMAC(NT)
TicketFlags    : 0x40e00000 -> forwardable renewable initial pre_authent
StartTime      : 3/9/2022 12:39:54 (local)
EndTime        : 3/6/2032 12:39:54 (local)
RenewTime      : 3/6/2032 12:39:54 (local)
SessionKeyType : RSADSI RC4-HMAC(NT)
CacheFlags     : 0x1 -> PRIMARY
KdcCalled      :
...
```
{% endcode %}

_Retrieving ticket time values_

{% code overflow="wrap" %}
```powershell
PS C:\Users\offsec.CORP\Desktop\Persistence> Get-LogonIds | Get-Tickets | Select LogonId,StartTime,EndTime | Sort EndTime

LogonId StartTime                 EndTime
------- ---------                 -------
0xa54c6 3/9/2022 12:39:54 (local) 3/6/2032 12:39:54 (local)
0x3e7   3/9/2022 12:19:05 (local) 3/9/2022 22:19:02 (local)
0x3e7   3/9/2022 12:19:02 (local) 3/9/2022 22:19:02 (local)
...
```
{% endcode %}

_Function to analyze ticket values_

{% code overflow="wrap" lineNumbers="true" %}
```powershell
Function Invoke-GoldenSweep {
    [cmdletbinding()]
    param (
        [parameter(mandatory = $true, ValueFromPipeline = $true)]
        $Ticket
    )
    Process {
        # Time Beacons
        $StartTime = ($Ticket.StartTime -split ' ')[0]
        $EndTime = ($Ticket.EndTime -split ' ')[0]
        $RenewTime = ($Ticket.RenewTime -split ' ')[0]
        if ((New-TimeSpan -Start $StartTime -End $EndTime).Days -gt 10) {
            $Flagged = $Ticket
        }
        if ($RenewTime -ne 0) {
            if ((New-TimeSpan -Start $StartTime -End $RenewTime).Days -gt 7) {
                $Flagged = $Ticket
            }
        }
    }
    End {
        return $Flagged
    }
}
```
{% endcode %}

_Running a golden ticket discovery chain_

{% code overflow="wrap" %}
```powershell
PS C:\Users\offsec.CORP\Desktop\Persistence> . .\Invoke-GoldenSweep.ps1

PS C:\Users\offsec.CORP\Desktop\Persistence> Get-LogonIds | Get-Tickets | Invoke-GoldenSweep

LogonId        : 0xa54c6
Ticket         : 0
Client         : dadmin @ corp.com
Server         : krbtgt/corp.com @ corp.com
EncryptionType : RSADSI RC4-HMAC(NT)
TicketFlags    : 0x40e00000 -> forwardable renewable initial pre_authent
StartTime      : 3/9/2022 12:39:54 (local)
EndTime        : 3/6/2032 12:39:54 (local)
RenewTime      : 3/6/2032 12:39:54 (local)
SessionKeyType : RSADSI RC4-HMAC(NT)
CacheFlags     : 0x1 -> PRIMARY
KdcCalled      :
```
{% endcode %}

_Logic to detect the RC4 encryption type value_

{% code overflow="wrap" lineNumbers="true" %}
```powershell
# Encryption Beacons
$EncryptionType = $Ticket.EncryptionType
If ($EncryptionType -eq ‘RSADSA RC4-HMAC(NT)’) {
	$Flagged = $Ticket
}
```
{% endcode %}
