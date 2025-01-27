# Module 13: Active Directory Enumeration

## Abusing Lightweight Directory Access Protocol

### Understanding LDAP

LDAP was designed to interact with a directory service, such as Active Directory. It is built upon the _client-server model_.

LDAP clients send requests called _operations_ to an LDAP server. These are used to authenticated clients or retrieve/modify entries within a directory.

<figure><img src="../../../.gitbook/assets/image.png" alt=""><figcaption><p>Simple LDAP client-server model</p></figcaption></figure>

### Interacting with LDAP

LDAP is inter-operable with custom applications, which is largely possible due to the inclusion of _Active Directory Service Interfaces_ (ADSI).

_PowerShell script to perform LDAP lookup_

{% code overflow="wrap" %}
```powershell
PS C:\Users\offsec> $Searcher = New-Object System.DirectoryServices.DirectorySearcher

PS C:\Users\offsec> $Searcher.Filter = '(distinguishedName=CN=DC-2,OU=Domain Controllers,DC=corp,DC=com)'

PS C:\Users\offsec> $Searcher.FindOne()
```
{% endcode %}

{% hint style="info" %}
By default, _DirectorySearcher_ instantiates an object with the Filter property to the value of _(objectClass=\*)_, which is an LDAP query returning every entry within a directory service.
{% endhint %}

_PowerShell script to execute LDAP as a different user_

{% code overflow="wrap" %}
```powershell
PS C:\Users\offsec> $Searcher = New-Object System.DirectoryServices.DirectorySearcher

PS C:\Users\offsec> $Searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=corp,DC=com", 'corp\jdoe','Qwerty09!')

PS C:\Users\offsec> $Searcher.Filter = '(&(objectClass=computer)(cn=*dc*))'

PS C:\Users\offsec> $Searcher.FindAll()

Path                                                Properties
----                                                ----------
LDAP://CN=DC01,OU=Domain Controllers,DC=corp,DC=com {ridsetreferences, logoncount, codepage, ob...
LDAP://CN=DC-2,OU=Domain Controllers,DC=corp,DC=com {logoncount, codepage, objectcategory, iscr...
```
{% endcode %}

### Enumerating Active Directory with PowerView

PowerView contains dozens of functions that can be used to enumerate Active Directory. They incorporate OS APIs.

## Detecting Active Directory Enumeration

### Auditing Object Access

To identify malicious enumeration events taking place against AD, we need to implement an _audit policy_. These are extensions of the built-in Windows logging.

We can display and configure audit policies with the _auditpol_ command line utility.

### Baseline Monitoring



### Using Honey Tokens

