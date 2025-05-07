# Module 18: SIEM Part Two: Combining the Logs

## Phase One: Web Server Initial Access

### Enumeration and Command Injection of web01

Assumptions for this module-long lab: _phase one was initiated shortly after Apr 27, 2022 @ 12:58:00.000 and ended just before Apr 27, 2022 @ 13:00:00.000._

### Phase One Detection Rules

_Creating a Web Enumeration detection rule_

<figure><img src="../../../.gitbook/assets/image (81).png" alt=""><figcaption><p>Rule Type and Custom Query for Web Enumeration</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (82).png" alt=""><figcaption><p>Group by fields for Web Enumeration</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (83).png" alt=""><figcaption><p>About rule details for Web Enumeration</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (84).png" alt=""><figcaption><p>Rule schedule and actions for Web Enumeration</p></figcaption></figure>

_Creating a Command Injection detection rule_

<figure><img src="../../../.gitbook/assets/image (85).png" alt=""><figcaption><p>Rule Type and Custom Query for Command Injection</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (86).png" alt=""><figcaption><p>About rule details for Command Injection</p></figcaption></figure>

_Example of detection rules in action_

<figure><img src="../../../.gitbook/assets/image (87).png" alt=""><figcaption><p>Phase One Alert Detection</p></figcaption></figure>

## Phase Two: Lateral Movement to Application Server

### Brute Force and Authentication to appsrv01

Utilizing fields like _source.ip, host.ip,_ and _event.action_ can assist in identifying brute force and authentication as _event.action_ will easily identify the action taken and then filtering on failed/successful logins will show the attack path.

### Phase Two Detection Rules

_Creating a detection rule to identify SSH logins as root_

<figure><img src="../../../.gitbook/assets/image (88).png" alt=""><figcaption><p>Define rule for SSH using root account</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (89).png" alt=""><figcaption><p>About rule for SSH using root account</p></figcaption></figure>

_Creating a detection rule to identify RDP Brute Force attempts_

<figure><img src="../../../.gitbook/assets/image (90).png" alt=""><figcaption><p>Define rule for RDP Brute Force</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (91).png" alt=""><figcaption><p>About rule for RDP Brute Force</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (92).png" alt=""><figcaption><p>RDP Brute Force Security Override</p></figcaption></figure>

_Example of detection rules in action_

<figure><img src="../../../.gitbook/assets/image (93).png" alt=""><figcaption><p>Phase Two Alert Detection</p></figcaption></figure>

## Phase Three: Persistence and Privilege Escalation on Application Server

### Persistence and Privilege Escalation on appsrv01

_Syslog rocks_.&#x20;

### Phase Three Detection Rules

_Creating a detection rule for DLL Creation by PowerShell_

<figure><img src="../../../.gitbook/assets/image (96).png" alt=""><figcaption><p>Define rule for DLL Creation by PowerShell</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (97).png" alt=""><figcaption><p>About rule for DLL Creation by PowerShell</p></figcaption></figure>

_Creating a detection rule for finding Mimikatz_

_Custom query to detect PowerShell's access of lsass.exe_

{% code overflow="wrap" %}
```
event.code: 10 and winlog.event_data.TargetImage : "C:\\Windows\\system32\\lsass.exe" and process.name: "powershell.exe"
```
{% endcode %}

<figure><img src="../../../.gitbook/assets/image (98).png" alt=""><figcaption><p>About rule for detecting PowerShell's access of lsass.exe</p></figcaption></figure>

_Example of detection rules in action_

<figure><img src="../../../.gitbook/assets/image (99).png" alt=""><figcaption><p>Phase Three Alert Detection</p></figcaption></figure>

## Phase Four: Perform Actions on Domain Controller

### Dump AD Database

Follow the strings, OSQuery can be useful... sometimes...

### Phase Four Detection Rules

_Creating a detection rule to catch ntdsutil dumping registry_

_Custom query to detect execution of ntdsutil.exe_

```
event.code: "1" and process.name: "ntdsutil.exe"
```

<figure><img src="../../../.gitbook/assets/image (94).png" alt=""><figcaption><p>About rule for Active Directory Database Hashdump (ntdsutil.exe)</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (95).png" alt=""><figcaption><p>Phase Four Alert Detection</p></figcaption></figure>
