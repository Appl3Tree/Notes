# Linux Basics

{% hint style="success" %}
Hack Responsibly.

Always ensure you have **explicit** permission to access any computer system **before** using any of the techniques contained in these documents. You accept full responsibility for your actions by applying any knowledge gained here.‌
{% endhint %}

## Preseeding
You can pressed any installer question with boot parameters which are accessible through /proc/cmdline.
> You can directly use the full identifier of the debconf questions, such as `debian-installer/lanugage=en`, `language=en`, or `hostname=kali`  

### Preseed Config
File presence locations
- Media
    * /cdrom/preseed.cfg
    * /hdmedia/preseed.cfg
- Network
    * preseed/url=http://server/preseed.cfg 

### Overcoming limitations
To overcome the limitation of not being able to preseed the language, country, and keyboard questions, you can add the boot parameter `auto-install/enable=true` (or `auto=true`)

### Creating a Preseed File
The simplest way to write a preseed file is to install a system by hand. Then the `debconf-get-selections --installer` command will provide the answers you provided. You can get answers directed to other packages with `debconf-get-selections`.
The cleaner solution is to write the preseed file by hand, starting from an example and then going through the documentation. This way only questions where the default answer needs to be overwritten can be preseeded. Provide the `priority=critical` boot parameter to instruct Debconf to only ask critical questions, and to use default answers for others.
Examples:
- `d-i mirror/suite string kali-rolling`
