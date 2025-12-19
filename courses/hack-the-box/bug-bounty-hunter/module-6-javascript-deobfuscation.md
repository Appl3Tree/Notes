# Module 6: JavaScript Deobfuscation

## Introduction

### Introduction

This module teaches locating and deobfuscating JavaScript in web pages to analyze hidden or malicious behavior.

Code deobfuscation is a core skill for code analysis and reverse engineering. Obfuscated JavaScript often conceals functionality (for example, malware that fetches payloads). Understanding and reversing that obfuscation reveals intent and enables manual replication or mitigation.

The module workflow:

* examine the HTML page structure and locate embedded/linked JavaScript;
* define obfuscation, common techniques, and typical use-cases;
* apply deobfuscation methods to recover readable code;
* decode encoded messages found in scripts;
* perform basic code analysis to determine behavior;
* send simple HTTP requests to reproduce or observe network interactions.

***

### Source Code

Client-side web applications commonly split responsibilities: HTML defines structure and semantics, CSS defines presentation, and JavaScript implements behavior. Browsers render these artifacts so users rarely inspect the raw source, but viewing the source reveals client-side logic and comments that can contain useful (or sensitive) information.

#### HTML

Open the page source (for example, via **Ctrl+U**) to inspect structure, inline comments, and references to external assets. Source often contains developer comments and markup that clarify how the page should behave; attackers or analysts can leverage that information.

Example (fictionalized) minimal page:

```html
<!doctype html>
<html>
<head>
    <title>Secret Serial Generator</title>
    <link rel="stylesheet" href="AcmeCorp_style.css">
</head>
<body>
    <h1>Secret Serial Generator</h1>
    <script src="AcmeCorp_secret.js"></script>
</body>
</html>
```

#### CSS

Styles may be embedded inside `<style>` blocks or provided by external `.css` files referenced with `<link>`. Inline styles appear in the HTML; external styles are useful to locate for additional context.

Example inline snippet:

```html
<style>
    *, html { margin: 0; padding: 0; border: 0; }
    h1 { font-size: 144px; }
    p  { font-size: 64px; }
</style>
```

#### JavaScript

Behavioral logic can be inline in `<script>` tags or kept in external `.js` files. External scripts are followed from the HTML source (click the filename in the source viewer). Obfuscated code commonly uses `eval` or code-generators to hide intent; when you open such a file you may see a dense `eval(...)` wrapper rather than readable logic. Identifying whether a script is internal or external and then fetching that file is a first step toward deobfuscation.

Example (fictionalized) observed pattern:

```javascript
// external file: AcmeCorp_secret.js
eval(/* large generated payload or encoder wrapper */);
```

***

## Obfuscation

### Code Obfuscation

Obfuscation transforms readable source into a functionally equivalent form that is intentionally hard for humans to understand. Tools perform this automatically by rewriting identifiers, restructuring control flow, and replacing literal tokens with lookups or computed values. The transformed code runs normally (sometimes with reduced performance) but resists manual inspection and simple signature detection.

#### What is obfuscation

Obfuscators commonly replace identifiers and literals with references into generated dictionaries, encode strings, and wrap logic in evaluators (e.g., `eval`) or decoder functions that reconstruct behavior at runtime. Interpreted client-side languages—especially JavaScript—are frequent targets because their source is delivered to users’ browsers in cleartext, unlike typical server-side languages.

#### Use Cases

* Intellectual property protection: make reuse or copying harder by hiding original structure and names.
* Attempted protection of client-side secrets: obfuscation can raise the effort to extract keys or algorithms (note: performing authentication or encryption in client-side code is not recommended).
* Evasion and malicious use: attackers obfuscate payloads to bypass signature-based detectors and to slow analysis.
* Anti-reverse-engineering: increase cost and time for analysts attempting to understand the code.

Intrusion Detection and Prevention systems (IDPS) are commonly targeted by obfuscation-based evasions.

***

### Basic Obfuscation

Obfuscation is typically performed using automated tools that rewrite source code into a less readable but functionally identical form. Developers and attackers alike use such tools to hinder analysis or protect intellectual property.

#### Running JavaScript code

Start with a simple snippet and verify its behavior before any transformations.

```javascript
console.log('Demo Message');
```

When executed in a browser console, this prints:

```
Demo Message
```

#### Minifying JavaScript code

Minification removes whitespace and formatting without changing functionality. For a one-line snippet, the effect is minimal but demonstrates the process used on larger scripts.

```javascript
console.log('Demo Message');
```

#### Packing JavaScript code

Packing compresses and obfuscates by encoding tokens into a dictionary and reconstructing them at runtime. This technique often wraps the code inside an `eval()` call that decodes and executes the script dynamically.

Working packed example:

```javascript
eval(function(p,a,c,k,e,d){
    e=function(c){return c};
    if(!''.replace(/^/,String)){while(c--){d[c]=k[c]||c}k=[function(e){return d[e]}];e=function(){return'\\w+'};c=1}
    while(c--){if(k[c]){p=p.replace(new RegExp('\\b'+e(c)+'\\b','g'),k[c])}}
    return p;
}("3.2('1 0');",4,4,'Message|Demo|log|console'.split('|'),0,{}))
```

When executed, this produces the same output:

```
Demo Message
```

The `function(p,a,c,k,e,d)` wrapper pattern is characteristic of **packer-style obfuscation**, where identifiers and literals are stored in a lookup table and reassembled during runtime to conceal original logic.

***

### Advanced Obfuscation

**Quick Notes**

* Hide cleartext strings and semantic hints
* Base64 string-array obfuscation
* Runtime decoding and indirection
* Verification via JS consoles
* Performance trade-offs of extreme encodings

#### Why Advanced Obfuscation Is Needed

Simple obfuscation techniques still expose string literals, which often reveal program intent. Advanced obfuscation focuses on eliminating all readable strings so functionality cannot be inferred through static inspection.

#### Base64 String Array Obfuscation

A common technique is relocating all string literals into an encoded array that is decoded at runtime. A public tool that supports this approach is:

* [https://obfuscator.io](https://obfuscator.io/)

Typical usage:

1. Paste the JavaScript source.
2. Enable string array handling with **Base64 encoding**.
3. Generate the obfuscated output.
4. Execute the result to confirm behavior is unchanged.

Common characteristics of the output:

* Encoded string array
* Array index shuffling
* Runtime Base64 decoder
* Decoded-string caching
* Dynamic property and function access

All meaningful identifiers and strings are resolved only during execution.

#### Verifying Behavior

Obfuscated output should still perform identically. This can be verified by running it in a JavaScript execution environment such as:

* [https://jsconsole.com](https://jsconsole.com/)

Observable output (e.g., logging or alerts) should match the original script.

#### Obfuscation Strength vs Performance

More aggressive settings increase resistance to analysis but introduce overhead:

* Larger script size
* Slower initialization
* Increased runtime cost

Each added layer trades performance for opacity.

#### Extreme Expression-Based Obfuscation

Some obfuscators encode entire scripts using only booleans, arrays, coercion, and indexing. These rely on predictable JavaScript type conversions to rebuild identifiers at runtime.

Typical traits:

* Expressions like `![]`, `!![]`, `[]+[]`
* Character extraction from coerced strings
* Deeply nested runtime reconstruction

These scripts execute correctly but can be very slow for non-trivial payloads.

#### Practical Considerations

Highly aggressive obfuscation is useful for:

* Discouraging casual analysis
* Demonstrations
* Bypassing simplistic filters

It is generally unsuitable for maintainable production code due to performance impact and loss of debuggability. Tools such as JJ Encode and AA Encode fall into this category and should be used selectively.

***

### Deobfuscation

**Quick Notes**

* Minification vs obfuscation
* Beautifying JavaScript for readability
* Automated unpacking of common obfuscation patterns
* Limits of deobfuscation tools
* When manual reverse engineering is required

#### Purpose of Deobfuscation

Deobfuscation focuses on restoring readability and understanding behavior in obfuscated code. Automated tools can reverse common patterns, but success depends on how the code was originally transformed.

#### Beautifying Minified JavaScript

Obfuscated scripts are often minified into a single line. The first step in analysis is formatting the code.

Common options:

* Browser developer tools (pretty-print)
* Code editor plugins (Prettier, Beautifier)
* Online JavaScript beautifiers

Beautification restores indentation and line structure, making control flow easier to follow. It does not remove obfuscation logic.

#### Why Formatting Is Insufficient

Even after beautifying:

* Identifiers remain meaningless
* Strings may be reconstructed at runtime
* Logic may rely on `eval` or regex-based replacement

Deobfuscation is required to expose intent.

#### Automated Deobfuscation (Unpacking)

A frequent obfuscation method is **packing**, where code is stored as an encoded string and rebuilt at runtime.

A reliable public unpacking tool is:

* [https://matthewfl.com/unPacker.html](https://matthewfl.com/unPacker.html)

Typical workflow:

1. Copy the obfuscated JavaScript.
2. Paste it into the unpacker.
3. Run the unpack operation.

> **Tip:** Do not include empty lines before the script, as this can cause incorrect results.

Successful unpacking often reveals:

* Clear function definitions
* Restored string literals
* Expanded control flow
* Visible network or DOM interactions

Example result (simplified):

```javascript
function generateSerial() {
    var xhr = new XMLHttpRequest();
    var url = "/serial.php";
    xhr.open("POST", url, true);
    xhr.send(null);
}
```

#### Manual Unpacking Technique

For simple packing schemes:

* Locate the function return value.
* Replace `eval` execution with `console.log`.
* Output the reconstructed source instead of executing it.

This exposes decoded code without running it.

#### Limits of Automated Tools

Automated unpackers are pattern-based and may fail when:

* Custom obfuscation is used
* Multiple encoding layers exist
* Runtime state influences decoding

Partial output or failure is common in advanced cases.

#### Manual Reverse Engineering

When tools fail, manual analysis is required:

* Step through decoding logic
* Resolve string transformations
* Track control-flow manipulation
* Reconstruct behavior incrementally

Advanced JavaScript deobfuscation typically combines static inspection with runtime debugging.

***

## Deobfuscation Examples

### Code Analysis

**Quick Notes**

* Identify exposed functions after deobfuscation
* Analyze network-related code behavior
* Understand client-side vs server-side responsibility
* Spot unused or unreleased functionality

#### Reviewing the Deobfuscated Code

After deobfuscation, the script is readable and minimal. The `secret.js` file defines a single function:

```javascript
'use strict';
function generateSerial() {
    var xhr = new XMLHttpRequest();
    var url = "/serial.php";
    xhr.open("POST", url, true);
    xhr.send(null);
}
```

The only executable logic present is the `generateSerial` function.

#### HTTP Request Construction

The function begins by creating an `XMLHttpRequest` object. This object is used in JavaScript to send HTTP requests and handle responses asynchronously.

A second variable defines the request target:

* `"/serial.php"`
  * No domain is specified, so the request is sent to the same origin as the current page.

#### Request Execution

The following calls define and execute the request:

* `xhr.open("POST", url, true)`
  * Initializes an asynchronous HTTP POST request to `/serial.php`.
* `xhr.send(null)`
  * Sends the request with no body data and without processing any response.

No headers are set, no payload is included, and no callback is defined to handle a response.

#### Functional Interpretation

The function’s behavior is limited to issuing a POST request to a server-side endpoint. It does not:

* Generate data client-side
* Process server responses
* Modify the DOM

This suggests the actual serial-generation logic, if it exists, would be implemented server-side in `serial.php`.

#### Contextual Implications

The absence of any visible trigger (e.g., a button or event handler calling `generateSerial`) implies the function may be:

* Unused
* Incomplete
* Reserved for future functionality

Such dormant or unreleased features are often poorly tested and may expose unintended behavior.

#### Next Analysis Step

With the client-side behavior understood, the logical next step is to manually replicate the request. Sending a POST request to `/serial.php` directly allows verification of whether:

* The endpoint is active
* It performs any action without authentication
* It returns sensitive data or errors

Unimplemented or hidden functionality frequently contains logic flaws or security issues.

***

### HTTP Requests

**Quick Notes**

* Reproduce an empty POST request to `/serial.php`
* Use `curl` for GET and POST requests
* Reduce output noise with `-s`
* Include POST body parameters with `-d`

#### Using cURL for Web Requests

`curl` is a command-line utility available on Linux, macOS, and modern Windows environments. Providing a URL returns the server response as plain text, which is useful for inspecting HTML or endpoint behavior.

```bash
user@examplehost:~$ curl http://SERVER_IP:PORT/
```

The response should match the same HTML content previously observed when reviewing the page source.

#### Sending a POST Request

To explicitly send a POST request, specify the request method with `-X POST`. The `-s` flag suppresses progress and status output to keep the response clean.

```bash
user@examplehost:~$ curl -s http://SERVER_IP:PORT/ -X POST
```

> **Tip:** Use `-s` to avoid cluttering the output with transfer statistics.

#### Sending POST Data

POST requests commonly include body data. The `-d` flag is used to include parameters in the request body.

```bash
user@examplehost:~$ curl -s http://SERVER_IP:PORT/ -X POST -d "param1=sample"
```

Multiple parameters can be included by separating them with `&` or by repeating the `-d` flag.

***

### Decoding

**Quick Notes**

* Encoded output returned from server-side logic
* Common encodings used in obfuscated code
* Base64, hex, and rot13 identification and decoding
* Manual and automated decoding approaches

#### Encoded Server Response

After issuing a POST request to `/serial.php`, the server returns an encoded string:

```bash
user@examplehost:~$ curl http://SERVER_IP:PORT/serial.php -X POST -d "param1=sample"
```

```
ZG8gdGhlIGV4ZXJjaXNlLCBkb24ndCBjb3B5IGFuZCBwYXN0ZSA7KQo=
```

Encoded data is frequently used in obfuscated workflows to hide meaningful output until runtime. Scripts often decode such values dynamically before using them.

#### Common Encoding Techniques

The following encodings are frequently encountered during JavaScript deobfuscation.

**Base64**

Base64 represents data using:

* Uppercase and lowercase letters
* Numbers
* `+` and `/`
* Optional `=` padding

The encoded length is always a multiple of 4 characters, with `=` used as padding when required.

**Base64 Encode**

```bash
user@examplehost:~$ echo https://example.com/ | base64
```

```
aHR0cHM6Ly9leGFtcGxlLmNvbS8K
```

**Base64 Decode**

```bash
user@examplehost:~$ echo aHR0cHM6Ly9leGFtcGxlLmNvbS8K | base64 -d
```

```
https://example.com/
```

**Hex Encoding**

Hex encoding converts each character to its hexadecimal ASCII value.

**Spotting Hex**

* Only characters `0-9` and `a-f`
* Even-length strings

**Hex Encode**

```bash
user@examplehost:~$ echo https://example.com/ | xxd -p
```

```
68747470733a2f2f6578616d706c652e636f6d2f0a
```

**Hex Decode**

```bash
user@examplehost:~$ echo 68747470733a2f2f6578616d706c652e636f6d2f0a | xxd -p -r
```

```
https://example.com/
```

**Caesar Cipher / Rot13**

A Caesar cipher shifts characters by a fixed number. The most common variant is rot13, which shifts letters by 13 positions.

**Spotting Rot13**

* Output appears scrambled but retains recognizable structure
* Character-to-character substitution is consistent

**Rot13 Encode**

```bash
user@examplehost:~$ echo https://example.com/ | tr 'A-Za-z' 'N-ZA-Mn-za-m'
```

```
uggcf://rknzcyr.pbz/
```

**Rot13 Decode**

```bash
user@examplehost:~$ echo uggcf://rknzcyr.pbz/ | tr 'A-Za-z' 'N-ZA-Mn-za-m'
```

```
https://example.com/
```

#### Identifying Unknown Encodings

Not all encoded data uses common formats. When the encoding is unclear:

* Examine the character set and length
* Look for padding or structural patterns
* Use automated identifier tools to guess the encoding type

Some tools can analyze encoded strings and suggest likely encodings automatically.

#### Encoding vs Encryption

Encoding is reversible without a key. Encryption requires a key to recover the original data.

Obfuscation tools may use encryption instead of encoding. If the decryption key is not present in the client-side code, reversing the logic becomes significantly more difficult.

***
