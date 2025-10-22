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



## Deobfuscation Examples

