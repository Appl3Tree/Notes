# Module 3: Using Web Proxies

## Getting Started

### Intro to Web Proxies

***

#### What Are Web Proxies?

Web proxies are tools placed between a browser or mobile application and a back-end server to capture and inspect web requests. They act as man-in-the-middle (MITM) tools, focusing mainly on web traffic over HTTP (80) and HTTPS (443). Unlike network sniffers such as Wireshark, which analyze all traffic, web proxies provide direct insight into web-specific requests and responses.

They allow testers to:

* View all HTTP requests and server responses.
* Intercept and modify specific requests to test server handling.
* Simplify the process of capturing and replaying requests compared to older CLI-based methods.

Web proxies are considered essential for web penetration testing.

#### Uses of Web Proxies

Beyond capturing and replaying HTTP requests, web proxies support:

* Web application vulnerability scanning
* Web fuzzing
* Web crawling
* Web application mapping
* Web request analysis
* Web configuration testing
* Code reviews

This module focuses on learning how to use web proxies and their features, not on specific web attacks. The two most common tools are Burp Suite and OWASP Zed Attack Proxy (ZAP).

#### Burp Suite

Burp Suite (commonly pronounced “Burp Sweet”) is the most widely used web proxy for penetration testing. It features a strong user interface and an integrated Chromium browser.

* **Free (Community) Version**: Powerful enough for most testers.
* **Paid Versions (Pro/Enterprise)**: Include advanced features like:
  * Active web application scanner
  * Faster Burp Intruder
  * Ability to load specific Burp Extensions

{% hint style="success" %}
Tip: Educational or business email addresses can often qualify for a free Burp Pro trial.
{% endhint %}

#### OWASP Zed Attack Proxy (ZAP)

ZAP is a free, open-source web proxy maintained by the [Open Web Application Security Project (OWASP)](https://owasp.org/). Unlike Burp, it has no paid features or limitations.

Strengths include:

* No throttling or restrictions in scans.
* Growing community contributions adding advanced capabilities.
* Many Burp Pro-like features available for free.

In practice:

* ZAP is ideal for testers seeking a fully free solution.
* Burp Pro is often chosen in corporate or advanced test settings for its maturity and commercial support.
* Learning both provides flexibility to adapt to different pentesting needs.

***

### Setting Up

#### Burp Suite

Burp Suite is available for Windows, Linux, and macOS. If not pre-installed, download it from the official Burp download page and follow the platform-specific installer instructions.

* **Launching Burp**
  *   From terminal:

      ```bash
      analyst1@AcmeCorp:~$ burpsuite
      ```
  * From the application menu.
  *   Using the JAR file (requires Java Runtime Environment):

      ```bash
      analyst1@AcmeCorp:~$ java -jar </path/to/burpsuite.jar>
      ```

Note: Burp and ZAP both require Java, usually bundled in the installers. If missing, install separately.

* **Startup Options**
  * **Community Edition**: Only temporary projects are available (no saving progress).
  * **Pro/Enterprise**: Options include temporary project, new project on disk, or open existing project.
* **Configuration**
  * Choose **Burp Defaults** for standard settings.
  * Advanced users can later load custom configuration files.

After setup, Burp is ready for use.

#### ZAP

Download ZAP from its official download page and install the version for your operating system.

* **Launching ZAP**
  *   From terminal:

      ```bash
      analyst1@AcmeCorp:~$ zaproxy
      ```
  *   Using the JAR file (requires Java Runtime Environment):

      ```bash
      analyst1@AcmeCorp:~$ java -jar </path/to/zap.jar>
      ```
  * From the application menu.
* **Startup Options**
  * Prompted to create a persistent session or use a temporary one.
  * For short tasks, choose **no persistence**.

Once started, ZAP is ready for proxy configuration.

{% hint style="success" %}
* **Burp Dark Theme**: `User Options > Display > Theme > dark`
* **ZAP Dark Theme**: `Tools > Options > Display > Look and Feel > Flat Dark`
{% endhint %}

***

## Web Proxy

### Proxy Setup

***

#### Pre-Configured Browser

Both Burp and ZAP include pre-configured browsers with built-in proxy settings and pre-installed CA certificates, making them quick to use for penetration testing.

* **Burp**: In **Proxy > Intercept**, select **Open Browser** to launch Burp’s embedded browser, which automatically routes all traffic through Burp.
* **ZAP**: Click the Firefox browser icon in the top bar to launch a pre-configured browser session through ZAP.

For most uses, these pre-configured browsers are sufficient.

#### Proxy Setup in Real Browsers

For real browsers such as Firefox, manual proxy configuration is required.

* Default proxy port: **8080** (can be changed if in use).
* Burp: Change listening port under **Proxy > Options**.
* ZAP: Change listening port under **Tools > Options > Local Proxies**.

In Firefox, navigate to preferences and configure the proxy to use `127.0.0.1:8080`.

**FoxyProxy**

Instead of switching proxies manually, FoxyProxy can manage proxy settings:

* Pre-installed on PwnBox; can also be installed from the Firefox Extensions page.
* Configure by adding `127.0.0.1` as IP, `8080` as port, and name it Burp or ZAP.
* Once added, select the Burp/ZAP profile from the FoxyProxy menu to activate.

#### Installing CA Certificates

To properly handle HTTPS traffic, the proxy’s CA certificate must be installed in Firefox.

* **Burp**:
  * With Burp selected as proxy, browse to `http://burp`.
  * Click **CA Certificate** to download.
* **ZAP**:
  * Navigate to **Tools > Options > Dynamic SSL Certificate**.
  * Click **Save** to export the current certificate or **Generate** to create a new one.
* **Firefox Certificate Installation**:
  * Go to `about:preferences#privacy`.
  * Scroll to **Certificates** and click **View Certificates**.
  * Open the **Authorities** tab → **Import** → select downloaded CA certificate.
  * Check **Trust this CA to identify websites** and **Trust this CA to identify email users**, then click **OK**.

Once the certificate is installed and the proxy configured, all Firefox traffic will be routed through the web proxy for interception and analysis.

***

### Intercepting Web Requests

#### Intercepting Requests

**Burp**

In **Proxy > Intercept**, request interception is on by default. The **Intercept is on/off** button toggles interception.

* Start the pre-configured browser and visit the target site.
* Intercepted requests appear in Burp and will wait until acted upon.
* Use **Forward** to send the request.
* If unrelated requests appear (e.g., browser background traffic), continue forwarding until the target request is shown.

**ZAP**

In ZAP, interception is **off by default**.

* Toggle interception:
  * Click the green button in the top bar.
  * Or press **CTRL+B**.
* Start the pre-configured browser and revisit the target page.
* The intercepted request appears in the top-right pane.
* Use **Step** (next to the red break button) to forward the request.

ZAP also includes a **Heads Up Display (HUD)** inside the pre-configured browser:

* Enable HUD from the top menu bar.
* Use the left-pane buttons to toggle request interception.
* When a request is intercepted, HUD provides **Step**, **Continue**, or **Drop** options:
  * **Step**: Forward one request at a time to observe responses.
  * **Continue**: Forward all remaining requests after the selected one.

{% hint style="success" %}
Tip: The first time HUD is used, ZAP displays a tutorial that explains its features. It can be replayed later from the bottom-right configuration menu.
{% endhint %}

***

#### Manipulating Intercepted Requests

When a request is intercepted, it is paused until forwarded. During this pause, the request can be edited before being sent. This enables testing how back-end servers handle unexpected or malicious inputs.

Common vulnerabilities tested this way include:

* SQL injection
* Command injection
* Upload bypass
* Authentication bypass
* Cross-site scripting (XSS)
* XML external entity injection (XXE)
* Error handling flaws
* Deserialization issues

**Example**

Intercepting a simple request:

```http
POST /ping HTTP/1.1
Host: demo.AcmeCorp.local:30820
Content-Length: 4
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://demo.AcmeCorp.local:30820
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://demo.AcmeCorp.local:30820/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

ip=1
```

Normally, the web form only allows numeric values for the `ip` parameter due to front-end validation. However, intercepting the request allows bypassing these restrictions.

Modify the request:

```http
ip=;ls;
```

Forward the modified request. If the back-end server does not validate inputs, it may execute the injected command.

Response:

```
report.txt
dashboard.html
lib
package.json
static
app.js
```

This shows that the request was successfully manipulated, demonstrating how interception can reveal critical vulnerabilities.

***

### Intercepting Responses

In some cases, intercepting **HTTP responses** before they reach the browser helps modify page behavior (e.g., enabling disabled inputs or revealing hidden fields) to support penetration testing tasks. With response interception, client-side restrictions can be bypassed without changing server-side logic.

#### Burp

Enable response interception: **Proxy > Options > Intercept server responses** (check **Intercept Response**). Optionally enable automatic **Update Content-Length**.

Workflow:

1. Turn **request interception on** (Proxy > Intercept).
2. In the browser, hard-refresh the page (**CTRL+SHIFT+R**) to fetch a fresh copy.
3. In Burp, **Forward** the intercepted request; the **response** will then be intercepted for editing.
4. Edit HTML to relax input constraints, then **Forward**.

Example: change a numeric-only IP field into a free-text field and extend its length limit:

```html
<input type="text" id="ip" name="ip" maxlength="100"
    oninput="javascript: if (this.value.length > this.maxLength) this.value = this.value.slice(0, this.maxLength);"
    required>
```

{% hint style="success" %}
Tip: Burp can auto-modify responses without manual interception via **Proxy > Options > Response modification** (e.g., **Unhide hidden form fields**).
{% endhint %}

#### ZAP

By default, ZAP does not intercept; toggle breaking on responses via the top bar or **CTRL+B**, then **Step** to send the request and automatically intercept the response for editing. Make the same HTML changes as above and **Continue** to render the modified page.

**HUD shortcuts** (ZAP’s in-browser overlay):

* **Show/Enable (light bulb icon)**: reveals hidden fields and enables disabled inputs without intercepting or refreshing.
* **Comments**: add from the left-pane (+ → **Comments**) to highlight inline HTML comments on the page.

Result: the page renders with editable inputs, enabling payload entry directly in the browser without resending crafted requests. This reduces friction when testing client-side restrictions. Next, you will automate these response changes so they apply consistently without repeated manual edits.

***

### Automatic Modification

#### Automatic Request Modification

Web proxies can automatically apply modifications to all outgoing HTTP requests using configurable rules. For example, changing the **User-Agent** string can help bypass filters that block specific clients.

**Burp Match and Replace**

1. Go to **Proxy > Options > Match and Replace**.
2. Click **Add**, then configure:
   * **Type**: Request header
   * **Match**: `^User-Agent.*$`
   * **Replace**: `User-Agent: AcmeCorp Agent 1.0`
   * **Regex match**: True

Burp will now automatically replace any `User-Agent` header with the custom value.

Example intercepted request after replacement:

```http
GET / HTTP/1.1
Host: demo.AcmeCorp.local
User-Agent: AcmeCorp Agent 1.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9
...
```

**ZAP Replacer**

Access via **CTRL+R** or **Options > Replacer**. Add a new rule:

* **Description**: Custom User-Agent
* **Match Type**: Request Header (add if missing)
* **Match String**: User-Agent
* **Replacement String**: AcmeCorp Agent 1.0
* **Enable**: True

ZAP also allows specifying **Initiators** (where the rule applies). Leave default (**all HTTP(S) messages**) to apply globally.

After enabling interception (**CTRL+B**) and visiting a page, the User-Agent header is automatically replaced.

***

#### Automatic Response Modification

Automatic response modification ensures changes persist without manual interception each time a page refreshes.

**Burp Match and Replace**

1. Go to **Proxy > Options > Match and Replace**.
2. Add a new rule:
   * **Type**: Response body
   * **Match**: `type="number"`
   * **Replace**: `type="text"`
   * **Regex match**: False
3. Add another rule:
   * **Match**: `maxlength="3"`
   * **Replace**: `maxlength="100"`

Now, refreshing the page (**CTRL+SHIFT+R**) automatically enables any characters in the IP field and allows longer input values.

Modified form snippet automatically applied:

```html
<input type="text" id="ip" name="ip" maxlength="100"
    oninput="javascript: if (this.value.length > this.maxLength) this.value = this.value.slice(0, this.maxLength);"
    required>
```

This persists across refreshes and allows command injection testing without re-editing each response.

**ZAP Replacer**

The same response modification rules can be applied using ZAP’s **Replacer** with **Match Type: Response Body**.

***

### Repeating Requests

#### Proxy History

Request repeating avoids the overhead of manually intercepting, editing, and forwarding each request. Instead, previously sent requests can be quickly resent, modified, and replayed directly from within the proxy tool.

* **Burp**: History is available under **Proxy > HTTP History**, showing methods, URLs, status codes, MIME types, and server IPs.
* **ZAP**: History is visible in the bottom **History** tab or HUD’s History pane.

Both tools allow filtering and sorting, which is useful when large volumes of requests must be analyzed. Each also tracks **WebSockets history**, showing asynchronous connections initiated by the application.

* **Burp**: Provides both the **Original Request** and the **Edited Request** for comparison.
* **ZAP**: Shows only the final request that was sent.

Clicking a request displays its full request and response for closer inspection.

***

#### Repeating Requests in Burp

1. Locate the desired request in HTTP History.
2. Press **CTRL+R** to send it to the **Repeater** tab.
   * Use **CTRL+SHIFT+R** to open Repeater directly.
3. Inside Repeater, edit the request as needed, then click **Send**.

{% hint style="success" %}
Tip: Right-click the request and select **Change Request Method** to toggle between `GET` and `POST` without rewriting.
{% endhint %}

Example:

```http
POST /ping HTTP/1.1
Host: demo.AcmeCorp.local
User-Agent: AcmeCorp Agent 1.0
Content-Type: application/x-www-form-urlencoded
Content-Length: 8

ip=;whoami;
```

Response:

```
webuser
```

***

#### Repeating Requests in ZAP

1. Locate the request in the History tab.
2. Right-click → **Open/Resend with Request Editor**.
3. Modify request data, then click **Send** to execute.
   * The Method drop-down allows quick switching between HTTP verbs.

The Request/Response panels can be rearranged (tabs, side-by-side, stacked) for convenience.

***

#### Repeating Requests in ZAP HUD

Within the pre-configured browser:

1. Locate the request in the bottom History pane.
2. The Request Editor window opens with options:
   * **Replay in Console**: show response inside HUD.
   * **Replay in Browser**: render the response in the browser window.

Like Burp Repeater, all requests are editable before resending.

***

#### Key Benefit

Request repeating streamlines testing:

* Rapidly test variations of the same injection.
* Enumerate commands or payloads without re-intercepting.
* Switch methods or parameters efficiently.

This capability is essential when requests contain **URL-encoded data**, which will be the focus of the next section.

***

### Encoding/Decoding

#### URL Encoding

When sending custom HTTP requests, request data must be **URL-encoded** to avoid server errors. Certain characters require encoding:

* **Spaces** → otherwise terminate request data
* **&** → otherwise treated as a parameter delimiter
* **#** → otherwise treated as a fragment identifier
* **Burp**: In Repeater, select text → right-click → **Convert Selection > URL > URL encode key characters**, or press **CTRL+U**. Burp can also encode automatically while typing if enabled.
* **ZAP**: Automatically URL-encodes request data before sending, even if not shown explicitly.

Variants like full URL encoding and Unicode URL encoding may be required for special cases.

***

#### Decoding

Web applications often encode data, requiring decoding to analyze original values. Similarly, servers may expect data encoded in a specific format before accepting it.

Both Burp and ZAP support:

* HTML
* Unicode
* Base64
* ASCII hex

**Burp**

* Use the **Decoder** tab to encode/decode text.
* Example: decoding a Base64 cookie.

Encoded string:

```
eyJ1c2VybmFtZSI6Imd1ZXN0IiwgImlzX2FkbWluIjpmYWxzZX0=
```

Decoded:

```json
{"username":"guest","is_admin":false}
```

Recent versions also include **Burp Inspector**, available in Proxy or Repeater, to handle inline encoding/decoding automatically.

**ZAP**

* Use **Encoder/Decoder/Hash** (**CTRL+E**) to test multiple encoders/decoders.
* The Decode tab automatically applies decoding methods to the input string.
* Custom tabs can be created to group specific encoders/decoders for faster workflow.

***

#### Encoding

After decoding, testers may modify values and re-encode them.

Example: modifying the decoded JSON to escalate privileges.

```json
{"username":"admin","is_admin":true}
```

Re-encode as Base64:

```
eyJ1c2VybmFtZSI6ImFkbWluIiwgImlzX2FkbWluIjp0cnVlfQ==
```

This new encoded string can then be inserted into requests using Burp Repeater or ZAP Request Editor.

{% hint style="success" %}
Tip: In Burp, outputs can be directly re-encoded by selecting a different encoder in the output pane. In ZAP, copy the modified value into the input field and apply the encoder again.
{% endhint %}

***

### Proxying Tools

#### Overview

Web proxies can also intercept and analyze requests from **command-line tools** and **thick client applications**, not just browsers. By routing these tools’ traffic through a proxy (e.g., `http://127.0.0.1:8080`), testers gain visibility into requests and can apply the same modifications as with web applications.

{% hint style="danger" %}
Proxying tools can slow them down, so enable proxying only when needed for inspection.
{% endhint %}

***

#### Proxychains

[Proxychains](http://proxychains.sourceforge.net/) forces any command-line tool to route traffic through a specified proxy.

1. Edit `/etc/proxychains.conf`:
   * Comment out the last line.
   *   Add:

       ```ini
       #socks4         127.0.0.1 9050
       http 127.0.0.1 8080
       ```
   * Uncomment `quiet_mode` to reduce noise.
2. Prepend `proxychains` to any command. Example with **cURL**:

```bash
analyst1@AcmeCorp:~$ proxychains curl http://demo.AcmeCorp.local:3080
ProxyChains-3.1 (http://proxychains.sf.net)
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Ping IP</title>
</head>
...SNIP...
</html>
```

Burp/ZAP will show the proxied request in HTTP history.

***

#### Nmap

Nmap supports experimental proxying with the `--proxies` flag. For example:

```bash
analyst1@AcmeCorp:~$ nmap --proxies http://127.0.0.1:8080 demo.AcmeCorp.local -p3080 -Pn -sC
Starting Nmap 7.91 ( https://nmap.org )
Nmap scan report for demo.AcmeCorp.local
Host is up (0.11s latency).

PORT     STATE SERVICE
3080/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 0.49 seconds
```

All requests appear in the proxy tool’s history.

{% hint style="danger" %}
Nmap’s proxying is marked experimental; if unreliable, use Proxychains instead.
{% endhint %}

***

#### Metasploit

Metasploit modules can also be routed through a proxy for debugging and inspection.

1.  Launch Metasploit:

    ```bash
    analyst1@AcmeCorp:~$ msfconsole
    ```
2. Configure proxy in a module using the `PROXIES` option:

```none
msf6 > use auxiliary/scanner/http/robots_txt
msf6 auxiliary(scanner/http/robots_txt) > set PROXIES HTTP:127.0.0.1:8080
PROXIES => HTTP:127.0.0.1:8080

msf6 auxiliary(scanner/http/robots_txt) > set RHOST demo.AcmeCorp.local
RHOST => demo.AcmeCorp.local

msf6 auxiliary(scanner/http/robots_txt) > set RPORT 3080
RPORT => 3080

msf6 auxiliary(scanner/http/robots_txt) > run
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

The request to `/robots.txt` is then visible in Burp or ZAP.

***

#### Summary

* **Proxychains**: universal method for CLI tools.
* **Nmap**: has built-in `--proxies` flag (experimental).
* **Metasploit**: configure via `PROXIES` option.

The same concept applies to other tools, scripts, and thick clients: configure them to use the web proxy, and all requests become visible and modifiable for penetration testing.

***

## Web Fuzzer

### Burp Intruder

#### Overview

Burp Intruder is Burp Suite’s built-in **web fuzzer**, useful for fuzzing pages, directories, parameters, and brute-forcing values. While more advanced than most CLI-based fuzzers, the **Community Edition** is throttled at 1 request/second, making it practical only for short queries. The **Pro version** removes this limit and includes additional features, making Intruder competitive with tools like `ffuf`, `gobuster`, or `wfuzz`.

***

#### Target

1. Start Burp and its pre-configured browser.
2. Visit the target web application.
3. Locate the request in **Proxy > HTTP History**.
4. Right-click → **Send to Intruder** (or press **CTRL+I**).
5. Open the **Intruder** tab (or press **CTRL+SHIFT+I**).

The **Target** tab displays host and port details from the request.

***

#### Positions

In the **Positions** tab, select the location where payloads will be inserted.

*   Example: fuzzing directories.

    ```http
    GET /DIRECTORY/ HTTP/1.1
    ```
* Highlight `DIRECTORY` → click **Add §**.
* The attack type determines payload usage. For simplicity, use **Sniper** (one position, one payload).

{% hint style="success" %}
Tip: leave two blank lines at the end of the request to avoid server errors.
{% endhint %}

***

#### Payloads

The **Payloads** tab configures wordlists and payload behavior.

**Payload Sets**

* For a single Sniper position, choose **Payload Set 1**.
* **Payload Types** examples:
  * _Simple List_: use a wordlist.
  * _Runtime File_: loads line-by-line for large lists.
  * _Character Substitution_: permutes characters based on substitution rules.

**Payload Options**

* For **Simple List**, load a wordlist (e.g., `/opt/useful/seclists/Discovery/Web-Content/common.txt`).
* Items can be manually added, loaded from files, or combined.
* Burp Pro includes built-in wordlists.

**Payload Processing**

Rules can modify payloads during fuzzing.

* Example: skip lines beginning with a period (`.`).
  * Rule: **Skip if matches regex** → `^\..*$`

**Payload Encoding**

Controls URL-encoding of characters such as `./^=<>&+?:;'{}|^`.

* Leave enabled for most attacks.

***

#### Options

Additional configuration is available under **Options**.

* **Retries on failure**: can be set to 0.
* **Grep - Match**: flag responses matching patterns (e.g., `200 OK`).
* **Grep - Extract**: highlight specific portions of responses.
* **Resource Pool**: manage network resources for large scans.

For directory fuzzing, enable **Grep - Match**, clear defaults, add `200 OK`, and disable **Exclude HTTP Headers**.

***

#### Attack

Click **Start Attack**.

* In Community Edition, requests are throttled.
* Payloads matching the skip regex (`^\..*$`) are ignored.
* Results can be sorted by **Status**, **Length**, or **200 OK** matches.

Example output:

```
Payload     Status   Length   Match
-----------------------------------
admin       200      244      ✓
about       404      458
help        404      458
```

The hit `/admin` can then be visited in the browser:

```
http://demo.AcmeCorp.local:3080/admin/
```

***

#### Use Cases

Burp Intruder can perform:

* Directory and file fuzzing.
* Parameter fuzzing.
* Password brute-forcing and spraying.
* Testing authentication portals (e.g., Outlook Web Access, SSL VPNs, Citrix, custom AD-backed apps).

{% hint style="danger" %}
The free edition is too slow for large-scale attacks, but the Pro version unlocks its full power.
{% endhint %}

***

### ZAP Fuzzer

#### Overview

ZAP includes a built-in **Fuzzer** that can perform directory brute-forcing, parameter fuzzing, and other enumeration tasks. Unlike Burp Intruder Community Edition, ZAP Fuzzer is **not throttled**, making it faster and more practical for larger fuzzing tasks. Although it lacks some of Burp Intruder’s advanced payload features, it offers built-in wordlists and a flexible processor system.

***

#### Fuzz

1. Visit the target URL with the pre-configured browser.\
   Example: `http://demo.AcmeCorp.local:3080/test/`
2. Locate the request in Proxy History.
3. Right-click → **Attack > Fuzz**.

This opens the **Fuzzer window**, showing the captured HTTP request and allowing configuration.

***

#### Locations

* Select the text to fuzz (e.g., `test`) and click **Add**.
* The selected word becomes a **Fuzz Location**, marked in green.
* Each payload will be substituted into this location during the attack.

***

#### Payloads

Payloads in ZAP Fuzzer are similar to Burp’s but less extensive. Types include:

* **File**: load a custom wordlist.
* **File Fuzzers**: built-in wordlists from ZAP’s database (e.g., _dirbuster_ lists).
* **Numberzz**: generate numeric sequences.

Example:

* Select **File Fuzzers** → `dirbuster/directory-list-1.0.txt`.
* Preview displays entries such as `cgi-bin`, `.git`, `.svn`.

***

#### Processors

Processors modify payloads before sending them. Examples include:

* Base64 Encode/Decode
* URL Encode/Decode
* Hashing (MD5, SHA-1/256/512)
* Prefix/Postfix String
* Script (custom logic)

For directory fuzzing, add **URL Encode** to avoid errors with special characters. Use **Generate Preview** to confirm payload output.

***

#### Options

The **Options** tab allows tuning performance:

* **Concurrent threads per scan**: e.g., 20 for faster fuzzing.
* **Retries on I/O error**: default 3.
* **Depth First** vs. **Breadth First** strategies.
* **Follow Redirects**: toggle depending on the attack type.

Example: using **Depth First** ensures all payloads are tested in one location before moving to the next.

***

#### Start

Click **Start Fuzzer** to launch the attack. Results are displayed in a sortable table.

Example results:

```
ID    Code   Reason   Time   Size   Payload
908   200    OK       109ms  246B   skills
909   404    Not Found  95ms  458B   admin
```

* **Code**: HTTP response code (200 indicates success).
* **Payload**: the tested value.
* **Size Resp. Body**: useful for identifying different responses.
* **RTT (Round Trip Time)**: helpful for timing-based attacks.

Click a result to view full request/response details.\
Example hit: `/skills/` → HTTP 200 OK with HTML body showing a “Welcome” page.

***

#### Summary

* ZAP Fuzzer is **fast** and supports **built-in wordlists** via File Fuzzers.
* Lacks some of Burp Intruder’s advanced attack modes but makes up for it with free, unlimited fuzzing.
* Results can be filtered by **status code**, **response size**, or **timing behavior** to detect hidden or vulnerable endpoints.

***

## Web Scanner

### Burp Scanner

#### Overview

Burp Scanner is Burp Suite’s built-in vulnerability scanner. It includes a **Crawler** to map application structure and a **Scanner** for passive and active vulnerability analysis.

{% hint style="danger" %}
This is a **Pro-only feature**; it is not available in the free Community Edition.
{% endhint %}

***

#### Target Scope

Scans can be initiated in multiple ways:

* From a specific request in **Proxy History** → right-click → **Scan** (or **Passive/Active Scan**).
* From the **Dashboard** via **New Scan**.
* By running scans only on items included in **Target Scope**.

The **Scope** defines what URLs are included/excluded:

* **Add to scope**: right-click on site map entries.
* **Remove from scope**: exclude items like logout functions.
* **Advanced scope control**: specify include/exclude regex patterns.

Once defined, Burp can be limited to in-scope items to reduce noise and resource usage.

***

#### Crawler

The Crawler maps site structure by following links, forms, and requests.

* Start via **Dashboard > New Scan**.
* Choose **Crawl** (mapping only) or **Crawl and Audit** (mapping plus scanning).
* Use built-in configurations (e.g., _Crawl strategy – fastest_) or create custom ones.
* Optional: configure login sequences or credentials to cover authenticated areas.

Crawl results appear in the **Site map**, showing discovered directories, files, and pages.

***

#### Passive Scanner

A **Passive Scan** analyzes captured responses without sending new requests.

* Start from Proxy History or Site map → right-click → **Do passive scan**.
* Issues are listed in the **Dashboard > Issue activity** pane.
* Findings include missing security headers, DOM-based XSS indicators, or insecure cookies.
* Each issue is assigned a **Severity** (High, Medium, Low, Information) and a **Confidence** level (Certain, Firm, Tentative).

This provides a quick way to surface potential issues with minimal impact on the target.

***

#### Active Scanner

An **Active Scan** is more aggressive and thorough:

* Performs a Crawl plus directory discovery.
* Runs Passive Scan on all pages.
* Sends crafted requests to confirm vulnerabilities found during passive analysis.
* Tests insertion points for common vulnerabilities (XSS, SQLi, OS command injection, etc.).
* Performs JavaScript analysis for DOM-based issues.

Configuration:

* Start from a request or scope with **Do active scan** or **Dashboard > New Scan**.
* Choose from presets (e.g., _Audit checks – critical issues only_) or define custom audit rules.
* Optionally add login details to test authenticated functionality.

Example finding: **OS command injection** on an `ip` parameter, rated **High severity, Firm confidence**.

***

#### Reporting

Burp Scanner can generate detailed reports:

* From **Target > Site map** → right-click → **Report issues for this host**.
* Choose export format (HTML, XML) and severity/confidence filters.
* Reports include:
  * Issue summary by severity/confidence
  * Proof-of-concept requests/responses
  * Exploitation details
  * Remediation guidance

{% hint style="danger" %}
Reports from tools should never be delivered as final client reports without validation. Instead, they should be used as **supplementary or appendix data** in professional penetration test reports.
{% endhint %}

***

### ZAP Scanner

#### Overview

ZAP includes a **Web Scanner** that combines:

* **Spider** (site discovery)
* **Passive Scanner** (response analysis)
* **Active Scanner** (vulnerability testing)

This mirrors Burp Scanner’s functionality but is fully free and open-source.

***

#### Spider

The **Spider** crawls websites to discover links, forms, and endpoints.

* Start from **History tab** → right-click request → **Attack > Spider**.
* Or use the **HUD** in the pre-configured browser → click the **Spider Start** button.
* If the site is not in scope, ZAP will prompt to add it.

Progress is shown in the **Spider tab** and discovered URLs appear under the **Sites tree**.

{% hint style="info" %}
Tip: ZAP also provides an **Ajax Spider**, which detects links loaded dynamically via JavaScript/AJAX. Running it after the normal Spider often reveals additional content.
{% endhint %}

***

#### Passive Scanner

While the Spider runs, ZAP automatically performs passive analysis on responses.

* Identifies missing headers, DOM-based XSS, insecure cookies, etc.
* Alerts are displayed:
  * Left pane → alerts for the current page.
  * Right pane → overall alerts for the site.
* The **Alerts tab** shows details, affected pages, severity, and confidence levels.

Example: **X-Frame-Options header not set** flagged with _Medium severity_ across multiple pages.

***

#### Active Scanner

The **Active Scanner** launches targeted attacks against discovered endpoints.

* Start via **Active Scan** button in the HUD or from the main UI.
* If no Spider scan exists, ZAP will run one first.
* Progress and requests are shown in real time.

The Active Scanner tests for common vulnerabilities, such as:

* XSS
* SQL injection
* Command injection
* Path traversal
* Misconfigured headers

Example finding:

* **High severity**: Remote OS Command Injection
* Payload: `127.0.0.1&cat /etc/passwd&`
* Evidence: system file contents in the response

Details include the vulnerable URL, request/response data, and example payloads.

***

#### Reporting

ZAP generates exportable reports:

* **Report > Generate HTML Report** (also available in XML or Markdown).
* Reports summarize findings by severity and confidence.

Example summary:

* 1 High
* 3 Medium
* 8 Low
* 6 Informational

Reports provide exploit evidence, remediation advice, and a structured list of vulnerabilities for tracking or sharing.

***

#### Summary

* **Spider**: maps site structure (with Ajax Spider for JavaScript-heavy apps).
* **Passive Scanner**: highlights potential issues without sending extra requests.
* **Active Scanner**: performs full vulnerability testing.
* **Reporting**: exports detailed, organized findings in multiple formats.

ZAP Scanner, while not as feature-rich as Burp Pro, provides a **free, unlimited, and effective alternative** for web vulnerability scanning.

***

### Extensions

#### Burp BApp Store

Burp’s extensibility is handled through the **Extender** tab and its built-in **BApp Store**, where community-created extensions can be installed.

* Extensions provide added functionality such as request manipulation, code beautification, scanning enhancements, or encoding/decoding utilities.
* Some are **Pro-only**, but most are free to use with the Community Edition.
* Certain extensions require external dependencies (e.g., `Jython`).

Example: **Decoder Improved**

* Installed via the BApp Store.
* Adds a new tab with advanced encoding, hashing, and decoding features beyond the built-in Decoder.
* Supports options such as hashing with MD5, Unicode handling, and a hex editor.

Other useful Burp extensions include:

* **.NET Beautifier**
* **J2EEScan**
* **Software Vulnerability Scanner**
* **Active Scan++**
* **Additional Scanner Checks**
* **AWS Security Checks**
* **Backslash Powered Scanner**
* **Wsdler**
* **Java Deserialization Scanner**
* **Autorize**
* **CSRF Scanner**
* **JS Link Finder**
* **Retire.JS**
* **CSP Auditor**

These extensions expand Burp’s effectiveness for both general and specialized penetration testing workflows.

***

#### ZAP Marketplace

ZAP provides extensibility through its **Marketplace**, accessible from the **Manage Add-ons** menu.

* Add-ons are categorized by stability: **Release**, **Beta**, or **Alpha**.
* Extensions include scanners, scripts, fuzzing payloads, and integrations.

Example: **FuzzDB Files** and **FuzzDB Offensive**

* Adds a large library of wordlists and payloads for fuzzing.
* Example payload set: _fuzzdb > attack > os-cmd-execution > command\_execution-unix.txt_.
* Useful for command injection testing and bypassing WAFs.

When used in the ZAP Fuzzer, payloads like `;id` or `/usr/bin/id` can automatically be tried, revealing exploitable inputs.

***

#### Closing Thoughts

Both **Burp Suite** and **ZAP** are indispensable tools for web application penetration testing:

* **Burp Suite**: polished interface, enterprise-ready features, and powerful extensions—though advanced capabilities (Intruder speed, Scanner) require the Pro version.
* **ZAP**: fully free and open-source, with strong community support and an expanding Marketplace of add-ons.

Together, these tools complement core penetration testing utilities like **Nmap**, **Wireshark**, **tcpdump**, **sqlmap**, **ffuf**, **Gobuster**, and **Hashcat**, making them must-have components of any offensive security toolkit.

***
