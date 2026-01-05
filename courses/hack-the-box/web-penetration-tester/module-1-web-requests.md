# Module 1: Web Requests

## HTTP Fundamentals

### HyperText Transfer Protocol (HTTP)

#### Overview

* **Definition**: HTTP (HyperText Transfer Protocol) is an application-layer protocol for requesting and transferring resources over the web.
* **Purpose**: Enables communication between a **client** (e.g., browser) and a **server**.
* **Default Port**:
  * `80` for HTTP
  * `443` for HTTPS (secure)
* **Process**:
  1. Client sends a request for a resource.
  2. Server processes the request and responds with the requested data.
* **Example**: Visiting `https://www.example.com` sends an HTTP request to fetch the site’s content.

***

#### URL Structure

A URL specifies how to access resources. It can include several components:

| Component     | Example                 | Description                                                  |
| ------------- | ----------------------- | ------------------------------------------------------------ |
| **Scheme**    | `http://` or `https://` | Protocol used; ends with `://`                               |
| **User Info** | `admin:password@`       | Optional credentials for authentication                      |
| **Host**      | `example.com`           | Domain or IP address of the resource                         |
| **Port**      | `:80`                   | Optional; defaults to `80` (HTTP) or `443` (HTTPS)           |
| **Path**      | `/dashboard.php`        | File or folder location; defaults to `index.html` if omitted |
| **Query**     | `?login=true`           | Parameters for the request, separated by `&`                 |
| **Fragment**  | `#status`               | Client-side reference to a section within the resource       |

**Minimum Required:** Scheme + Host.

***

#### HTTP Request Flow

1. **DNS Resolution**
   * Browser queries DNS to resolve the domain into an IP address.
   * Local `/etc/hosts` is checked first (can be modified manually).
2. **HTTP Request**
   * Client sends a request (usually `GET`) to the server at the resolved IP.
3. **Server Response**
   * Server responds with a status code (e.g., `200 OK`) and the requested resource.
4. **Rendering**
   * Browser interprets the response and displays it to the user.

***

#### cURL Basics

* **What it is**: `cURL` (Client URL) is a command-line tool for sending web requests.
* **Advantages**:
  * Works with multiple protocols (including HTTP/HTTPS).
  * Useful for scripting, automation, and penetration testing.
* **Basic Usage**:\
  `curl example.com`
  * Displays raw HTML (does not render content like a browser).

***

#### Common cURL Options

| Flag               | Purpose                               |
| ------------------ | ------------------------------------- |
| `-O`               | Save output using remote file name    |
| `-o <filename>`    | Save output to a specific file        |
| `-s`               | Silent mode (no progress output)      |
| `-i`               | Include response headers              |
| `-d <data>`        | Send HTTP POST data                   |
| `-u user:password` | Authenticate with credentials         |
| `-A <user-agent>`  | Specify User-Agent header             |
| `-v`               | Verbose mode for detailed output      |
| `-h` or `--help`   | Show help (categories or all options) |

**Examples**:

* Save page as `index.html` (remote filename):\
  `curl -O example.com/index.html`
* Save page as `custom.html` (custom filename):\
  `curl -o custom.html example.com/index.html`
* Silent download:\
  `curl -s -O example.com/index.html`

**Tip**: Use `man curl` or `curl --help all` for complete documentation.

### HyperText Transfer Protocol Secure (HTTPS)

#### Overview

* **Problem with HTTP**:
  * Data sent over HTTP is in **clear-text**.
  * Vulnerable to **Man-in-the-Middle (MITM)** attacks where attackers can intercept and read sensitive information.
* **Solution: HTTPS**
  * Encrypts all communication between client and server.
  * Prevents third parties from easily reading intercepted data.
  * Widely adopted; most browsers block or warn against plain HTTP.
* **Identification**:
  * URLs start with `https://`
  * Browser shows a **lock icon** in the address bar.
* **Important Note**:
  * While HTTPS encrypts data, DNS requests can still reveal visited domains unless using **encrypted DNS** (e.g., `8.8.8.8`, `1.1.1.1`) or a **VPN**.

***

#### HTTP vs HTTPS Example

* **HTTP (Insecure)**: Login credentials are visible in plain text if intercepted.
* **HTTPS (Secure)**: Data appears as encrypted binary; credentials are hidden from interception.

***

#### HTTPS Flow (High-Level)

1. **Initial Request**
   * User may start with `http://` request.
   * Server responds with `HTTP 301 Moved Permanently` redirect to `https://` (port `443`).
2. **TLS Handshake**
   * Client sends **Client Hello** (capabilities & preferences).
   * Server responds with **Server Hello** and sends SSL certificate.
   * Keys are exchanged and verified.
3. **Secure Communication**
   * Encrypted HTTP traffic begins.
   * Same HTTP methods (`GET`, `POST`, etc.) are now secured.

**Note**:\
Modern browsers protect against **HTTP downgrade attacks** (forcing HTTPS to HTTP).

***

#### cURL with HTTPS

* **Automatic Handling**:\
  `cURL` negotiates TLS and encrypts data automatically.
* **Invalid Certificates**:
  * By default, `cURL` refuses connections with invalid or expired SSL certificates.
  * Example error: `curl: (60) SSL certificate problem: Invalid certificate chain`
* **Bypassing Certificate Checks** (Testing Only):\
  Use `curl -k https://example.com` to skip certificate validation.

***

#### Key Points

* HTTPS ensures **confidentiality** and **integrity** of transmitted data.
* Always prefer `https://` for secure communications.
* Avoid disabling certificate checks except in **controlled testing environments**. HTTP Requests and Responses

### HTTP Requests and Responses

#### Overview

HTTP communication is built around a simple request–response model:

* **HTTP Request**: Sent by a client (e.g. browser, `cURL`) to request a resource.
* **HTTP Response**: Sent by the server in reply, containing the requested data or a status message.

The request includes details like:

* The resource being requested (URL, path, parameters)
* Headers (e.g. `User-Agent`, `Host`, `Cookie`)
* Optional request body (e.g. form data)

The server processes the request and returns a response, which includes:

* A status code (e.g. `200 OK`, `404 Not Found`)
* Headers (e.g. `Set-Cookie`, `Content-Type`)
* An optional response body (HTML, JSON, images, etc.)

***

#### HTTP Request Structure

Example HTTP request:

```
GET /users/login.html HTTP/1.1
Host: inlanefreight.com
User-Agent: Mozilla/5.0
Cookie: PHPSESSID=c4ggt4jull9obt7aupa55o8vbf
```

Key components of the request:

* **Method**: The action to perform (`GET`, `POST`, etc.)
* **Path**: The resource being accessed
* **Version**: HTTP protocol version (e.g. `HTTP/1.1`)
* **Headers**: Metadata like host name, cookies, accepted content types
* **Body (optional)**: Only used in some requests like `POST`, `PUT`

**Note**:

* HTTP/1.x requests are plain-text with newline-separated fields.
* HTTP/2 uses a binary format for efficiency and performance.

***

#### HTTP Response Structure

Example HTTP response:

```
HTTP/1.1 200 OK
Date: Tue, 21 Jul 2020 05:20:15 GMT
Server: Apache/2.4.41
Set-Cookie: PHPSESSID=m4u64rqlpfthrvvb12ai9voqgf
Content-Type: text/html; charset=UTF-8

<!DOCTYPE html>
<html>
  <body>
    <h1>Welcome</h1>
  </body>
</html>
```

Key components of the response:

* **Status line**: Contains the HTTP version and status code (e.g. `200 OK`)
* **Headers**: Metadata such as content type and cookies
* **Body (optional)**: The content returned (HTML, JSON, images, etc.)

The body is often HTML, but can be any type of data: images, PDFs, JavaScript, CSS, etc.

***

#### Using cURL to Inspect Requests & Responses

By default, `cURL` only displays the response body:

```
curl inlanefreight.com
```

Use the `-v` flag (verbose) to see the full HTTP request and response:

```
curl inlanefreight.com -v
```

Example verbose output (simplified):

```
> GET / HTTP/1.1
> Host: inlanefreight.com
> User-Agent: curl/7.65.3
> Accept: */*

< HTTP/1.1 401 Unauthorized
< Date: Tue, 21 Jul 2020 05:20:15 GMT
< Server: Apache/X.Y.ZZ (Ubuntu)
< WWW-Authenticate: Basic realm="Restricted Content"
< Content-Length: 464
< Content-Type: text/html; charset=iso-8859-1
```

Use `-vvv` for even more detailed output.

This allows you to see:

* Exactly what headers and methods were sent
* What the server responded with (status, headers, and body)

***

#### Using Browser DevTools

Modern browsers like Chrome and Firefox include built-in **Developer Tools (DevTools)** that let you inspect HTTP traffic.

To open DevTools:

* Press `Ctrl + Shift + I` or `F12`

Go to the **Network** tab, then refresh the page.

You’ll see:

* All HTTP requests made by the browser
* Request methods (e.g. `GET`, `POST`)
* Response codes (e.g. `200`, `404`)
* Requested paths and URLs

You can also:

* Click any request to view its headers and body
* Use filters to find specific requests
* View the raw HTML/JSON response under the **Response** tab → click **Raw**

### HTTP Headers

#### Overview

HTTP headers pass information between the client and the server. Some headers are specific to requests, others to responses, and some apply to both. Headers are written as `Header-Name: value` and may contain multiple values separated by commas.

Headers are commonly categorized as:

* General Headers
* Entity Headers
* Request Headers
* Response Headers
* Security Headers

***

#### General Headers

Used in both requests and responses to describe the message context.

* **Date**: `Date: Wed, 16 Feb 2022 10:38:44 GMT` – Timestamp of the message (UTC recommended)
* **Connection**: `Connection: close` – Controls whether the connection stays open (`keep-alive`) or closes after the request

***

#### Entity Headers

Describe the content being transferred. Common in responses and in `POST` or `PUT` requests.

* **Content-Type**: `Content-Type: text/html; charset=UTF-8` – Type of resource and character encoding
* **Media-Type**: `Media-Type: application/pdf` – Specifies the media/file type
* **Boundary**: `boundary="b4e4fbd93540"` – Used to separate multipart content
* **Content-Length**: `Content-Length: 385` – Size of the entity body in bytes
* **Content-Encoding**: `Content-Encoding: gzip` – Specifies transformations like compression

***

#### Request Headers

Sent by the client to describe request details.

* **Host**: `Host: www.inlanefreight.com` – Target host or domain
* **User-Agent**: `User-Agent: curl/7.77.0` – Identifies the client software
* **Referer**: `Referer: http://www.inlanefreight.com/` – Source page of the request
* **Accept**: `Accept: */*` – Accepted content types
* **Cookie**: `Cookie: PHPSESSID=b4e4fbd93540` – Session or stored user data
* **Authorization**: `Authorization: BASIC cGFzc3dvcmQK` – Credentials or authentication token

***

#### Response Headers

Sent by the server to provide response details.

* **Server**: `Server: Apache/2.2.14 (Win32)` – Server software and version
* **Set-Cookie**: `Set-Cookie: PHPSESSID=b4e4fbd93540` – Cookies for client identification
* **WWW-Authenticate**: `WWW-Authenticate: BASIC realm="localhost"` – Authentication requirements

***

#### Security Headers

Used to enforce security policies in the browser.

* **Content-Security-Policy**: `Content-Security-Policy: script-src 'self'` – Restricts allowed content sources
* **Strict-Transport-Security**: `Strict-Transport-Security: max-age=31536000` – Forces HTTPS for a set duration
* **Referrer-Policy**: `Referrer-Policy: origin` – Controls referrer header behavior

***

#### Using cURL with Headers

* Show only response headers:\
  `curl -I https://www.inlanefreight.com`
* Show headers and body:\
  `curl -i https://www.inlanefreight.com`
* Change User-Agent:\
  `curl https://www.inlanefreight.com -A 'Mozilla/5.0'`

Example `-I` output:

```
Date: Sun, 06 Aug 2020 08:49:37 GMT
Connection: keep-alive
Content-Length: 26012
Content-Type: text/html; charset=ISO-8859-4
Content-Encoding: gzip
Server: Apache/2.2.14 (Win32)
Set-Cookie: name1=value1,name2=value2; Expires=Wed, 09 Jun 2021 10:18:14 GMT
WWW-Authenticate: BASIC realm="localhost"
Content-Security-Policy: script-src 'self'
Strict-Transport-Security: max-age=31536000
Referrer-Policy: origin
```

***

#### Viewing Headers in Browser DevTools

* Open DevTools (`Ctrl + Shift + I` or `F12`)
* Go to **Network** tab and refresh the page
* Click a request to see **Headers** tab
  * Displays request and response headers
  * Option to view raw format
* **Cookies tab** shows any cookies in the request

## HTTP Methods

### HTTP Methods and Codes

#### Overview

HTTP supports multiple methods for accessing and interacting with resources. These methods tell the server how to process the request and what kind of action to take. The server’s response includes a status code that indicates the result of the request.

With `cURL`, using `-v` shows the HTTP method in the first line (e.g., `GET / HTTP/1.1`). In browser DevTools, the HTTP method appears in the **Method** column, while the status code appears in the **Status** column.

***

#### Common HTTP Methods

* **GET** – Retrieves a specific resource. Extra parameters can be added via query strings (e.g., `?param=value`).
* **POST** – Sends data to the server. Data is placed in the request body. Commonly used for forms, logins, or file uploads.
* **HEAD** – Returns only headers, no body. Often used to check response size before downloading.
* **PUT** – Creates or replaces a resource on the server. Requires strict controls to prevent uploading malicious files.
* **DELETE** – Removes an existing resource. Poorly secured endpoints could allow deletion of important files.
* **OPTIONS** – Returns server information, such as supported HTTP methods.
* **PATCH** – Applies partial updates to a resource.

Most modern applications rely mainly on **GET** and **POST**. REST APIs frequently use **PUT** and **DELETE** for updating and removing data.

***

#### HTTP Status Codes

Status codes indicate the result of an HTTP request. They are grouped into five classes:

* **1xx** – Informational responses, no effect on request processing
* **2xx** – Successful requests
* **3xx** – Redirect responses
* **4xx** – Client errors (e.g., malformed requests, unauthorized access)
* **5xx** – Server errors

***

#### Common Status Code Examples

* **200 OK** – Successful request; body usually contains requested resource
* **302 Found** – Redirect to another URL (e.g., redirect to dashboard after login)
* **400 Bad Request** – Malformed request (e.g., missing line terminators)
* **403 Forbidden** – Client lacks permission or input was blocked as malicious
* **404 Not Found** – Resource doesn’t exist on the server
* **500 Internal Server Error** – Server unable to process the request

Different providers (e.g., Cloudflare, AWS) may also implement their own non-standard codes.

### GET

#### Overview

When we visit any URL, the browser makes a default `GET` request to retrieve resources from the server. Once the initial page loads, additional `GET` or other method-based requests may be made for assets like images, scripts, or API data. These can be viewed in the browser’s DevTools **Network** tab.

**Exercise**: Open any website, open the Network tab in DevTools, and monitor the HTTP activity to understand how the site communicates with its backend.

***

#### HTTP Basic Auth

Some pages require credentials via **HTTP Basic Authentication**, rather than a standard login form. This method is handled directly by the web server (not the application backend).

Example URL:\
`http://<SERVER_IP>:<PORT>/`

When prompted, enter credentials `admin:admin`.

#### Unauthenticated cURL Request:

```bash
curl -i http://<SERVER_IP>:<PORT>/
```

Response:

```
HTTP/1.1 401 Authorization Required
WWW-Authenticate: Basic realm="Access denied"
```

This confirms the page is protected with Basic Auth.

#### Authenticated cURL Requests:

Using `-u`:

```bash
curl -u admin:admin http://<SERVER_IP>:<PORT>/
```

Embedding in URL:

```bash
curl http://admin:admin@<SERVER_IP>:<PORT>/
```

Add `-i` to either command to see response headers.

***

#### HTTP Authorization Header

With `-v`, we can inspect the full request/response, including the Authorization header:

```bash
curl -v http://admin:admin@<SERVER_IP>:<PORT>/
```

Part of the request:

```
> Authorization: Basic YWRtaW46YWRtaW4=
```

This is the base64 encoding of `admin:admin`.

#### Manually setting the header:

```bash
curl -H 'Authorization: Basic YWRtaW46YWRtaW4=' http://<SERVER_IP>:<PORT>/
```

This achieves the same result and is useful when scripting or bypassing interactive credential prompts.

***

#### GET Parameters

After authentication, we gain access to a **City Search** function on the site. Typing a query like "le" triggers a request to the backend:

```
http://<SERVER_IP>:<PORT>/search.php?search=le
```

Use DevTools **Network** tab (shortcut: `Ctrl+Shift+E`) to observe these requests.

#### Example cURL Request with GET Parameters:

```bash
curl 'http://<SERVER_IP>:<PORT>/search.php?search=le' -H 'Authorization: Basic YWRtaW46YWRtaW4='
```

Expected output:

```
Leeds (UK)
Leicester (UK)
```

{% hint style="info" %}
**Note**: When copying as cURL from DevTools, unnecessary headers may be included. You can remove all except essential ones like `Authorization`.
{% endhint %}

***

#### Fetch via JavaScript Console

You can also copy the request as JavaScript Fetch:

* Right-click request → Copy > Copy as Fetch
* Go to Console (`Ctrl+Shift+K`)
* Paste and execute the Fetch command to replicate the request

Example:

```js
fetch("http://127.0.0.1/search.php?search=le", {
  headers: {
    "Authorization": "Basic YWRtaW46YWRtaW4="
  }
})
.then(response => response.text())
.then(data => console.log(data));
```

This shows the response directly in the console and helps understand frontend-to-backend interaction.

### POST

#### Overview

Unlike `GET`, which places parameters in the URL, `POST` sends parameters in the **HTTP request body**.

Benefits of POST:

* **No URL logging**: Large file uploads or sensitive data aren’t logged in the URL.
* **Less encoding**: Data in the body can include binary data without URL encoding.
* **Larger payload**: URLs are limited in length (generally below 2,000 characters), while POST bodies can handle much larger data.

***

#### Login Forms

Example application uses a PHP login form:\
`http://<SERVER_IP>:<PORT>/`

Credentials: `admin:admin`

Observed in DevTools Network tab, the POST request sends:

```
username=admin&password=admin
```

Crafting this request with `cURL`:

```bash
curl -X POST -d 'username=admin&password=admin' http://<SERVER_IP>:<PORT>/
```

If authentication redirects to another page, follow redirects with `-L`:

```bash
curl -L -X POST -d 'username=admin&password=admin' http://<SERVER_IP>:<PORT>/
```

***

#### Authenticated Cookies

After successful login, server returns a session cookie:

```
Set-Cookie: PHPSESSID=c1nsa6op7vtk7kdis7bcnbadf1; path=/
```

Use cookie in subsequent requests with `-b`:

```bash
curl -b 'PHPSESSID=c1nsa6op7vtk7kdis7bcnbadf1' http://<SERVER_IP>:<PORT>/
```

Or send cookie as a header:

```bash
curl -H 'Cookie: PHPSESSID=c1nsa6op7vtk7kdis7bcnbadf1' http://<SERVER_IP>:<PORT>/
```

In the browser:

* Open **Storage** tab (`Shift+F9`) in DevTools
* Add or edit cookie `PHPSESSID` with authenticated value to bypass login

***

#### JSON Data

Search functionality sends a POST request with JSON data:

```json
{"search":"london"}
```

Request headers include:

```
Content-Type: application/json
Cookie: PHPSESSID=c1nsa6op7vtk7kdis7bcnbadf1
```

Replicating with `cURL`:

```bash
curl -X POST -d '{"search":"london"}' \
-b 'PHPSESSID=c1nsa6op7vtk7kdis7bcnbadf1' \
-H 'Content-Type: application/json' \
http://<SERVER_IP>:<PORT>/search.php
```

Response:

```
["London (UK)"]
```

***

#### Using Fetch in Browser Console

Right-click the request in DevTools → Copy → Copy as Fetch\
Execute in Console (`Ctrl+Shift+K`):

```js
fetch("http://<SERVER_IP>:<PORT>/search.php", {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    "Cookie": "PHPSESSID=c1nsa6op7vtk7kdis7bcnbadf1"
  },
  body: JSON.stringify({search:"london"})
})
.then(response => response.json())
.then(data => console.log(data));
```

Returns the same result as cURL, confirming direct interaction with backend without frontend login.

### CRUD API

#### APIs

Web applications can expose **APIs** to allow programmatic interaction with resources, often connected to a backend database. These APIs typically follow a pattern where:

* The **table name** is part of the URL (e.g., `/city`)
* The **row or record** is also part of the URL (e.g., `/city/london`)
* The **HTTP method** (GET, POST, PUT, DELETE) determines the action

Example:

```bash
curl -X PUT http://<SERVER_IP>:<PORT>/api.php/city/london
```

***

#### CRUD

Common operations supported by REST-style APIs:

| Operation | HTTP Method | Description                   |
| --------- | ----------- | ----------------------------- |
| Create    | POST        | Adds new data to the database |
| Read      | GET         | Retrieves existing data       |
| Update    | PUT         | Modifies existing data        |
| Delete    | DELETE      | Removes existing data         |

***

#### Read

To read a single city entry:

```bash
curl http://<SERVER_IP>:<PORT>/api.php/city/london
```

Formatted with `jq`:

```bash
curl -s http://<SERVER_IP>:<PORT>/api.php/city/london | jq
```

To read all cities matching a search term:

```bash
curl -s http://<SERVER_IP>:<PORT>/api.php/city/le | jq
```

To read all entries:

```bash
curl -s http://<SERVER_IP>:<PORT>/api.php/city/ | jq
```

You can also test these URLs in the browser to view the raw JSON output.

***

#### Create

To create a new city using `POST`:

```bash
curl -X POST http://<SERVER_IP>:<PORT>/api.php/city/ \
-d '{"city_name":"HTB_City", "country_name":"HTB"}' \
-H 'Content-Type: application/json'
```

To confirm it was added:

```bash
curl -s http://<SERVER_IP>:<PORT>/api.php/city/HTB_City | jq
```

**Exercise**: Try using a JavaScript `fetch` POST request in the browser DevTools Console to add a city.

***

#### Update

To update an existing city using `PUT`:

```bash
curl -X PUT http://<SERVER_IP>:<PORT>/api.php/city/london \
-d '{"city_name":"New_HTB_City", "country_name":"HTB"}' \
-H 'Content-Type: application/json'
```

Confirm the update:

```bash
curl -s http://<SERVER_IP>:<PORT>/api.php/city/london | jq
curl -s http://<SERVER_IP>:<PORT>/api.php/city/New_HTB_City | jq
```

{% hint style="info" %}
Note: Some APIs allow PUT to also create entries if the target doesn't exist. Try updating a non-existent city to test behavior.
{% endhint %}

***

#### Delete

To delete a city:

```bash
curl -X DELETE http://<SERVER_IP>:<PORT>/api.php/city/New_HTB_City
```

Then verify it's gone:

```bash
curl -s http://<SERVER_IP>:<PORT>/api.php/city/New_HTB_City | jq
```

Expected output: `[]`

**Exercise**: Try deleting any other city you previously added and confirm with a read request.

***

With this approach, you can fully manage CRUD operations through an API using `cURL`.

In real-world applications:

* These API actions are typically restricted to authorized users
* Authentication might be required via **cookies** or **Authorization headers** (e.g., JWT)
* Write operations (create, update, delete) should be protected with proper access control policies.
