# Module 2: Introduction to Web Applications

## Introduction to Web Applications

### Introduction

Web applications run in browsers using a client-server model. The **front end** (UI) operates on the client side, while the **back end** (logic and databases) runs on remote servers. This setup enables centralized updates, global access, and consistent functionality. Examples include email services, e-commerce platforms, and online productivity tools.

Anyone can develop and host a web application, which has led to millions of publicly accessible apps and billions of daily users.

#### Web Applications vs. Websites

Traditional websites (Web 1.0) are static and show the same content to all visitors, requiring manual updates by developers.\
Modern websites (Web 2.0) often operate as **web applications** that update dynamically based on user actions.

Key differences:

* Websites are static and informational; web apps are interactive and functional.
* Web apps adapt to any device and platform.

#### Web Applications vs. Native Operating System Applications

Web apps:

* Run in browsers, require no installation, and save local storage space.
* Offer version consistency, as updates occur on the server for all users.
* Reduce maintenance and support costs by avoiding platform-specific builds.

Native OS apps:

* Integrate deeply with system libraries and hardware for better performance.
* Load faster and support more advanced capabilities.

Modern **hybrid** and **progressive web apps** combine aspects of both, leveraging native features while maintaining browser-based portability.

#### Web Application Distribution

* **Open source apps** (e.g., WordPress, OpenCart, Joomla) can be customized for specific needs.
* **Closed source apps** (e.g., Wix, Shopify, DotNetNuke) are proprietary, sold or licensed through subscriptions.

#### Security Risks of Web Applications

Because web apps are public-facing, they have a large attack surface. Vulnerabilities can be introduced through complex features or poor coding practices.

Potential risks:

* Data breaches affecting sensitive corporate or user data.
* Disruption of services.
* Lateral movement into connected systems.

Best practices:

* Regular penetration testing (authenticated and unauthenticated).
* Secure coding throughout the development lifecycle.
* Prompt patching with validation.

Testing is often guided by frameworks like the **OWASP Web Security Testing Guide**, starting with the front end (HTML, CSS, JavaScript) and then analyzing server-side functionality and authentication.

#### Attacking Web Applications

Most organizations host web apps, ranging from simple static sites to complex multi-role systems. These apps frequently change, and even small code updates can introduce severe vulnerabilities.

Common attack types:

* **SQL Injection** – Manipulating unsafe queries to extract or modify data, sometimes enabling attacks like password spraying against VPN or email portals.
* **File Inclusion** – Gaining access to source code or hidden features that can lead to remote code execution.
* **Unrestricted File Upload** – Uploading non-image files (e.g., malicious code) when upload filters are poorly enforced.
* **Insecure Direct Object References (IDOR)** – Modifying object identifiers (e.g., `/user/701` → `/user/702`) to access other users’ data.
* **Broken Access Control** – Exploiting poorly implemented role or privilege checks, such as modifying registration parameters to gain admin rights.

These flaws can be chained for greater impact. A strong understanding of web applications and their attack vectors helps security professionals uncover vulnerabilities others might miss.



## Front End Components



## Front End Vulnerabilities



## Back End Components



## Back End Vulnerabilities



## Next Steps
