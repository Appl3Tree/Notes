# Module 4: Introduction to Burp Suite

## Browser and Integration

### Launching Burp Suite

### [Using Burp Suite's Built-in Browser](https://appl3tree.gitbook.io/notes/courses/offsec/web-200/module-2-tools-archived#burp-suite)

### [Integrating Burp Suite with Other Browsers](https://appl3tree.gitbook.io/notes/courses/offsec/web-200/module-2-tools-archived#using-burp-suite-with-other-browsers)

## Proxy and Scope

### [Proxy](https://appl3tree.gitbook.io/notes/courses/offsec/web-200/module-2-tools-archived#proxy)

### Scope

_Options > Project > Scope_.

<figure><img src="../../../.gitbook/assets/dac7ad1b587f7d83526adf51f22a7051-burp-scope-06.png" alt=""><figcaption><p>Adding offsecwp to our target scope</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/545d2d9e9110d2722cc9a5a428af854d-burp-scope-07.png" alt=""><figcaption><p>Ignoring out-of-scope (OOS) items</p></figcaption></figure>



## Core Burp Suite Tools and Tabs

### [Repeater](https://appl3tree.gitbook.io/notes/courses/offsec/web-200/module-2-tools-archived#repeater)

### Comparer

<figure><img src="../../../.gitbook/assets/9c4062af840bd3e91c476f8e5a20db05-burp-comparer-01.png" alt=""><figcaption><p>The Comparer tool</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/add760b26ce881a3a0a2160122cfba8c-burp-comparer-02.png" alt=""><figcaption><p>Loading two separate endpoins for comparison</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/cbd0c599336e28798c9315381c341522-burp-comparer-03.png" alt=""><figcaption><p>Both Responses loaded into Comparer</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/b57d054b00db2a9c74a0c527c280697e-burp-comparer-04.png" alt=""><figcaption><p>Comparing the Responses of our Requests</p></figcaption></figure>

### [Intruder](https://appl3tree.gitbook.io/notes/courses/offsec/web-200/module-2-tools-archived#intruder)

* Sniper: Single field brute force.
* Battering Ram: Bruteforce multiple fields with a wordlist.
* Pitchfork: Bruteforce multiple fields with different wordlists.
* Cluster Bomb: Bruteforce multiple fields with multiple wordlists.

### Decoder

<figure><img src="../../../.gitbook/assets/09713c0cdf2d51e49b1523afac62935b-burp-decoder-01.png" alt=""><figcaption><p>Decoder</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/40e0253765b4473c171fd9a30d56b771-burp-decoder-02.png" alt=""><figcaption><p>A new box apperars after entering data</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/b04c7e314e2c05952822ff6e92d32271-burp-decoder-03.png" alt=""><figcaption><p>Telling Burp Suite to decode as Base64</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/eb64529a811ab1e05d2a72c0d45b2616-burp-decoder-04.png" alt=""><figcaption><p>Decoded string result</p></figcaption></figure>

## Professional Features

### Burp Scanner, Active Scan, Collaborator, and Intruder

* Burp Scanner: automated scanning on a domain, an endpoint, or even from a specific intercepted request.
* Extensions like ActiveScan++
* Collaborator tool: requests/payloads are sent additionally to the collaborator server. If there is interaction between the request made and its internal database, collaborate notifies the tester.
* Intruder is no longer throttled.
* CSRF PoC generator.
