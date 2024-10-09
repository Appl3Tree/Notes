---
layout:
  title:
    visible: true
  description:
    visible: false
  tableOfContents:
    visible: true
  outline:
    visible: true
  pagination:
    visible: true
---

# Module 7: Threat Hunting Challenge Labs

## TH-200 Challenge Lab 1

### Lab Environment

_Context._

<figure><img src="../../../.gitbook/assets/image.png" alt=""><figcaption><p>Megacorp One Network Topology</p></figcaption></figure>

### Assignment and Recommendations

{% file src="../../../.gitbook/assets/Threat_Intel_Chall1.pdf" %}
Threat Intel for Challenge Lab 1
{% endfile %}

## Scoring Mechanism

_The Challenge Labs and Exam consist of a list of questions that you need to answer by successfully conducting the assigned threat hunt. Instead of directly entering the answers, such as timestamps, hash values, or object names, you are required to input them into the application located at **C:\Users\offsec\Desktop\flags.exe** on the DEV machine. This application generates a hash based on your input that you can submit as an answer._

_To verify the correctness of your answer's format, each exercise includes a list of 10 hash values. After generating a hash with **flags.exe**, you should compare it against the provided list to ensure your input format is accurate. If your hash does not match any on the list, it indicates either an incorrect answer or format error._

For exercises that ask for file hashes, submit the SHA-256 hash, not the MD5 hash, which may also be present in the event data.
