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

# Module 3: Communication and Reporting for Threat Hunters

## Inbound Communication

### Traffic Light Protocol

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption><p>Traffic Light Protocol</p></figcaption></figure>

**TLP:Red**: Used when information cannot be effectively acted upon without **significant** risk to teh privacy, reputation, or operations of the organizations involved. Information is usually exchanged verbally or in person and is only for use by the specific recipient(s) and may not be shared outside of the exchange, meeting, or conversation in which it was originally disclosed.

**TLP:Amber+Strict**: Used when exposure of the information carries a **risk** to privacy, reputation, or operations, but the information requires support from second parties to be effectively acted upon. Information can be shared on a need-to-know basis with members of their own organization.

**TLP:Amber**: Used when information carries a **risk** to privacy, reputation, or operations if exposed beyond the source and recipient organizations. Information can be shared on a need-to-know basis within the recipient organization and its clients.

**TLP:Green**: Used when information is not intended for public exposed but carries **no risk** when used within the recipient's organization and its wider community of peer and partner organizations. Information may not be shared outside of the cyber security or cyber defense community.

**TLP:Clear**: Used when the information carries **minimal or no foreseeable risk** of misuses and may be shared without restriction.&#x20;

### Threat Intel Feeds

<figure><img src="../../../.gitbook/assets/image (4) (1) (1) (1).png" alt=""><figcaption><p>Threat Intelligence Operations</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (5) (1) (1) (1).png" alt=""><figcaption><p>Threat Hunting Maturity Model</p></figcaption></figure>

Using cURL to send a request to the MITRE threat intelligence API:

{% code overflow="wrap" %}
```bash
kali@kali:~$ curl -H "Accept: application/vnd.oasis.stix+json; version=2.0"  https://cti-taxii.mitre.org/stix/collections/2f669986-b40b-4423-b720-4396ca6a462b/objects/  > threats

kali@kali:~$  cat threats | jq 
{
  "type": "bundle",
  "id": "bundle--833c1ad0-13f3-4719-84c3-650c12994630",
  "spec_version": "2.0",
  "objects": [
    {
      "type": "relationship",
      "id": "relationship--3d5a1472-4042-49a4-8b66-7ff1fcfee92c",
      "created": "2024-04-18T15:36:58.833Z",
      "created_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
      "revoked": false,
      "external_references": [
        {
          "source_name": "MSTIC Octo Tempest Operations October 2023",
          "description": "Microsoft. (2023, October 25). Octo Tempest crosses boundaries to facilitate extortion, encryption, and destruction. Retrieved March 18, 2024.",
          "url": "https://www.microsoft.com/en-us/security/blog/2023/10/25/octo-tempest-crosses-boundaries-to-facilitate-extortion-encryption-and-destruction/"
        }
      ],
      "object_marking_refs": [
        "marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168"
      ],
      "modified": "2024-04-18T17:49:54.985Z",
      "description": "[Scattered Spider](https://attack.mitre.org/groups/G1015) has sent SMS phishing messages to employee phone numbers with a link to a site configured with a fake credential harvesting login portal.(Citation: MSTIC Octo Tempest Operations October 2023)",
      "relationship_type": "uses",
```
{% endcode %}

## Outbound Communication

### Internal Security Communications

_Not much to add, just talking about the different approaches to threat hunting and their order of operation._

### Disclosure Protocol

_Not much to add, essentially adhere to responsible disclosure policies._

### Threat Intel Reporting

_Not much to add, talking about writing up threat intel reports via MITRE ENGENUITY's CTI Blueprints._&#x20;

{% hint style="info" %}
Likely useful for the reporting aspect of the OSTH exam.
{% endhint %}

