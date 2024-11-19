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

# Module 3: Wi-Fi Encryption

## Open Wireless Networks

<figure><img src="../../../.gitbook/assets/image (21) (1).png" alt=""><figcaption><p>The process of connecting to open networks</p></figcaption></figure>

## Wired Equivalent Privacy

WEP uses a 24-bit initialization vector (IV). A 64-bit key was permitted, 24 bits are used for IVs, resulting in a real key size of 40 bits.

### RC4

RC4 is a symettric cipher. Streams of bits are XOR'd with plain text to get the encrypted data. Decrypting it is simply XORing the encrypted text with the key stream.&#x20;

RC4 costs of two key elements:

1. **Key Scheduling Algorithm (KSA)**: Initializes the state table with the IV and WEP key.
2. **Pseudo-Random Generation Algorithm (PRGA)**: Creates the keystream.

<figure><img src="../../../.gitbook/assets/image (22) (1).png" alt=""><figcaption><p>RC4 encryption/decryption overview</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (23) (1).png" alt=""><figcaption><p>The WEP encryption process</p></figcaption></figure>

1. Concatenate the IV and WEP key, then run KSA and PRGA to get the keystream.
2. Create the Integrity Check Value (ICV) of the message, then concatenate it to the message.
3. XOR the plain text message plus the CRC32 and the keystream to obtain the encrypted text.
4. The packet then contains the following elements:
   * IV (Used Previously)
     * Key ID
     * Encrypted Text
     * ICV that is the CRC32 of the plain text

<figure><img src="../../../.gitbook/assets/image (24) (1).png" alt=""><figcaption><p>The WEP decryption process</p></figcaption></figure>

1. Concatenate the IV and the key corresponding to the key ID, then run KSA and PRGA to obtain the keystream.
2. XOR the encrypted message and the keystream, resulting in the message + ICV.
3. Compare the decrypted ICV with the one received with the packet. If they are the same, the frame is intact and accepted, otherwise, discard the frame, as the packet is fake or corrupted.

### WEP Authentication

WEP can make use of two authentication systems:

1. Open Authentication: Client does not provide any credentials. Once associated, it must possess the correct key to encrypt/decrypt data frames.
2. Shared Authentication: A challenge text is sent to the client. The text must be encrypted with the WEP key by the client and sent back to the AP for verification. The AP then attempts to decrypt the text. If successful and matches the clear text version, the client is allowed to proceed to associate with the AP.

## Wi-Fi Protected Access

<figure><img src="../../../.gitbook/assets/image (25) (1).png" alt=""><figcaption><p>The WPA connection process</p></figcaption></figure>

### WPA Ciphers

Two ciphers are available to WPA:

1. TKIP: Designed to be backward compatible with legacy hardware. Can only handle WEP, but addresses the flaws found in WEP:
   * Per packet key mixing
   * IV sequencing to avoid replay attacks
   * New Message Integrity Check (MIC), using the Michael algorithm and countermeasures on MIC failures
   * Key distribution and rekeying mechanism
2. CCMP: Based on AES. Also known as Robust Security Network (RSN). Designed from the ground up and is not compatible with older hardware.

### WPA Network Connection

The secure communication channel is set up in four steps:

1. Agreement on security protocols
2. Authentication
3. Key distribution and verification
4. Data encryption and integrity

<figure><img src="../../../.gitbook/assets/image (30).png" alt=""><figcaption><p>The WPA Enterprise connection process</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (1) (1) (1) (1) (1).png" alt=""><figcaption><p>The WPA-PSK connection process</p></figcaption></figure>

### WPA Authentication

The authentication step is only done in WPA Enterprise configurations and is based on the Extensible Authentication Protocol (EAP).

<figure><img src="../../../.gitbook/assets/image (2) (1) (1) (1) (1).png" alt=""><figcaption><p>The key distribution and verification phase</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption><p>The group key handshake process</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (4) (1) (1) (1).png" alt=""><figcaption><p>The Pairwise Transient Key (PMK) generation process</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (5) (1) (1) (1).png" alt=""><figcaption><p>The GTK construction process</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (6) (1) (1).png" alt=""><figcaption><p>A TKIP encrypted frame</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (7) (1) (1).png" alt=""><figcaption><p>A CCMP encrypted frame</p></figcaption></figure>

## Wi-Fi Protected Access 3

Simultaneous Authentication of Equals (SAE) replaces PSK in WPA personal. SAE is a variant of Dragonfly. AES is the only cipher allowed.&#x20;

<figure><img src="../../../.gitbook/assets/image (8) (1) (1).png" alt=""><figcaption><p>WPA3 authentication</p></figcaption></figure>

## Opportunistic Wireless Encryption

<figure><img src="../../../.gitbook/assets/image (9) (1) (1).png" alt=""><figcaption><p>Opportunistic Wireless encryption connection</p></figcaption></figure>

## Wireless Protected Setup

### WPS Architecture

There are three components to WPS:

* Enrollee: a device seeking to join a WLAN
* Access point
* Registrar: an entity with the authority to issue or revoke credentials for a WLAN

<figure><img src="../../../.gitbook/assets/image (10) (1) (1).png" alt=""><figcaption><p>WPS components and interfaces</p></figcaption></figure>

### WPS Configuration Methods

Two modes of operations are available: in-band configuration and out-of-band configuration. In-band is done via WLAN communication and out-of-band is done using any other communication channel or method, such as by using a NFC tag or USB thumbdrive.

### WPS Protocol

<figure><img src="../../../.gitbook/assets/image (11) (1).png" alt=""><figcaption><p>Setup using a standalone AP/Registrar</p></figcaption></figure>

### WPS Registration Protocol Messages

_The M1 to M8 EAP messages are specific to the WPS registration protocol._   &#x20;

## 802.11w

### Connection

The below table details the outcome of connection depending on the client and AP settings for PMF:

| AP       | Client   | Connection | PMF |
| -------- | -------- | ---------- | --- |
| No       | No       | Yes        | No  |
| No       | Capable  | Yes        | No  |
| No       | Required | No         |     |
| Capable  | No       | Yes        | No  |
| Capable  | Capable  | Yes        | Yes |
| Capable  | Required | Yes        | Yes |
| Required | No       | No         |     |
| Required | Capable  | Yes        | Yes |
| Required | Required | Yes        | Yes |

### Security Association Teardown Protection

This mechanism prevents attacks using unprotected association, disassociation or deauthentication frames from tearing down a connection.
