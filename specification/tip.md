The Introduction Protocol (TIP)
===============================

The Introduction Protocol (TIP) provides a means to to securely introduce one
entity to another. The protocol establishes a unique pair-wise secret between
peers and then enables the peers to demonstrate the possession of one or more
public keys. The ownership of a long-term public key is used as a form of
identity to support access control and authorization.

TIP is a generic protocol that does not directly describe cryptographic
algorithms. The cryptographic functions are grouped together into Cipher Suites
that define the processing necessary to implement the generic protocol. An
instantiation of TIP must support at least one Cipher Suite that fully describes
the required processing to create and encode the fields within protocol. The
Cipher Suite definition includes public key operations, hash algorithms,
encryption and the means to demonstrate a proof-of-possession of a public key.

The protocol is structured to limit the exposure of long-term identifiers. This
provides protection from third party observation of the protocol exchange. The
protocol first exchanges ephemeral keys to provide shared cryptographic keys.
These derived unique keys are then used encrypt subsequent message exchanges.
The exchange of long-term public keys, credentials and configuration information
is always encrypted. At the completion of the protocol exchange both peer's
share a common shared symmetric key as part of a pairwise Security Association
(SA).

The mappings of the TIP messages to a particular communication channel are
defined separately from the protocol to facilitate its use over any type of
media. The protocol is primarily an authentication mechanism, but allows the
inclusion of configuration information to support out-of-box setup. Application
of TIP to specific discovery and communication channels for setup is described
in Section 4.

TIP Messages
------------

The TIP authenticated key exchange consists of five messages M0, M1, M2, M3, and
M4. The M0 message is optionally included in the discovery process to indicate
the available Cipher Suites.

The M1, M2, M3 and M4 messages are carried within the service information field
of the Service Descriptor Attribute (SDA) of SDFs of subsequent follow-up
messages.

\< ... Figure goes here ... \>

Figure 1: Example Flow of Protocol with User Interactions

### M0 Message

The M0 message is optionally sent to describe the supported Cipher Suites. If
sent, it contains a list of supported *csid* values. M0 may optionally be
included in the Publish SDF by the Enrollee.

### M1 Message

M1 is sent from the entity initiating the authentication process and contains
two unencrypted fields:

-   *csid* indicates the Cipher Suite used for the exchange and determines the
    format and usage of the associated *keyData* field.

-   *keyData* is an opaque octet string. The Cipher Suite determines the usage
    and encoding of the field. For public key based Cipher Suites this field
    typically contains the initiators ephemeral public key.

### M2 Message

M2 is sent in response to received M1 messages and contains both unencrypted and
encrypted fields:

-   *SCID* indicates the Security Context IDentifer of the message. The SCID
    uniquely identifies the information necessary to decrypt associated message.
    The calculation of the SCID is determined by the Cipher Suite and should be
    a truncated hash of fields in M1.

-   *keyData* is an opaque octet string containing the appropriate key
    information for the Cipher Suite. Typically for public key based Cipher
    Suites this field contains the responder's ephemeral public key.

-   *wrappedData* is an opaque octet string containing additional fields that
    have been encrypted and integrity protected (AEAD algorithm). For public key
    based Cipher Suites the encryption keys for this data are created using a
    Diffie-Hellman key establishment process. When decrypted, the *wrappedData*
    may contain the following fields:

    -   *newKeyList*

    -   *credentialList*

-   *newKeyList* provides one or more public keys owned by the responding
    entity. This public key should be a long-term key suitable to identify the
    responder for subsequent authorization and access control. The joint
    ownership of this public key shall be demonstrated using the
    proof-of-possession (PoP) processing defined by the Cipher Suite. The list
    contains one or more newKey fields consisting of three fields:

    -   *csid*

    -   *keyData*

    -   *proof* contains an opaque octet string that cryptographically
        demonstrates the joint ownership of the associated Key and the ephemeral
        public key sent unencrypted in the same M2 message.

-   *credentialList* contains attributes of the responding entity. The
    credentials may be a list of self declared attributes or third-party signed
    certificates.

### M3 Message

The initiating device sends M3 after successful processing of a received M2
message. The M3 message contains both unencrypted and encrypted fields.

-   *scid* indicates the Security Context of the message. The SCID uniquely
    identifies the context of the message. The calculation of the SCID is
    determined by the Cipher Suite and should be a truncated hash of fields in
    M2.

-   *wrappedData* is an opaque octet string containing additional fields that
    have been encrypted and integrity protected (AEAD algorithm). For public key
    based Cipher Suites the encryption keys for this data are created using a
    Diffie-Hellman key establishment process. Either the derivation of the
    encryption key or the 'additional associated data' of the AEAD algorithm
    shall be different than the prior M2 to mitigate reflection attacks. When
    decrypted, wrappedData may contain the following fields:

    -   *newKeyList*

    -   *credentialList*

-   newKey (within M3) provides a public key owned by the initiating entity.
    This public key should be a long-term key suitable to identify the initiator
    for subsequent authorization and access control. The joint ownership of this
    public key and the shall be demonstrated using the proof-of-possession (PoP)
    processing defined by the Cipher Suite. The newKey field contains three
    fields:

    -   *csid*

    -   *keyData*

-   *proof* contains an opaque octet string that cryptographically demonstrates
    the joint ownership of the associated Key and the ephemeral public key sent
    in M1.

-   *credentialList* contains attributes of the responding entity. The list of
    credentials may be a list of self-declared attributes or third-party signed
    certificates.

### M4 Message

M4 is sent by the responding entity after successful processing of a received M3
message and provides confirmation of the M3 message and the authentication
process. Subsequently, M4 may be used by either the initiating or responding
entity to exchange additional protected data. The M3 message contains both
unencrypted and encrypted fields.

-   *scid* indicates the Security Context of the message. The *scid* uniquely
    identifies the protocol context to support multiple instances of the
    protocol. The calculation of the SCID is determined by the Cipher Suite and
    should be a truncated hash of fields in prior messages.

-   *wrappedData* is an opaque octet string containing additional fields that
    have been encrypted and integrity protected (AEAD algorithm). For public key
    based Cipher Suites the encryption keys for this data are created using a
    Diffie-Hellman key establishment process. The M4 wrappedData field may be
    empty. When decrypted, the *wrappedData* may contain the following fields:

    -   optional additional data

Message Structure
-----------------

Each attribute is documented with a descriptive text name for the field, the
Attribute ID used for encoding, the attribute type and description and usage of
the field. The attribute types may be one of the following:

-   Map values that encapsulate a set of distinct additional attributes

-   List attributes that contain repeated instances of the same attribute

-   Atomic attributes that contain a single typed value (e.g. String, Integer,
    etc.). Note that Attribute Id values are only unique within the context of
    the containing structures (map or list).

### Messages M0, M1, M2, M3 and M4

The structure of the five base messages types are defined in Table 2.

**Table 2**: M0, M1, M2, M3 and M4 Encoding

| **Field** | **Attribute Id** | **Type** | **Description**                                                                                                                        |
|-----------|------------------|----------|----------------------------------------------------------------------------------------------------------------------------------------|
| *m0*      | 1                | List     | The Enrollee may optionally provide a list of one or more supported Cipher Suites with M0. One or more *csid* values must be included. |
| *m1*      | 2                | Map      | M1 carries the Initiators ephemeral or masked public key and contains: *csid* and *keyData*                                            |
| *m2*      | 3                | Map      | M2 contains: *scid*, *keyData*, *wrappedData*. When decrypted,the *wrappedData* contains the *privateData* map attribute.              |
| *m3*      | 4                | Map      | M3 contains: *scid* and *wrappedData*. When decrypted the *wrappedData* contains the *privateData* map attribute.                      |
| *m4*      | 5                | Map      | M4 contains: *scid* and *wrappedData*. When decrypted the *wrappedData* contains the *privateData* map attribute.                      |

### Message Attributes

The M0, M1, M2, M3 and M4 messages may contain the attributes defined below in
Table 3.

**Table 3**: Message Attributes

| **Field**     | **Attribute Id** | **Type**     | **Description**                                                                                                                                                                                                                         |
|---------------|------------------|--------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| *csid*        | 1                | Octet String | The Cipher Suite Identifier that describes the algorithm and processing of the *keyData* in M1 and subsequent cryptographic processing for all messages.                                                                                |
| *keyData*     | 2                | Octet String | An opaque octet string containing cryptographic key data. The encoding and processing of the field is determined by the associated *csid. keyData* is a required field in M1 and M2.                                                    |
| *scid*        | 3                | Octet String | The Security Context IDentifier (SCID) that identifies the context of the processing. The *scid* provides a unique transaction identifier to support multiple instances of the protocol. The *scid* shall be included in M2, M3 and M4. |
| *wrappedData* | 4                | Octet String | When decrypted the *wrappedData* contains the *privateData* map attribute.                                                                                                                                                              |

### Wrapped Data

The fields within the *wrappedData* of the M2, M3 and M4 message may contain the
protected attributes in Table 4.

**Table 4**: *wrappedData* Attributes

| **Field**           | **Attribute Id** | **Type** | **Description**                                                                                                                                                                                                                                                                                             |
|---------------------|------------------|----------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| *deviceDescription* | 1                | Map      | A set of one or more attributes describing characteristics of the device sending the attributes. The description shall include: *friendlyName* and may include: *manufacturer*, *modelDescription*, *modelName*, *modelNumber* and *serialNumber*. The *deviceDescription* should be included in M2 and M3. |
| *newKeyList*        | 2                | List     | A list of *newKey* attributes. The *newKey*                                                                                                                                                                                                                                                                 |

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
object provides a public key and a proof-of-possession of the public key
that demonstrates ownership of the key. | | *credentialList* | 3 | List
| A list of *credential* provided to support access control and
authorization decisions. | | *configData* | 4 | Map | A set of
configuration data to be used by the recipient. *configData* will typically
be sent once by the Configurator to the Enrollee in M3. Acceptance and
application of the *configData* is dependent on the state of and security
policies of the recipient. |
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

1.  3.2.4Device Description Attributes

The *deviceDescription* map may contain the attributes defined in Table 5.

Table 5: \_deviceDescription_Attributes

| **Field**          | **Attribute Id** | **Type** | **Description**                                                                                                                                                                                                                                     |
|--------------------|------------------|----------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| *friendlyName*     | 1                | String   | A short user-friendly title. The UTF-8 string shall not include non-printing characters and shall be less than 32 characters in length. The default value for devices should strive to be unique. This attribute is required in *deviceDescripton*. |
| *manufacturer*     | 2                | String   | The manufacturer name. This shall be a printable UTF-8 string and less than 32 characters in length.                                                                                                                                                |
| *modelDescription* | 3                | String   | Long user-friendly title. This shall be a printable UTF-8 string and less than 32 characters in length.                                                                                                                                             |
| *modelName*        | 4                | String   | Model name. This shall be a printable UTF-8 string and less than 32characters in length.                                                                                                                                                            |
| *modelNumber*      | 5                | String   | Model number. This should be a printable ASCII string less than 32 characters in length.                                                                                                                                                            |
| *serialNumber*     | 6                | String   | Manufacturer's serial number. This should be a printable ASCII string less than 32 characters in length.                                                                                                                                            |

1.  3.2.5New Key

The *newKeyList* provides the mechanism for an entity to demonstrate ownership
of one or more public keys. The list should include at least one primary
"identity key" to be used for access control and authorization processing by the
receiving entity. A new key shall be accepted only if the proof-of-possession
processing is valid for the associated Cipher Suite.

New keys (*newKeyList*) may be sent in M2, M3 or M4.

Table 6: \_newKey_Attribute

| **Field** | **Attribute Id** | **Type** | **Description**           |
|-----------|------------------|----------|---------------------------|
| *newKey*  | 1                | Map      | Each new key is a map of: |

-   *csid*

-   *keyData*

-   \_proof_The sub-attributes of *newKey* are defined in Table 7 \|

Table 7: *newKey* Sub-Attributes

| **Field** | **Attribute Id** | **Type**     | **Description**                                                                                                                                                                                                                                                                                                                             |
|-----------|------------------|--------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| *csid*    | 1                | Octet String | The Cipher Suite Identifier that describes the algorithm and processing of the *keyData* in the *newKey* map.                                                                                                                                                                                                                               |
| *keyData* | 2                | Octet String | An opaque octet string containing cryptographic key data. The encoding and processing of the field is determined by the associated *csid* in the *newKey* field_.\_                                                                                                                                                                         |
| *proof*   | 5                | Octet String | An opaque octet string containing a cryptographic proof of possession of the associated public key. The process to create or to validate the proof is determined by the associated Cipher Suite (*csid*). The proof should bound the possession to the current Security Association used to protect the transmission of the *newKey* field. |

### Credentials

A list of credentials may be provided to support access control and
authorization decisions. The application of the credentials to support a
security policy is out-of-scope of this protocol exchange. The credentials are
provided to upper layers for processing as event data from the reception of M2,
M3 or M4 messages.

The *credentialList* may contain one or more *credential* attributes as defined
in Table 8.

Table 8: *credential* Attribute

| **Field**    | **Attribute Id** | **Type** | **Description**                                  |
|--------------|------------------|----------|--------------------------------------------------|
| *credential* | 1                | Map      | A *credential* is a typed value with attributes: |

-   credentialType

-   credentialOctets \|

A *credential* is a typed value where the enumerated types may include X.509
certificates or other forms of third party signed attestations.

Table 9: *credential* Sub_-_Attributes

| **Field**          | **Attribute Id** | **Type**     | **Description**                                                                                                                                                                        |
|--------------------|------------------|--------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| *credentialType*   | 1                | Enum         | An enumerated type describing the associated *credentialOctets*.                                                                                                                       |
| *credentialOctets* | 2                | Octet String | An opaque octet string containing the credential of enumerated type *credentialType*. Interpretation and processing of the octet string is determined by the types defined in Table 10 |

Table 10: Enumerated *credentialType* Sub_-_Attributes

| **Field**   | **Enum Value** | **Type** | **Description**                                       |
|-------------|----------------|----------|-------------------------------------------------------|
| *UNKNOWN*   | 0              | Integer  | Error condition returned by unknown enumerated types. |
| *CONNECTOR* | 1              | Integer  | DPP Connector.                                        |
| *X509*      | 2              | Integer  | X.509 Certificate                                     |
| *HOTSPOT2*  | 3              | Integer  | Hotspot 2.0 Certificate                               |

### Configuration Attributes

The *configData* attribute may be included in M3 or M4 message.

Table 11: *configData* Attributes

| **Field**          | **Attribute Id** | **Type** | **Description**                                                                                                                        |
|--------------------|------------------|----------|----------------------------------------------------------------------------------------------------------------------------------------|
| *wpa2PersonalList* | 1                | List     | A list of configuration information for WPA2-Personal. The list may contain one or more values of *wpa2Personal* as defined in Section |
| *Other TBD*        | tbd              | tbd      | tbd                                                                                                                                    |

#### WPA2-Personal On-boarding

The Enrollee may optionally be provided with credentials to connect to one or
more WPA2-Personal protected Wi-Fi networks.

Table 12: WPA-2 Personal Configuration Attributes

| **Field**        | **Attribute Id** | **Type** | **Description**                                                                   |
|------------------|------------------|----------|-----------------------------------------------------------------------------------|
| *wpa2Credential* | 1                | Map      | Information necessary to connect securely to a Wi-Fi network using WPA2-Personal: |

-   *ssid*

-   wpa2_Passphrase\_

-   *macAddress (optional)* \|

The wpa2Credential contains the attributes defined in Table 13

Table 13: *wpa2Credential* Sub-Attributes

| **Field**        | **Attribute Id** | **Type**     | **Description**                                                                           |
|------------------|------------------|--------------|-------------------------------------------------------------------------------------------|
| *ssid*           | 1                | String       | A maximum of 32 characters containing the Service Set Identifier (SSID).                  |
| *wpa2Passphrase* | 2                | String       | The PSK or Passphrase is either a string of 8-63 characters or a string of 64 hex values. |
| *macAddress*     | 3                | Octet String | 6 octets containing the MAC address of the AP. This is an optional attribute.             |

TIP Encoding
------------

All attributes are encoded as Type-Length-Value (TLV) encodings as defined in
Table 14: Attribute Encoding Format.

Table 14: Attribute Encoding Format

| **Field**    | **Size (Octets)** | **Value (Hex)** | **Description**                         |
|--------------|-------------------|-----------------|-----------------------------------------|
| Attribute ID | 1                 | Variable        | Identifies the type of sub-attribute    |
| Length       | 2                 | Variable        | Length of the following value           |
| Value        | Variable          | Variable        | Value specific to the type of the field |

TIP Schema
----------

The following is an informative description of the protocol structure using the
Protocol Buffer [1] schema language. The use of this schema does not imply a
requirement to support Protocol Buffer binary serialization. The encoding
described in Section 3.2 uses the schema below with a simple TLV encoding for
serialization. The schema could be used for other serialization techniques (e.g.
JSON by using the field names as readable tag values).

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// tip.proto
//
// Protocol syntax definition for The Introduction Protocol (TIP)
//

message M0 {                      // optional capability indication
  repeated string csid = 1;
}

message M1 {                  
  required string csid = 1;
  required string keyData = 2;
}

message M2 {
  required string scid = 1;
  required string keyData = 2;
  required string wrappedData = 5; // when decrypted contains privateData
}

message M3 {
  required string scid = 1;
  required string wrappedData = 5; // when decrypted contains privateData
}

message M4 {
  required string scid = 1;
  required string wrappedData = 5; // when decrypted contains privateData
}

message Wpa2Credential {
  required string ssid = 1;
  required string wpa2Passphrase = 2;
  optional string macAddress = 3;
}

message Wpa2PersonalList {
  repeated Wpa2Credential wpa2Credential = 1;
}

message DeviceDescription { 
  // loosely based on UPnP - Basic:1.0 Device Definition Version 1.0
  // urn:schemas-upnp-org:device:Basic:1 
  optional string friendlyName = 1  // short user-friendly title UTF-8
                                    // default to disambiguate
  optional string manufacturer = 2  // manufacturer name UTF-8 
  optional string modelDescription = 3  // long user-friendly title
  optional string modelName = 4     // model name
  optional string modelNumber = 5   // model number
  optional string serialNumber = 6  // manufacturer's serial number
}

message NewKey {
  required string csid = 1;
  required string keyData = 2;
  required string proof = 7; // opaque octet string
}

message NewKeyList {
  repeated NewKey newKey = 1;
}

message Credential {
  enum CredentialType {
    UNKNOWN = 0;
    CONNECTOR = 1; 
    HOTSPOT2 = 2;
    X.509 = 3;
  }
  required CredentialType credentialType = 1;
  required string credentialOctets = 2;
}

message CredentialList {
  repeated Credential credential = 1;
}

message Wpa2Credential {
  required string ssid = 1;
  required string wpaPassphrase = 2;
  optional string macAddress =3;
}
message ConfigData {
  optional Wpa2Credential wpa2Credential = 1;
}

message privateData {
  optional DeviceDescription deviceDescription = 1;
  optional NewKeyList newKeyList = 2;
  optional CredentialList credentialList = 3;
  optional ConfigData configData = 4;
}

message TipMessage {
  // Types of TIP message PDUs
  optional M0 m0 = 0;  // optional csid list to indicate capabilities
  optional M1 m1 = 1;  // Introduction message with first key
  optional M2 m2 = 2;
  optional M3 m3 = 3;
  optional M4 m4 = 4;
}
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

1.  4Easy Setup Application

The Easy Setup service may be implemented with a variety of discovery and
connectivity mechanisms. This section provides a mapping of the protocol to
specific communication technologies.

1.  4.1Easy Setup Using NAN Active Publish

This section describes the embodiment of the Easy Setup service using Wi-Fi
Aware as the discovery mechanism and communication channel. The Wi-Fi Aware
discovery is also known as Neighbor Awareness Networking (NAN) and is a power
efficient discovery technology defined by the Wi-Fi Alliance.

The discovery of the service is based on Enrollees using NAN to publish the need
for the setup service. The M0 message is optionally included the Publish SDF
service information from the Enrollee.

The TIP authentication and configuration is mapped to NAN Service Discovery
Frames (SDF). The M1, M2, M3 and M4 messages are carried within the service
information field of the Service Descriptor Attribute (SDA) of SDFs of
subsequent follow-up messages.

### Service Definitions

This section provides a definition of the Easy Setup service interface and the
mapping of the discovery process as a NAN publish/subscribe model of
interaction.

#### Publish

-   *Service Name*

-   UTF-8 name string which is "easysetup"

-   *Service Specific Info*

-   Device Information sub-attribute: Publisher shall include the publisher
    device's information sub-attribute as defined in Table 11.

-   *Configuration Parameters*

-   Publish Type: Can be solicited or unsolicited

-   Time to Live: The instance of this publish service shall run until it is
    cancelled

-   Discovery Range: Shall be limited

-   Event Condition: Publish related event may be requested to be generated

-   NAN2 Ranging flag: NAN2 Ranging shall be Optional

#### Subscribe

-   *Service Name*

-   UTF-8 name string which is "easysetup"

-   *Configuration Parameters*

-   Subscribe Type: Shall be active subscription

-   Discovery Range: Shall be set to limited

-   Query Period: Recommend every 5 DW

-   Time to Live: The instance of this subscribe shall run until it is cancelled

-   NAN2 Ranging flag: NAN2 Ranging shall be Optional

-   *Service Response Filter*

-   Null

#### Follow-up Transmit

-   *Service Specific Info*

-   Remote Device Information sub-attribute: The forwarding node shall include
    the remote device information sub-attribute as defined in Error! Reference
    source not found.

-   *Handle*

-   Publish instance ID of the NAN Mapping Publish service instance

-   *Configuration Parameter*

-   NAN Interface Address: MAC address of the triggering NAN device

-   Requestor Instance ID: Subscribe instance ID of the triggering NAN device

1.  4.1.2NAN Active Publish Processing

**Figure 2**: Easy Setup using NAN Active Publish

1.  Enrollee is powered ON, andinitiates operation as a NAN device. The Enrollee
    actively publishes the "easysetup" service and starts sending discovery
    frames (Discovery Beacons or SDF frames).

2.  The Configurator is powered ON and initiates operation as a NAN device. The
    Configurator subscribes to the "easysetup" service. The subscription to this
    service can be triggered manually using App, or this can be notified
    automatically to user. Automatic notification requirescontinuous publishing
    of the service and subsequent notification on the discovery of a subscribing
    device.

3.  Ranging operation between Configurator and Enrollee is optional. Enrollee
    can initiate Ranging Setup by sending the Publish SDF during the next
    discovery windows. On completing the FTM based range determination,
    Configurator and Enrollee obtain the range result (Appendix B).

4.  Enrollee can send the Publish SDF during the next discovery window. Enrollee
    will be available on the entire discovery window, until he receives the
    configuration information.

-   The Publish SDF may include multiple Cipher Suite Identifiers (CSIDs) to
    indicate the supported security techniques. The format of the information
    element is as described in the section 2.4.

1.  The Configurator chooses a supported CSID from the offered list in the
    Enrollee Publish SDF.

2.  The Configurator then proceeds with the authenticated key exchange using the
    selected Cipher Suite and associated processing. The key exchange is carried
    in NAN SDF frames and consists of the M1 – M4 messages. These messages are
    carried in the NAN SDF Service Info fields as described in Section 3.

3.  Enrollee and Configurator after successful authentication process, share the
    same shared secret and have validated ownership of their peers public
    key(s).

4.  Once the Enrollee receives the configuration information, it terminates
    publishing the "easysetup" service.

5.  If the Enrollee has been configured with WPA2-Personal credentials it should
    attempt to scan and find a configured AP and securely associate.

For use with IEEE 802.11 and NAN the Pairwise SA developed by the authentication
exchange is equivalent to the PTKSA defined in the IEEE 802.11 Specification
[11mcD4.3 § 11.6.1.1.6].

Cipher Suites
=============

TIP supports flexibility in cryptographic processing by the bundling
cryptographic mechanisms into Cipher Suites. A Cipher Suite IDentifier (CSID)
identifies the Cipher Suites. Cipher Suites defined herein include:

-   CS_P256_AES_128

Implementations of this service should support the CS_P256_AES_128 cipher suite.

1.  5.1Cipher Suite CS_P256_AES_128

The CS_P256_AES_128 Cipher Suite supports 128-bit security.

1.  5.1.1CS_P256_AES_128 Base Cryptographic Algorithms

CS_P256_AES_128 uses as a basis for the processing:

-   The AES as the encryption algorithm.

-   The AES-SIV-128 mode is used for protection of the M2, M3 and M4 message
    contents. The SIV mode provides the required AEAD properties for the
    protocol.

-   When 802.11 frame protection is required using keys derived from the
    exchange, AES-CCMP-128 is used. The master key for the 802.11 processing
    shall be derived as: PMK = Hkdf("802.11pmk", sk)

-   The NIST P-256 Elliptic Curve for public key operations

-   All public keys are encoded into *keyData* attributes using Section 2.3.3 of
    SEC1 ( <http://www.secg.org/sec1-v2.pdf>).

-   SHA256 is the base hash algorithm.

-   The Hkdf() function shall be HMAC per RFC 5869, HMAC-based
    Extract-and-Expand Key Derivation Function (HKDF), May 2010, (
    <https://tools.ietf.org/html/rfc5869>)

1.  5.1.2CS_P256_AES_128 Processing Overview

An overview of the processing flow for the CS_P256_AES_128 Cipher Suite is shown
in the figure below.

\<...\>

Appendix B: NAN-based Ranging
=============================

\<...\>

1

<https://developers.google.com/protocol-buffers/>
