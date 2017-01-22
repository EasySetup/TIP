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
inclusion of configuration information to support out-of-box setup.

 
