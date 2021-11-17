[ctoken](https://github.com/laurencelundblade/ctoken/blob/master/ctoken-logo.png?raw=true)
 
*Ctoken* is a library that implementats CWT, EAT and UCCS:

* [RFC8932](https://tools.ietf.org/html/rfc8943) CBOR Web Token, the basis for tokens
* [draft-ietf-rats-eat](https://datatracker.ietf.org/doc/html/draft-ietf-rats-eat) Entity Attestation Token, additions for attestation
* [draft-ietf-rats-uccs](https://datatracker.ietf.org/doc/html/draft-ietf-rats-uccs) Unsigned tokens for when the transport provides security
* [draft-tschofenig-rats-psa-token](https://datatracker.ietf.org/doc/html/draft-tschofenig-rats-psa-token) Extensions to EAT for ARM's Platform Security Architecture

These define a *token* format that is a list of label-value pairs called *claims*. 
They are usually signed with public key crypto using the COSE format.

This code only encodes and decodes the claims in the CBOR format. It doesn't
create them as that is very dependent on the operating environment and such.

This relies on [t_cose](https://github.com/laurencelundblade/t_cose) for the COSE-based signing format.  t_cose can use OpenSSL crypto
or MBed TLS crypto. Other crypto can be added through the t_cose crypto adaptor layer..

This relies on [QCBOR](https://github.com/laurencelundblade/QCBOR) for CBOR encoding and decoding.

See also [xclaim](https://github.com/laurencelundblade/xclaim), a command line tool for creating
and displaying CWT, EAT and UCCS tokens. It is implemented using ctoken.

![Cake Diagram](https://github.com/laurencelundblade/ctoken/blob/master/ctoken_cake-diagram.png)

## Claims Supported

EAT is an extension to CWT, so ctoken supports all the CWT claims. CWT was
created for authentication, not attestation, so some of the CWT claims don't 
apply directly for attestation.

### CWT Claims
The descriptions of these are in JWT. CWT is a CBOR version of JWT. 
Detailed descriptions of these claims are in [RFC7915](https://tools.ietf.org/html/rfc7915).

* Issuer — Principle that issued the token (authentication)
* Subject — The subject to which the claims apply (authentication)
* Audience — The intended recipients (authentication)
* IAT — Time stamp for when the token was created (attestation and authentication)
* CTI — Unique ID for token. Like a token serial number (attestation and authentication)
* Expiration — Time stamp after which this token is not valid (attestation and authentication)
* Not before — Time stamp before which this token is not valid (attestation and authentication)

### EAT Claims
* Nonce — Unique value from server to guarantee freshness
* UEID — a unique device identifier (similar to a serial number)
* OEM ID — Identifier of the manufacturer of the device
* HW Version — A string giving the version number of chip, circuit board or device hardware
* secboot — indicates if device booted securely
* debugstat — Whether or not debug facilities are enabled or not
* uptime — Number of seconds since the device started
* seclevel — A rough characteriziation of the type of security implemented (SW, TEE, HW)
* Submodules — Not a claim per-se, a way to group claims
* Profile — Reference to a document that narrows the definition of a token for a specific use case
* Itended Use — A rough characterization of the intended use of the token

Other claims are defined or in the process of being defined, but not yet implemented.

### PSA Token Claims
* Client ID —
* Implementation ID —
* Lifecycle —
* Certification Reference —
* Measurement —

### Generic data types for claims
The ctoken library has some general functions for general data types. The values
of many claims are one of these, so these are very useful. All that's needed 
beyond calling this is the label / key that identifies the particular claim.

* Signed integers
* Unsigned integers
* UTF-8 text strings
* Byte strings
* Booleans
* Double floating-point
* Maps — primarily opening / closing
* Arrays — primarily opening / closing

## Code Size

This implementation is intended for embedded use so code size and memory 
use are kept small. For the most part it is a very thin layer on top of QCBOR and t_cose.
A lot of the functions are inline and don't really add any code size.
The largest chunk of code is for EAT submodules.

## Standards Status

CWT is a stable IETF standard described in [RFC 8392](https://tools.ietf.org/html/rfc8392). It is not expected to change,
but new claims will be added to the IANA CWT registry.

EAT is an up and coming standard in development in the RATS working group. It
is in flux and parts of it are likely to change.  See [draft-ietf-rats-eat-08](https://tools.ietf.org/html/draft-ietf-rats-eat-08)

UCCS is a CWT that is not signed. See [draft-birkholz-rats-uccs-02](https://tools.ietf.org/html/draft-birkholz-rats-uccs-02)

PSA Token is also implemented here. It is a derivative of EAT and is also proposed
as an IETF standard. It may also change. See [draft-tschofenig-rats-psa-token-04](https://tools.ietf.org/html/draft-tschofenig-rats-psa-token-04)

## Code Status

This is a refactoring of the initial attestation code that was written for trustedfirmware.org.
That code is well tested so most of this code is also well tested.
