# ctoken

This is an implementation of CWT, EAT and things that are a signed CBOR Token
made up of label-value pairs.  It includes the CWT and EAT claims. Other claims
can easily be added.

This relies on [t_cose](https://github.com/laurencelundblade/t_cose) for the COSE-based signing format.  t_cose can use OpenSSL crypto
or PSA / mbed crypto. Other crypto can be added through the t_cose crypto adaptor layer..

This relies on [QCBOR](https://github.com/laurencelundblade/QCBOR) for CBOR encoding and decoding.

This code only encodes and decodes the claims in the right CBOR format. It doesn't
create them as that is very dependent on the operating environment and such.

![Cake Diagram](https://github.com/laurencelundblade/ctoken/blob/master/ctoken_cake-diagram.png)

## Standards Status

CWT is a stable IETF standard described in [RFC 8392](https://tools.ietf.org/html/rfc8392). It is not expected to change,
but new claims will be added to the IANA CWT registry.

EAT is an up and coming standard in development in the RATS working group. It
is in flux and parts of it are likely to change.  See [draft-ietf-rats-eat-02](https://tools.ietf.org/html/draft-ietf-rats-eat-02)

PSA Initial Attestation is also implemented here. It is a derivative of EAT and is also proposed
as an IETF standard. It may also change. See [draft-tschofenig-rats-psa-token-04](https://tools.ietf.org/html/draft-tschofenig-rats-psa-token-04)

## Code Status

This is a refactoring of the initial attestation code that was written for trustedfirmware.org.
That code is well tested so most of this code is also well tested. However the 
refactoring is recent, so it is not well documented, fully organized or tested. The
refactoring is mostly at the surface level, so the core complex parts should still be
in good shape.

**warning** The interface for ctoken may change (QCBOR and t_cose are stable; their
interfaces won't change).






