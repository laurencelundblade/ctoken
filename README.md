# ctoken

This is an implementation of CWT, EAT and things that are a signed CBOR Token
made up of label-value pairs.  It includes the CWT and EAT claims. Other claims
can easily be added.

This relies to t_cose for the COSE-based signing format.  t_cose can use OpenSSL crypto
or PSA / mbed crypto. Other crypto can be added.

This relies on QCBOR for CBOR encoding and decoding.

## Code Status

This is a refactoring of the initial attestation code that was written for trustedfirmware.org.
That code is well tested so most of this code is also well tested. However the 
refactoring is recent, so it is not well documented, fully organized or tested. The
refactoring is mostly at the surface level, so the core complex parts should still be
in good shape.




