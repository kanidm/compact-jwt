Compact JWT
===========

Json Web Tokens (JWT) are a popular method for creating signed transparent tokens that can be verified
by clients and servers. They are enshrined in standards like OpenID Connect which causes them to
be a widespread and required component of many modern web authentication system.

JWT and Json Web Signature (JWS) however have a long track record of handling issues, which have
led to security issues. This library will not be a complete implementation of JWT/JWS, instead
focusing on a minimal subset that can be secured and audited for correctness more closely within
a limited set of use cases.

When should I use this library?
-------------------------------

If you wish to create ECDSA signed JWT tokens, or verify ECDSA signed JWT tokens, this library is for you.

If you are implementing OIDC as a relying party or authorisation server, this library is for you.

If you want to use HMAC signatures, have a full JWS implementation, or have the non-compact (JSON)
serialisation support, this library is not what you want.

Why another JWT library?
------------------------

There are already many other libraries for JWT on crates.io however they each have a limitation
or design that conflicts with the project goals in Kanidm. Examples are:

* Incorrect Implementations - There are a number of JWT libraries in Rust that are incorrect to the RFC or do not have RFC vector tests
* Ring as the sole cryptographic provider - we need to use OpenSSL
* Only supporting RSA/Weak cryptographic algos - We want to use ECDSA
* Full JWS implementation - As mentioned, JWS has a number of sharp edges like alg=none

As a result, nothing "fit" what we wanted, so we are making another library.


