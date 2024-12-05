## XMSS Reference Code with HORS Integration
[![Build Status](https://travis-ci.org/XMSS/xmss-reference.svg?branch=master)](https://travis-ci.org/XMSS/xmss-reference)

This repository extends the reference implementation of [RFC 8391: _"XMSS: eXtended Merkle Signature Scheme"_](https://tools.ietf.org/html/rfc8391) with an integration of the HORS mechanism to achieve stateless operation.

The integration aims to enhance the usability of XMSS by eliminating the need for state management in the signature process while preserving quantum resistance.

### New Features
- **Stateless Operation**: By integrating HORS, this implementation avoids the complexities of state management inherent in traditional XMSS.
- All parameter sets as defined in RFC 8391 are supported.
- Preserves compatibility with the original implementation for cross-validation.

### Dependencies
For the SHA-2 hash functions (i.e. SHA-256 and SHA-512), we rely on OpenSSL. Make sure to install the OpenSSL development headers. On Debian-based systems, this is achieved by installing the OpenSSL development package `libssl-dev`.
