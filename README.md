ANSI X9.24-3-2017
Supplement
Python Source Code

Scope
=====
These files are a supplement to ANSI X9.24-3-2017 and is a set of source code that can be used as a reference implementation of the AES DUKPT algorithm and to support validation of an implementation of the AES DUKPT algorithm on a transaction-originating SCD or a receiving SCD.  AES DUKPT is used to derive transaction key(s) from an initial terminal DUKPT key based on the transaction number. Keys that can be derived include symmetric encryption/decryption keys, authentication keys, and HMAC (keyed hash message authentication code) keys.  AES DUKPT supports the derivation of AES-128, AES-192, AES-256, double length TDEA, and triple length TDEA keys from AES-128, AES-192, and AES-256 initial keys.

While the included source code contains a reference implementation of the AES DUKPT algorithm, in no way should the included source code be considered an implementation of the entirety of the requirements of the ANSI X9.24 Part 3 standard. Care must be taken to follow all requirements when deploying a complete implementation of the standard.

The included source code contains no warranty or guarantees and is considered open source.

Python Reference Implementation
============================
The included source files gives the Python source code that was used to generate the test vectors in Annex B of the standard.  In the event that it disagrees with the pseudo code in the main body of the standard, the text in the main body of the standard is considered normative.

It was developed using Python 3.4 and PyCrypto version 2.6.1, but should work with any version of Python 3.  
Information about PyCrypto can be found at https://pypi.python.org/pypi/pycrypto

The original Python source files for this 
AES DUKPT reference implementation can be found at http://x9.org/standards/x9-24-part-3-test-vectors/
