# sgxfun

Utilities and documentation for Intel SGX.

* `parse_enclave.py` takes an enclave in binary form and extracts some
  metadata

* `parse_quote.py` takes a quote in binary form and extracts its fields

* `EPID.md` documents the used of EPID anonymous group signatures

* `GETQUOTE.md` documents the quote format and cryptographic scheme
  behind, as implemented in the quoting enclave

## Extracting information from an enclave

### SIGSTRUCT

### ECALLs

## Extracting information from a quote

 * Can be intercepted at network level

 * Provides information about the running enclave and the security
   level of the platform (cpusvn, isvsvn, debug mode).

## Extracting information from the remote attestattion handshake (wip)

 * Can be intercepted at network level

 * Contains quote.

## Intellectual property

Copyright (c) 2016, Nagravision S.A.

Code under GPLv3
