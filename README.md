# sgxfun

Utilities and documentation for Intel SGX.

* Our [paper](paper/) 

* [parse_enclave.py](parse_enclave.py) takes an enclave in binary form and extracts some
  metadata

* [parse_quote.py](parse_quote.py) takes a quote in binary form and extracts its fields

* [parse_sealed.py](parse_sealed.py) takes a sealed blob of data and extracts its fields

* [GETQUOTE.md](GETQUOTE.md) documents the quote format and cryptographic scheme
  behind, as implemented in the quoting enclave


## Extracting information from an enclave

Usage: `./parse_enclave.py <enclave.signed.dll|enclave.signed.so>`

### SIGSTRUCT

SIGSTRUCT contains information about the enclave, including hash and
signature, and most of its fields are cryptographically signed, thus
avoiding a modified enclave to run on the platform.

The data structure is contained on signed enclave files (.dll and .so),
and it's also used on runtime when initializing the enclave. 

The `parse_enclave.py` output, when SIGSTRUCT is found, can reveal
some useful data about the enclave:

 * VENDOR: 00008086h for Intel enclaves; 00000000h otherwise
 * MODULUS: The signer's public key
 * ENCLAVEHASH: MRENCLAVE of this enclave (includes not only the raw
   data, but a log of the enclave memory initialization process)
 * ATTRIBUTES: Enclave attributes that must be set
 * ATTRIBUTEMASK: Filter mask for ATTRIBUTES; bits zeroed here are
   enforced to be disabled during initialization.
 * ISVPRODID and ISVSVN: Allows to identify different security releases
   (ISVSVN) of the same product (ISVPRODID) from the same vendor.

For additional information, check SIGSTRUCT entry on the Intel SGX
Programming Reference (Section 2.13).

### Signature Verification

RSA parameters from SIGSTRUCT are verified at the beginning of 
`parse_enclave.py` execution.

### ECALLs

ECALLs are the enclave entry points to the trusted zone: only these
memory positions can be called from the outside. In practice, they
behave as functions that can be invoked, receiving parameters and
returning values, as any other function. 

Understading where are these ECALLs located and what's their
functionality is essential when reversing an enclave, as they will
reveal the attack surface and the functionality exposed. Special
attention must be paid to debug and obsolete interfaces that could
be present by mistake.

At the moment, the ECALLs table is located through a small set of
heuristics not 100% reliable (known to fail in latest release of 
the PSW, 1.6 at the moment of writing).

When found, the table looks like this:

```
# ECALLs table found at 0x7b580
                   0    vaddr: 0x670
                   1    vaddr: 0xd20
```

The example contains the entry points found at a sample enclave and
reveals to entry points at Virtual Addresses 0x0670 and 0x0d20.
These entry points can serve as the beginning of a reverse engineering
session.


## Extracting information from a quote

Usage: `./parse_quote.py <quote.bin>`

Quotes are sent from the enclave to the software vendor server while
the remote attestation process. Together with the signature, they
include a report of the enclave running.

When intercepted, they can provide information about what enclave is
running, which key was used to sign it or wether they are running in
debug mode or not. They also carry the security revisions of the
platform (CPUSVN and ISVSVN).

## Extracting information from a sealed blob

Usage: `./parse_sealed.py <sealed.bin>`

### Sealing policy

The policy used to derive the sealing key determines which enclaves
will be able to decrypt the blob. Two possible values:

  * MRENCLAVE: The key derivation function includes the hash of the
    enclave, and only the enclave who performed the operation,
    running on the same machine and signed by the same signer, can
    unseal it.

  * MRSIGNER: The key derivation function does not includes the hash
    of the enclave. Other enclaves, running on the same machine and
    signed by the same signer, can unseal it.


### Additional authenticated data

Sealed blobs can carry additional authenticated data, that is not
encrypted but only authenticated. This piece of data can reveal useful
information regarding the sealed blob.


Copyright (c) 2016, Nagravision S.A.

Code under GPLv3
