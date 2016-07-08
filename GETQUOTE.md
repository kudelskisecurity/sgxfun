# Quoting cryptography mechanisms

The quoting enclave (QE) creates a quote using the EPID scheme and an
undocumented chain of crypto operations.  This is an attempt to document
and assess this part of the SGX attestation mechanism.

The main reference is the function `get_quote()` in the quoting enclave,
and also
* `linux-sgx/common/inc/sgx_quote.h`
* `linux-sgx/common/inc/sgx_report.h`
* `linux-sgx/external/epid/inc/epid_types.h`
* `linux-sgx/psw/ae/qe/quoting_enclave.edl`
* `linux-sgx/blob/master/common/inc/internal/se_quote_internal.h`
* https://eprint.iacr.org/2009/095
* http://www.shoup.net/papers/verenc.pdf
* and more...

**Disclaimer**: This is not a complete specs, and may even be totally
wrong. Use at your own risk.

Given a report, a nonce, and a signatures revocation list, the QE generates a
quote as described below. For simplicity, we describe the case when the
revocation list is empty.


## EPID signing and basic quote generation

Given a group key, private key (sealed), and a signature revocation
list, generate a `quote_t` structure, including an EPID signature:

```
typedef struct _quote_t
{
    uint16_t            version;      /* 0   version of the structure */
    uint16_t            sign_type;    /* 2   linkable or unlinkable */
    sgx_epid_group_id_t epid_group_id;/* 4   EPID group ID */
    sgx_isv_svn_t       qe_svn;       /* 8   SVN */
    uint8_t             reserved[6];  /* 10  for alignment */
    sgx_basename_t      basename;     /* 16  quote base name */
    sgx_report_body_t   report_body;  /* 48  */
    uint32_t            signature_len;/* 432 */
    uint8_t             signature[];  /* 436 */
} sgx_quote_t;
```

The `sgx_quote_t` structure is described in the SDK documentation.
The `signature[]` is the actual EPID signature, composed of

several elements:

```
typedef struct EpidSignature {
  BasicSignature sigma0;  ///< basic signature (GCM'd in a quote)
  OctStr32 rl_ver;        ///< revocation list version number (4)
  OctStr32 n2;            ///< number of entries in SigRL (4)
  NRProof sigma[1];       ///< array of non-revoked proofs (flexible array)
} EPIDSignature;

```

The actual quote, however, will contain more data than the `436+signature_len` bytes defined in the `quote_t` structure.

## RSA-OAEP key encapsulation

The QE generates a random 16-byte key and a random 12-byte IV for AES-GCM. 

The AES-GCM key is encrypted using RSA-OAEP-SHA-256, using a 2048-bit
public key. The QE then stores the 256-byte ciphertext, followed by the
32-byte SHA-256 hash of the key (as weak integrity check?).

## AES-GCM encryption

The EPID signature is encrypted in three parts, from a state `pState`
initialized using the key and IV randomly chosen before:

* `c1 = AES-GCM(sigma0, pState)`, a 336-byte ciphertext of the actual EPID signature
* `c2 = AES-GCM(rl_ver, pState)`, a 4-byte ciphertext of the revocation list version number
* `c3 = AES-GCM(n2, pState)`, a 4-byte ciphertext of the number of entries in the revocation list

The 16-byte tag then follows `c3`.

## Hashing

Two SHA-256 are computed:

* `SHA-256(nonce(16) || quote_t(436) || IV(16) || len(c1||c2||c3)(4)
  || c1 || c2 || c3)`, used a report data in the subsequent report
  generation

* `SHA-256(sig_rl(variable))`, whose ECDSA signature is verified using
  the public key available


## Quote final format

With hex offsets, and data byte size:

```
[start of quote_t struct]
000: version (2) 
002: sign_type (2)
004: epid_group_id (4)
008: qe_vn (2)
00a: reserved (6)
00f: basename (32)
030: report_body (384)
1b0: signature_len (4)
[start of se_encrypted_sign struct]
[start of se_wrap_key_t struct]
1b4: RSA-encrypted AES-GCM key (256)
2b4: SHA-256 hash of the AES-GCM key (32)
[end of se_wrap_key_t struct]
2d4: AES-GCM IV (12)
2e0: ciphertext size (4)
2e4: encrypted basic signature sigma0 (352)
444: encrypted revocation list version rl_ver (4)
448: encrypted number of revoked keys (4)
44c: GCM authentication tag (16)
[end of se_encrypted_sign struct]
[end of quote_t struct]
```

If the revocation list is not empty, each 160-byte non-revoked proof is
AES-GCM encrypted and written to the quote, eventually followed by
the tag of all encrypted data.

Proofs follow the following structure:

```
typedef struct NrProof {
  G1ElemStr T;    ///< an element in G1
  FpElemStr c;    ///< an integer between [0, p-1]
  FpElemStr smu;  ///< an integer between [0, p-1]
  FpElemStr snu;  ///< an integer between [0, p-1]
} NRProof;
```
