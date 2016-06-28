
The quoting enclave (QE) creates a quote using the EPID scheme and an
undocumented chain of crypto operations.  This is an attempt to document
and assess this part of the SGX attestation mechanism.

The main reference is the function `get_quote()` in the quoting enclave,
as well as (including and not limited to)
* `linux-sgx/common/inc/sgx_quote.h`
* `linux-sgx/common/inc/sgx_report.h`
* `linux-sgx/external/epid/inc/epid_types.h`
* https://eprint.iacr.org/2009/095
* http://www.shoup.net/papers/verenc.pdf

**Disclaimer**: This is not a complete specs, and may even be totally
wrong. Use at your own risk.


