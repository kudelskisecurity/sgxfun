#!/usr/bin/env python
"""
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

Copyright (c) 2016 Nagravision S.A.
"""

from binascii import hexlify
from struct import unpack
import struct
import sys

EXPECTED_LEN = 1116

"""
as per linux-sgx/common/inc/sgx_quote'.h's 

typedef struct _quote_t
{
    uint16_t            version;        /* 0   */
    uint16_t            sign_type;      /* 2   */
    sgx_epid_group_id_t epid_group_id;  /* 4   */
    sgx_isv_svn_t       qe_svn;         /* 8   */
    uint8_t             reserved[6];    /* 10  */
    sgx_basename_t      basename;       /* 16  */
    sgx_report_body_t   report_body;    /* 48  */
    uint32_t            signature_len;  /* 432 */
    uint8_t             signature[];    /* 436 */
} sgx_quote_t;

and as per linux-sgx/external/epid/inc/epid_types.h's

typedef struct EpidSignature {
  BasicSignature sigma0;  ///< basic signature (GCM'd in a quote)
  OctStr32 rl_ver;        ///< revocation list version number (4)
  OctStr32 n2;            ///< number of entries in SigRL (4)
  NRProof sigma[1];       ///< array of non-revoked proofs (flexible array)
} EPIDSignature;

and as per libsgx_qe.signed.so

"""

EXPECTED_QUOTELEN = 1116
EXPECTED_SIGLEN = 680
EXPECTED_SIGENCLEN = 360

def xlf(s):
    return hexlify(s).decode('utf-8')

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print('usage: %s quote' % sys.argv[0])
        sys.exit(1)

    with open(sys.argv[1], 'rb') as f:
        data = f.read()

    if len(data) != EXPECTED_LEN: 
        print('Unexpected quote length (%d vs %d)' % (len(data),\
            EXPECTED_QUOTELEN))

    version = struct.unpack('<H',data[:2])[0]
    sign_type = struct.unpack('<H', data[2:4])[0]
    epid_group_id = data[4:8]
    isv_svn = data[8:10]
    reserved = data[10:16]
    basename = data[16:48]
    report = data[48:432]
    siglen = struct.unpack('<I', data[432:436])[0]
    if siglen != EXPECTED_SIGLEN:
        print('Unexpected siglen (%d vs. %d)' % (sigenclen,\
            EXPECTED_SIGLEN))

    rsaenc = data[436:724]
    iv = data[724:736]
    sigenclen = struct.unpack('<I', data[736:740])[0]
    # check clen
    if sigenclen != EXPECTED_SIGENCLEN:
        print('Unexpected sigenclen (%d vs. %s)' % (sigenclen,\
            EXPECTED_SIGENCLEN))
    sigenc = data[740:740+sigenclen]
    tag = data[740+sigenclen:740+sigenclen+16]
    rl_verenc = data[1092:1096]
    n2enc = data[1096:1100]

    s= \
        '%20s\t%d\n' % ('version', version) +\
        '%20s\t%d\n' % ('sign_type', sign_type) +\
        '%20s\t%s\n' % ('epid_group_id', xlf(epid_group_id)) +\
        '%20s\t%s\n' % ('isv_svn', xlf(isv_svn)) +\
        '%20s\t%s\n' % ('reserved', xlf(reserved)) +\
        '%20s\t%s\n' % ('basename', xlf(basename)) +\
        '%20s\t%s\n' % ('report', xlf(report)) +\
        '%20s\t%d\n' % ('siglen', siglen) +\
        '%20s\t%s\n' % ('rsaenc', xlf(rsaenc)) +\
        '%20s\t%s\n' % ('iv', xlf(iv)) +\
        '%20s\t%d\n' % ('sigenclen', sigenclen) +\
        '%20s\t%s\n' % ('sigenc', xlf(sigenc)) +\
        '%20s\t%s\n' % ('tag', xlf(tag)) +\
        '%20s\t%s\n' % ('rl_verenc', xlf(rl_verenc)) +\
        '%20s\t%s\n' % ('n2enc', xlf(n2enc))

    print(s)
    
