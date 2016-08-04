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
import sys

"""
as per linux-sgx/common/inc/sgx_tseal.h's

typedef struct _sealed_data_t
{
    sgx_key_request_t  key_request;       /* 00: The key request used to obtain the sealing key */
    uint32_t           plain_text_offset; /* 64: Offset within aes_data.playload to the start of the optional additional MAC text */
    uint8_t            reserved[12];      /* 68: Reserved bits */
    sgx_aes_gcm_data_t aes_data;          /* 80: Data structure holding the AES/GCM related data */
} sgx_sealed_data_t;

typedef struct _aes_gcm_data_t
{
    uint32_t  payload_size;                   /*  0: Size of the payload which includes both the encrypted data and the optional additional MAC text */
    uint8_t   reserved[12];                   /*  4: Reserved bits */
    uint8_t   payload_tag[SGX_SEAL_TAG_SIZE]; /* 16: AES-GMAC of the plain text, payload, and the sizes */
    uint8_t   payload[];                      /* 32: The payload data which includes the encrypted data followed by the optional additional MAC text */
} sgx_aes_gcm_data_t

and as per linux-sgx/common/inc/sgx_key.h's

typedef struct _key_request_t
{
   uint16_t          key_name;        /* Identifies the key required */
   uint16_t          key_policy;      /* Identifies which inputs should be used in the key derivation */
   sgx_isv_svn_t     isv_svn;         /* Security Version of the Enclave */
   uint16_t          reserved1;       /* Must be 0 */
   sgx_cpu_svn_t     cpu_svn;         /* Security Version of the CPU */
   sgx_attributes_t  attribute_mask;  /* Mask which ATTRIBUTES Seal keys should be bound to */
   sgx_key_id_t      key_id;          /* Value for key wear-out protection */
   sgx_misc_select_t misc_mask;       /* Mask what MISCSELECT Seal keys bound to */
   uint8_t           reserved2[SGX_KEY_REQUEST_RESERVED2_BYTES];  /* Struct size is 512 bytes */
} sgx_key_request_t;
"""

KEY_NAME = {
    0: 'LICENSE',
    1: 'PROVISION',
    2: 'PROVISION_SEAL',
    3: 'REPORT',
    4: 'SEAL'
}

KEY_POLICY = {
    1: 'MRENCLAVE',
    2: 'MRSIGNER'
}

class SealedData(object):
    def __init__(self, data):
        self.key_request = data[0:512] # there's a missmatch between
                           # the comments and the code.
        self.plain_text_offset, = unpack("<I", data[512:516])
        self.reserved = data[516:528]
        self.aes_data = data[528:]

class AESGCMData(object):
    def __init__(self, data):
        self.payload_size, = unpack("<I", data[0:4])
        self.reserved = data[4:16]
        self.payload_tag = data[16:32]
        self.payload = data[32:]

class KeyRequest(object):
    def __init__(self, data):
        self.key_name, = unpack('<H', data[0:2])
        self.key_policy, = unpack('<H', data[2:4])
        self.isv_svn, = unpack('<H', data[4:6])
        self.reserved1 = data[6:8]
        self.cpu_svn = data[8:24]
        self.attribute_mask = data[24:40]
        self.key_id = data[40:72]
        self.misc_mask = data[72:76]
        self.reserved2 = data[76:436]


if __name__ == '__main__':
    with open(sys.argv[1], 'rb') as f:
        data = f.read()

    print('length: %d bytes' % len(data))
    # Parse sgx_sealed_data_t
    sealed_data = SealedData(data)
    # parse sgx_key_request_t
    key_request = KeyRequest(sealed_data.key_request)
    # Parse sgx_aes_gcm_data_t
    aesgcm_data = AESGCMData(sealed_data.aes_data)

    print('\n### key request ###\n' \
        '%20s\t%d (%s)\n' % ('key_request', key_request.key_name,
                     KEY_NAME[key_request.key_name]) +\
        '%20s\t%d (%s)\n' % ('key_policy', key_request.key_policy,
                       KEY_POLICY[key_request.key_policy]) +\
        '%20s\t%d\n' % ('isv_svn', key_request.isv_svn) +\
        '%20s\t%s\n' % ('cpu_svn', hexlify(key_request.cpu_svn)) +\
        '%20s\t%s\n' % ('attribute_mask', hexlify(key_request.attribute_mask)) +\
        '%20s\t%s\n' % ('key_id', hexlify(key_request.key_id)) +\
        '%20s\t%s\n' % ('misc_mask', hexlify(key_request.misc_mask)) +\
        '\n### aesgcm data ###\n' +\
        '%20s\t%d bytes\n' % ('ciphertext length', sealed_data.plain_text_offset) +\
        '%20s\t%d bytes\n' % ('aad length', aesgcm_data.payload_size - sealed_data.plain_text_offset) +\
        '%20s\t%s\n' % ('tag', hexlify(aesgcm_data.payload_tag)) +\
        '%20s\t%s\n' % ('ciphertext', hexlify(aesgcm_data.payload[:sealed_data.plain_text_offset])) +\
        '%20s\t%s\n' % ('aad', hexlify(aesgcm_data.payload[sealed_data.plain_text_offset:])))
