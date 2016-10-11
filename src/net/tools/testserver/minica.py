# Copyright (c) 2012 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import asn1
import datetime
import hashlib
import itertools
import os
import time

GENERALIZED_TIME_FORMAT = "%Y%m%d%H%M%SZ"

OCSP_STATE_GOOD = 1
OCSP_STATE_REVOKED = 2
OCSP_STATE_INVALID_RESPONSE = 3
OCSP_STATE_UNAUTHORIZED = 4
OCSP_STATE_UNKNOWN = 5
OCSP_STATE_TRY_LATER = 6
OCSP_STATE_INVALID_RESPONSE_DATA = 7
OCSP_STATE_MISMATCHED_SERIAL = 8

OCSP_DATE_VALID = 1
OCSP_DATE_OLD = 2
OCSP_DATE_EARLY = 3
OCSP_DATE_LONG = 4

OCSP_PRODUCED_VALID = 1
OCSP_PRODUCED_BEFORE_CERT = 2
OCSP_PRODUCED_AFTER_CERT = 3

# This file implements very minimal certificate and OCSP generation. It's
# designed to test revocation checking.

def RandomNumber(length_in_bytes):
  '''RandomNumber returns a random number of length 8*|length_in_bytes| bits'''
  rand = os.urandom(length_in_bytes)
  n = 0
  for x in rand:
    n <<= 8
    n |= ord(x)
  return n


def ModExp(n, e, p):
  '''ModExp returns n^e mod p'''
  r = 1
  while e != 0:
    if e & 1:
      r = (r*n) % p
    e >>= 1
    n = (n*n) % p
  return r

# PKCS1v15_SHA256_PREFIX is the ASN.1 prefix for a SHA256 signature.
PKCS1v15_SHA256_PREFIX = '3031300d060960864801650304020105000420'.decode('hex')

class RSA(object):
  def __init__(self, modulus, e, d):
    self.m = modulus
    self.e = e
    self.d = d

    self.modlen = 0
    m = modulus
    while m != 0:
      self.modlen += 1
      m >>= 8

  def Sign(self, message):
    digest = hashlib.sha256(message).digest()
    prefix = PKCS1v15_SHA256_PREFIX

    em = ['\xff'] * (self.modlen - 1 - len(prefix) - len(digest))
    em[0] = '\x00'
    em[1] = '\x01'
    em += "\x00" + prefix + digest

    n = 0
    for x in em:
      n <<= 8
      n |= ord(x)

    s = ModExp(n, self.d, self.m)
    out = []
    while s != 0:
      out.append(s & 0xff)
      s >>= 8
    out.reverse()
    return '\x00' * (self.modlen - len(out)) + asn1.ToBytes(out)

  def ToDER(self):
    return asn1.ToDER(asn1.SEQUENCE([self.m, self.e]))


def Name(cn = None, c = None, o = None):
  names = asn1.SEQUENCE([])

  if cn is not None:
    names.children.append(
      asn1.SET([
        asn1.SEQUENCE([
          COMMON_NAME, cn,
        ])
      ])
    )

  if c is not None:
    names.children.append(
      asn1.SET([
        asn1.SEQUENCE([
          COUNTRY, c,
        ])
      ])
    )

  if o is not None:
    names.children.append(
      asn1.SET([
        asn1.SEQUENCE([
          ORGANIZATION, o,
        ])
      ])
    )

  return names


# The private key and root certificate name are hard coded here:

# This is the private key
KEY = RSA(0x00a71998f2930bfe73d031a87f133d2f378eeeeed52a77e44d0fc9ff6f07ff32cbf3da999de4ed65832afcb0807f98787506539d258a0ce3c2c77967653099a9034a9b115a876c39a8c4e4ed4acd0c64095946fb39eeeb47a0704dbb018acf48c3a1c4b895fc409fb4a340a986b1afc45519ab9eca47c30185c771c64aa5ecf07d,
          3,
          0x6f6665f70cb2a9a28acbc5aa0cd374cfb49f49e371a542de0a86aa4a0554cc87f7e71113edf399021ca875aaffbafaf8aee268c3b15ded2c84fb9a4375bbc6011d841e57833bc6f998d25daf6fa7f166b233e3e54a4bae7a5aaaba21431324967d5ff3e1d4f413827994262115ca54396e7068d0afa7af787a5782bc7040e6d3)

# And the same thing in PEM format
KEY_PEM = '''-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQCnGZjykwv+c9AxqH8TPS83ju7u1Sp35E0Pyf9vB/8yy/PamZ3k
7WWDKvywgH+YeHUGU50ligzjwsd5Z2UwmakDSpsRWodsOajE5O1KzQxkCVlG+znu
60egcE27AYrPSMOhxLiV/ECftKNAqYaxr8RVGaueykfDAYXHccZKpezwfQIBAwKB
gG9mZfcMsqmiisvFqgzTdM+0n0njcaVC3gqGqkoFVMyH9+cRE+3zmQIcqHWq/7r6
+K7iaMOxXe0shPuaQ3W7xgEdhB5XgzvG+ZjSXa9vp/FmsjPj5UpLrnpaqrohQxMk
ln1f8+HU9BOCeZQmIRXKVDlucGjQr6eveHpXgrxwQObTAkEA2wBAfuduw5G0/VfN
Wx66D5fbPccfYFqLM5LuTimLmNqzK2gIKXckB2sm44gJZ6wVlumaB1CSNug2LNYx
3cAjUwJBAMNUo1hbI8ugqqwI9kpxv9+2Heea4BlnXbS6tYF8pvkHMoliuxNbXmmB
u4zNB5iZ6V0ZZ4nvtUNo2cGr/h/Lcu8CQQCSACr/RPSCYSNTj948vya1D+d+hL+V
kbIiYfQ0G7Jl5yIc8AVw+hgE8hntBVuacrkPRmaviwwkms7IjsvpKsI3AkEAgjhs
5ZIX3RXHHVtO3EvVP86+mmdAEO+TzdHOVlMZ+1ohsOx8t5I+8QEnszNaZbvw6Lua
W/UjgkXmgR1UFTJMnwJBAKErmAw21/g3SST0a4wlyaGT/MbXL8Ouwnb5IOKQVe55
CZdeVeSh6cJ4hAcQKfr2s1JaZTJFIBPGKAif5HqpydA=
-----END RSA PRIVATE KEY-----
'''

# Root certificate CN
ISSUER_CN = "Testing CA"

# All certificates are issued under this policy OID, in the Google arc:
CERT_POLICY_OID = asn1.OID([1, 3, 6, 1, 4, 1, 11129, 2, 4, 1])

# These result in the following root certificate:
# -----BEGIN CERTIFICATE-----
# MIIBzTCCATagAwIBAgIBATANBgkqhkiG9w0BAQsFADAVMRMwEQYDVQQDEwpUZXN0aW5nIENBMB4X
# DTEwMDEwMTA2MDAwMFoXDTMyMTIwMTA2MDAwMFowFTETMBEGA1UEAxMKVGVzdGluZyBDQTCBnTAN
# BgkqhkiG9w0BAQEFAAOBiwAwgYcCgYEApxmY8pML/nPQMah/Ez0vN47u7tUqd+RND8n/bwf/Msvz
# 2pmd5O1lgyr8sIB/mHh1BlOdJYoM48LHeWdlMJmpA0qbEVqHbDmoxOTtSs0MZAlZRvs57utHoHBN
# uwGKz0jDocS4lfxAn7SjQKmGsa/EVRmrnspHwwGFx3HGSqXs8H0CAQOjLzAtMBIGA1UdEwEB/wQI
# MAYBAf8CAQAwFwYDVR0gBBAwDjAMBgorBgEEAdZ5AgQBMA0GCSqGSIb3DQEBCwUAA4GBAHJJigXg
# ArH/E9n3AilgivA58hawSRVqiTHHv7oAguDRrA4zC8IvsL6b/6LV7nA3KWM0OUSZSGE3zQb9UlB2
# nNYsPMdv0Ls4GuOzVfy4bnQXqMWIflRw9L5Z5KH8Vu5U3ohoOUCfWN1sYMoeS9/22K9xtRsDPS+d
# pQo7Q6ZoOo8o
# -----END CERTIFICATE-----

# If you update any of the above, you can generate a new root by running this
# file as a script.


# Various OIDs

AIA_OCSP = asn1.OID([1, 3, 6, 1, 5, 5, 7, 48, 1])
AUTHORITY_INFORMATION_ACCESS = asn1.OID([1, 3, 6, 1, 5, 5, 7, 1, 1])
BASIC_CONSTRAINTS = asn1.OID([2, 5, 29, 19])
CERT_POLICIES = asn1.OID([2, 5, 29, 32])
COMMON_NAME = asn1.OID([2, 5, 4, 3])
COUNTRY = asn1.OID([2, 5, 4, 6])
HASH_SHA1 = asn1.OID([1, 3, 14, 3, 2, 26])
OCSP_TYPE_BASIC = asn1.OID([1, 3, 6, 1, 5, 5, 7, 48, 1, 1])
ORGANIZATION = asn1.OID([2, 5, 4, 10])
PUBLIC_KEY_RSA = asn1.OID([1, 2, 840, 113549, 1, 1, 1])
SHA256_WITH_RSA_ENCRYPTION = asn1.OID([1, 2, 840, 113549, 1, 1, 11])


def MakeCertificate(
    issuer_cn, subject_cn, serial, pubkey, privkey, ocsp_url = None):
  '''MakeCertificate returns a DER encoded certificate, signed by privkey.'''
  extensions = asn1.SEQUENCE([])

  # Default subject name fields
  c = "XX"
  o = "Testing Org"

  if issuer_cn == subject_cn:
    # Root certificate.
    c = None
    o = None
    extensions.children.append(
      asn1.SEQUENCE([
        BASIC_CONSTRAINTS,
        True,
        asn1.OCTETSTRING(asn1.ToDER(asn1.SEQUENCE([
          True, # IsCA
          0, # Path len
        ]))),
      ]))

  if ocsp_url is not None:
    extensions.children.append(
      asn1.SEQUENCE([
        AUTHORITY_INFORMATION_ACCESS,
        # There is implicitly a critical=False here. Since false is the default,
        # encoding the value would be invalid DER.
        asn1.OCTETSTRING(asn1.ToDER(asn1.SEQUENCE([
          asn1.SEQUENCE([
            AIA_OCSP,
            asn1.Raw(asn1.TagAndLength(0x86, len(ocsp_url)) + ocsp_url),
          ]),
        ]))),
      ]))

  extensions.children.append(
    asn1.SEQUENCE([
      CERT_POLICIES,
      # There is implicitly a critical=False here. Since false is the default,
      # encoding the value would be invalid DER.
      asn1.OCTETSTRING(asn1.ToDER(asn1.SEQUENCE([
        asn1.SEQUENCE([ # PolicyInformation
          CERT_POLICY_OID,
        ]),
      ]))),
    ])
  )

  tbsCert = asn1.ToDER(asn1.SEQUENCE([
      asn1.Explicit(0, 2), # Version
      serial,
      asn1.SEQUENCE([SHA256_WITH_RSA_ENCRYPTION, None]), # SignatureAlgorithm
      Name(cn = issuer_cn), # Issuer
      asn1.SEQUENCE([ # Validity
        asn1.UTCTime("100101060000Z"), # NotBefore
        asn1.UTCTime("321201060000Z"), # NotAfter
      ]),
      Name(cn = subject_cn, c = c, o = o), # Subject
      asn1.SEQUENCE([ # SubjectPublicKeyInfo
        asn1.SEQUENCE([ # Algorithm
          PUBLIC_KEY_RSA,
          None,
        ]),
        asn1.BitString(asn1.ToDER(pubkey)),
      ]),
      asn1.Explicit(3, extensions),
    ]))

  return asn1.ToDER(asn1.SEQUENCE([
    asn1.Raw(tbsCert),
    asn1.SEQUENCE([
      SHA256_WITH_RSA_ENCRYPTION,
      None,
    ]),
    asn1.BitString(privkey.Sign(tbsCert)),
  ]))

def MakeOCSPSingleResponse(
    issuer_name_hash, issuer_key_hash, serial, ocsp_state, ocsp_date):
  cert_status = None
  if ocsp_state == OCSP_STATE_REVOKED:
    cert_status = asn1.Explicit(1, asn1.GeneralizedTime("20100101060000Z"))
  elif ocsp_state == OCSP_STATE_UNKNOWN:
    cert_status = asn1.Raw(asn1.TagAndLength(0x80 | 2, 0))
  elif ocsp_state == OCSP_STATE_GOOD:
    cert_status = asn1.Raw(asn1.TagAndLength(0x80 | 0, 0))
  elif ocsp_state == OCSP_STATE_MISMATCHED_SERIAL:
    cert_status = asn1.Raw(asn1.TagAndLength(0x80 | 0, 0))
    serial -= 1
  else:
    raise ValueError('Bad OCSP state: ' + str(ocsp_state))

  now = datetime.datetime.fromtimestamp(time.mktime(time.gmtime()))
  if ocsp_date == OCSP_DATE_VALID:
    thisUpdate = now - datetime.timedelta(days=1)
    nextUpdate = thisUpdate + datetime.timedelta(weeks=1)
  elif ocsp_date == OCSP_DATE_OLD:
    thisUpdate = now - datetime.timedelta(days=1, weeks=1)
    nextUpdate = thisUpdate + datetime.timedelta(weeks=1)
  elif ocsp_date == OCSP_DATE_EARLY:
    thisUpdate = now + datetime.timedelta(days=1)
    nextUpdate = thisUpdate + datetime.timedelta(weeks=1)
  elif ocsp_date == OCSP_DATE_LONG:
    thisUpdate = now - datetime.timedelta(days=365)
    nextUpdate = thisUpdate + datetime.timedelta(days=366)
  else:
    raise ValueError('Bad OCSP date: ' + str(ocsp_date))

  return asn1.SEQUENCE([ # SingleResponse
    asn1.SEQUENCE([ # CertID
      asn1.SEQUENCE([ # hashAlgorithm
        HASH_SHA1,
        None,
      ]),
      issuer_name_hash,
      issuer_key_hash,
      serial,
    ]),
    cert_status,
    asn1.GeneralizedTime( # thisUpdate
      thisUpdate.strftime(GENERALIZED_TIME_FORMAT)
    ),
    asn1.Explicit( # nextUpdate
      0,
      asn1.GeneralizedTime(nextUpdate.strftime(GENERALIZED_TIME_FORMAT))
    ),
  ])

def MakeOCSPResponse(
    issuer_cn, issuer_key, serial, ocsp_states, ocsp_dates, ocsp_produced):
  # https://tools.ietf.org/html/rfc2560
  issuer_name_hash = asn1.OCTETSTRING(
      hashlib.sha1(asn1.ToDER(Name(cn = issuer_cn))).digest())

  issuer_key_hash = asn1.OCTETSTRING(
      hashlib.sha1(asn1.ToDER(issuer_key)).digest())

  now = datetime.datetime.fromtimestamp(time.mktime(time.gmtime()))
  if ocsp_produced == OCSP_PRODUCED_VALID:
    producedAt = now - datetime.timedelta(days=1)
  elif ocsp_produced == OCSP_PRODUCED_BEFORE_CERT:
    producedAt = datetime.datetime.strptime(
        "19100101050000Z", GENERALIZED_TIME_FORMAT)
  elif ocsp_produced == OCSP_PRODUCED_AFTER_CERT:
    producedAt = datetime.datetime.strptime(
        "20321201070000Z", GENERALIZED_TIME_FORMAT)
  else:
    raise ValueError('Bad OCSP produced: ' + str(ocsp_produced))

  single_responses = [
      MakeOCSPSingleResponse(issuer_name_hash, issuer_key_hash, serial,
          ocsp_state, ocsp_date)
      for ocsp_state, ocsp_date in itertools.izip(ocsp_states, ocsp_dates)
  ]

  basic_resp_data_der = asn1.ToDER(asn1.SEQUENCE([
    asn1.Explicit(2, issuer_key_hash),
    asn1.GeneralizedTime(producedAt.strftime(GENERALIZED_TIME_FORMAT)),
    asn1.SEQUENCE(single_responses),
  ]))

  basic_resp = asn1.SEQUENCE([
    asn1.Raw(basic_resp_data_der),
    asn1.SEQUENCE([
      SHA256_WITH_RSA_ENCRYPTION,
      None,
    ]),
    asn1.BitString(issuer_key.Sign(basic_resp_data_der)),
  ])

  resp = asn1.SEQUENCE([
    asn1.ENUMERATED(0),
    asn1.Explicit(0, asn1.SEQUENCE([
      OCSP_TYPE_BASIC,
      asn1.OCTETSTRING(asn1.ToDER(basic_resp)),
    ]))
  ])

  return asn1.ToDER(resp)


def DERToPEM(der):
  pem = '-----BEGIN CERTIFICATE-----\n'
  pem += der.encode('base64')
  pem += '-----END CERTIFICATE-----\n'
  return pem

# unauthorizedDER is an OCSPResponse with a status of 6:
# SEQUENCE { ENUM(6) }
unauthorizedDER = '30030a0106'.decode('hex')

def GenerateCertKeyAndOCSP(subject = "127.0.0.1",
                           ocsp_url = "http://127.0.0.1",
                           ocsp_states = None,
                           ocsp_dates = None,
                           ocsp_produced = OCSP_PRODUCED_VALID,
                           serial = 0):
  '''GenerateCertKeyAndOCSP returns a (cert_and_key_pem, ocsp_der) where:
       * cert_and_key_pem contains a certificate and private key in PEM format
         with the given subject common name and OCSP URL.
       * ocsp_der contains a DER encoded OCSP response or None if ocsp_url is
         None'''

  if ocsp_states is None:
    ocsp_states = [OCSP_STATE_GOOD]
  if ocsp_dates is None:
    ocsp_dates = [OCSP_DATE_VALID]

  if serial == 0:
    serial = RandomNumber(16)
  cert_der = MakeCertificate(ISSUER_CN, bytes(subject), serial, KEY, KEY,
                             bytes(ocsp_url))
  cert_pem = DERToPEM(cert_der)

  ocsp_der = None
  if ocsp_url is not None:
    if ocsp_states[0] == OCSP_STATE_UNAUTHORIZED:
      ocsp_der = unauthorizedDER
    elif ocsp_states[0] == OCSP_STATE_INVALID_RESPONSE:
      ocsp_der = '3'
    elif ocsp_states[0] == OCSP_STATE_TRY_LATER:
      resp = asn1.SEQUENCE([
        asn1.ENUMERATED(3),
      ])
      ocsp_der = asn1.ToDER(resp)
    elif ocsp_states[0] == OCSP_STATE_INVALID_RESPONSE_DATA:
      invalid_data = asn1.ToDER(asn1.OCTETSTRING('not ocsp data'))
      basic_resp = asn1.SEQUENCE([
        asn1.Raw(invalid_data),
        asn1.SEQUENCE([
          SHA256_WITH_RSA_ENCRYPTION,
          None,
        ]),
        asn1.BitString(KEY.Sign(invalid_data)),
      ])
      resp = asn1.SEQUENCE([
        asn1.ENUMERATED(0),
        asn1.Explicit(0, asn1.SEQUENCE([
          OCSP_TYPE_BASIC,
          asn1.OCTETSTRING(asn1.ToDER(basic_resp)),
        ])),
      ])
      ocsp_der = asn1.ToDER(resp)
    else:
      ocsp_der = MakeOCSPResponse(
          ISSUER_CN, KEY, serial, ocsp_states, ocsp_dates, ocsp_produced)

  return (cert_pem + KEY_PEM, ocsp_der)


if __name__ == '__main__':
  def bin_to_array(s):
    return ' '.join(['0x%02x,'%ord(c) for c in s])

  import sys
  sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..',
                               '..', 'data', 'ssl', 'scripts'))
  import crlsetutil

  der_root = MakeCertificate(ISSUER_CN, ISSUER_CN, 1, KEY, KEY, None)
  print 'ocsp-test-root.pem:'
  print DERToPEM(der_root)

  print
  print 'kOCSPTestCertFingerprint:'
  print bin_to_array(hashlib.sha1(der_root).digest())

  print
  print 'kOCSPTestCertSPKI:'
  print bin_to_array(crlsetutil.der_cert_to_spki_hash(der_root))
