#!/usr/bin/env python
# Copyright (c) 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""
This utility takes a JSON input that describes a CRLSet and produces a
CRLSet from it.

The input is taken on stdin and is a dict with the following keys:
  - BlockedBySPKI: An array of strings, where each string is a filename
      containing a PEM certificate, from which an SPKI will be extracted.
  - BlockedByHash: A dict of string to an array of ints, where the string is
      a filename containing a PEM format certificate, and the ints are the
      serial numbers. The listed serial numbers will be blocked when issued by
      the given certificate.

For example:

{
  "BlockedBySPKI": ["/tmp/blocked-certificate"],
  "BlockedByHash": {
    "/tmp/intermediate-certificate": [1, 2, 3]
  }
}
"""

import hashlib
import json
import optparse
import struct
import sys


def _pem_cert_to_binary(pem_filename):
  """Decodes the first PEM-encoded certificate in a given file into binary

  Args:
    pem_filename: A filename that contains a PEM-encoded certificate. It may
        contain additional data (keys, textual representation) which will be
        ignored

  Returns:
    A byte array containing the decoded certificate data
  """
  base64 = ""
  started = False

  with open(pem_filename, 'r') as pem_file:
    for line in pem_file:
      if not started:
        if line.startswith('-----BEGIN CERTIFICATE'):
          started = True
      else:
        if line.startswith('-----END CERTIFICATE'):
          break
        base64 += line[:-1].strip()

  return base64.decode('base64')


def _parse_asn1_element(der_bytes):
  """Parses a DER-encoded tag/Length/Value into its component parts

  Args:
    der_bytes: A DER-encoded ASN.1 data type

  Returns:
    A tuple of the ASN.1 tag value, the length of the ASN.1 header that was
    read, the sequence of bytes for the value, and then any data from der_bytes
    that was not part of the tag/Length/Value.
  """
  tag = ord(der_bytes[0])
  length = ord(der_bytes[1])
  header_length = 2

  if length & 0x80:
    num_length_bytes = length & 0x7f
    length = 0
    for i in xrange(2, 2 + num_length_bytes):
      length <<= 8
      length += ord(der_bytes[i])
    header_length = 2 + num_length_bytes

  contents = der_bytes[:header_length + length]
  rest = der_bytes[header_length + length:]

  return (tag, header_length, contents, rest)


class ASN1Iterator(object):
  """Iterator that parses and iterates through a ASN.1 DER structure"""

  def __init__(self, contents):
    self._tag = 0
    self._header_length = 0
    self._rest = None
    self._contents = contents
    self.step_into()

  def step_into(self):
    """Begins processing the inner contents of the next ASN.1 element"""
    (self._tag, self._header_length, self._contents, self._rest) = (
        _parse_asn1_element(self._contents[self._header_length:]))

  def step_over(self):
    """Skips/ignores the next ASN.1 element"""
    (self._tag, self._header_length, self._contents, self._rest) = (
        _parse_asn1_element(self._rest))

  def tag(self):
    """Returns the ASN.1 tag of the current element"""
    return self._tag

  def contents(self):
    """Returns the raw data of the current element"""
    return self._contents


def _der_cert_to_spki(der_bytes):
  """Returns the subjectPublicKeyInfo of a DER-encoded certificate

  Args:
    der_bytes: A DER-encoded certificate (RFC 5280)

  Returns:
    A byte array containing the subjectPublicKeyInfo
  """
  iterator = ASN1Iterator(der_bytes)
  iterator.step_into()  # enter certificate structure
  iterator.step_into()  # enter TBSCertificate
  iterator.step_over()  # over version
  iterator.step_over()  # over serial
  iterator.step_over()  # over signature algorithm
  iterator.step_over()  # over issuer name
  iterator.step_over()  # over validity
  iterator.step_over()  # over subject name
  return iterator.contents()


def pem_cert_file_to_spki_hash(pem_filename):
  """Gets the SHA-256 hash of the subjectPublicKeyInfo of a cert in a file

  Args:
    pem_filename: A file containing a PEM-encoded certificate.

  Returns:
    The SHA-256 hash of the first certificate in the file, as a byte sequence
  """
  return hashlib.sha256(
    _der_cert_to_spki(_pem_cert_to_binary(pem_filename))).digest()


def main():
  parser = optparse.OptionParser(description=sys.modules[__name__].__doc__)
  parser.add_option('-o', '--output',
                    help='Specifies the output file. The default is stdout.')
  options, _ = parser.parse_args()
  outfile = sys.stdout
  if options.output and options.output != '-':
    outfile = open(options.output, 'wb')

  config = json.load(sys.stdin)
  blocked_spkis = [
      pem_cert_file_to_spki_hash(pem_file).encode('base64').strip()
      for pem_file in config.get('BlockedBySPKI', [])]
  parents = {
    pem_cert_file_to_spki_hash(pem_file): serials
    for pem_file, serials in config.get('BlockedByHash', {}).iteritems()
  }
  header_json = {
      'Version': 0,
      'ContentType': 'CRLSet',
      'Sequence': 0,
      'DeltaFrom': 0,
      'NumParents': len(parents),
      'BlockedSPKIs': blocked_spkis,
  }
  header = json.dumps(header_json)
  outfile.write(struct.pack('<H', len(header)))
  outfile.write(header)
  for spki, serials in sorted(parents.iteritems()):
    outfile.write(spki)
    outfile.write(struct.pack('<I', len(serials)))
    for serial in serials:
      raw_serial = []
      if not serial:
        raw_serial = ['\x00']
      else:
        while serial:
          raw_serial.insert(0, chr(serial & 0xff))
          serial >>= 8

    outfile.write(struct.pack('<B', len(raw_serial)))
    outfile.write(''.join(raw_serial))
  return 0


if __name__ == '__main__':
  sys.exit(main())
