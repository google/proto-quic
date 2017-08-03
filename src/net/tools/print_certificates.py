#!/usr/bin/python
# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Pretty-prints certificates as an openssl-annotated PEM file.

Usage: print_certificates.py [SOURCE]...

Each SOURCE can be one of:
  (1) A server name such as www.google.com.
  (2) A PEM [*] file containing one or more CERTIFICATE blocks
  (3) A binary file containing DER-encoded certificate

When multiple SOURCEs are listed, all certificates in them are concatenated. If
no SOURCE is given then data will be read from stdin.

[*] Parsing of PEM files is relaxed - leading indentation whitespace will be
stripped (needed for copy-pasting data from NetLogs).
"""

import base64
import os
import re
import subprocess
import sys


def read_file_to_string(path):
  with open(path, 'r') as f:
    return f.read()


def read_certificates_data_from_server(hostname):
  """Uses openssl to fetch the PEM-encoded certificates for an SSL server."""
  p = subprocess.Popen(["openssl", "s_client", "-showcerts",
                        "-servername", hostname,
                        "-connect", hostname + ":443"],
                        stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE)
  result = p.communicate()

  if p.returncode == 0:
    return result[0]

  sys.stderr.write("Failed getting certificates for %s:\n%s\n" % (
      hostname, result[1]))
  return ""


def read_sources_from_commandline():
  """Processes the command lines and returns an array of all the sources
  bytes."""
  sources_bytes = []

  if len(sys.argv) == 1:
    # If no commonand-line arguments were given to the program, read input from
    # stdin.
    sources_bytes.append(sys.stdin.read())
  else:
    for arg in sys.argv[1:]:
      # If the argument identifies a file path, read it
      if os.path.exists(arg):
        sources_bytes.append(read_file_to_string(arg))
      else:
        # Otherwise treat it as a web server address.
        sources_bytes.append(read_certificates_data_from_server(arg))

  return sources_bytes


def strip_indentation_whitespace(text):
  """Strips leading whitespace from each line."""
  stripped_lines = [line.lstrip() for line in text.split("\n")]
  return "\n".join(stripped_lines)


def strip_all_whitespace(text):
  pattern = re.compile(r'\s+')
  return re.sub(pattern, '', text)


def extract_certificates_from_pem(pem_bytes):
  certificates_der = []

  regex = re.compile(
      r'-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----', re.DOTALL)

  for match in regex.finditer(pem_bytes):
    cert_der = base64.b64decode(strip_all_whitespace(match.group(1)))
    certificates_der.append(cert_der)

  return certificates_der


def extract_certificates(source_bytes):
  if "BEGIN CERTIFICATE" in source_bytes:
    return extract_certificates_from_pem(source_bytes)

  # Otherwise assume it is the DER for a single certificate
  return [source_bytes]


def pretty_print_certificate(certificate_der):
  p = subprocess.Popen(["openssl", "x509", "-text", "-inform", "DER",
                        "-outform", "PEM"],
                        stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE)
  result = p.communicate(certificate_der)

  if p.returncode == 0:
    return result[0]

  # Otherwise failed.
  sys.stderr.write("Failed: %s\n" % result[1])
  return ""


def pretty_print_certificates(certificates_der):
  result = ""
  for i in range(len(certificates_der)):
    certificate_der = certificates_der[i]
    pretty = pretty_print_certificate(certificate_der)
    result += """===========================================
Certificate%d
===========================================
%s
""" % (i, pretty)
  return result


def main():
  sources_bytes = read_sources_from_commandline()

  certificates_der = []
  for source_bytes in sources_bytes:
    certificates_der.extend(extract_certificates(source_bytes))

  print pretty_print_certificates(certificates_der)


if __name__ == "__main__":
  main()
