#!/usr/bin/python
# Copyright (c) 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Set of helpers to generate signed X.509v3 certificates.

This works by shelling out calls to the 'openssl req' and 'openssl ca'
commands, and passing the appropriate command line flags and configuration file
(.cnf).
"""

import base64
import os
import shutil
import subprocess
import sys

import openssl_conf

# Enum for the "type" of certificate that is to be created. This is used to
# select sane defaults for the .cnf file and command line flags, but they can
# all be overridden.
TYPE_CA = 2
TYPE_END_ENTITY = 3

# March 1st, 2015 12:00 UTC
MARCH_1_2015_UTC = '150301120000Z'

# March 2nd, 2015 12:00 UTC
MARCH_2_2015_UTC = '150302120000Z'

# January 1st, 2015 12:00 UTC
JANUARY_1_2015_UTC = '150101120000Z'

# January 1st, 2016 12:00 UTC
JANUARY_1_2016_UTC = '160101120000Z'

# January 1st, 2021 12:00 UTC
JANUARY_1_2021_UTC = '210101120000Z'

# The default time tests should use when verifying.
DEFAULT_TIME = MARCH_2_2015_UTC

# Counters used to generate unique (but readable) path names.
g_cur_path_id = {}

# Output paths used:
#   - g_out_dir: where any temporary files (keys, cert req, signing db etc) are
#                saved to.
#   - g_out_pem: the path to the final output (which is a .pem file)
#
# See init() for how these are assigned, based on the name of the calling
# script.
g_out_dir = None
g_out_pem = None

# The default validity range of generated certificates. Can be modified with
# set_default_validity_range().
g_default_start_date = JANUARY_1_2015_UTC
g_default_end_date = JANUARY_1_2016_UTC


def set_default_validity_range(start_date, end_date):
  """Sets the validity range that will be used for certificates created with
  Certificate"""
  global g_default_start_date
  global g_default_end_date
  g_default_start_date = start_date
  g_default_end_date = end_date

def get_unique_path_id(name):
  """Returns a base filename that contains 'name', but is unique to the output
  directory"""
  path_id = g_cur_path_id.get(name, 0)
  g_cur_path_id[name] = path_id + 1

  # Use a short and clean name for the first use of this name.
  if path_id == 0:
    return name

  # Otherwise append the count to make it unique.
  return '%s_%d' % (name, path_id)


def get_path_in_output_dir(name, suffix):
  return os.path.join(g_out_dir, '%s%s' % (name, suffix))


def get_unique_path_in_output_dir(name, suffix):
  return get_path_in_output_dir(get_unique_path_id(name), suffix)


class Key(object):
  """Describes a public + private key pair. It is a dumb wrapper around an
  on-disk key."""

  def __init__(self, path):
    self.path = path


  def get_path(self):
    """Returns the path to a file that contains the key contents."""
    return self.path


def generate_rsa_key(size_bits, path=None):
  """Generates an RSA private key and returns it as a Key object. If |path| is
  specified the resulting key will be saved at that location."""
  if path is None:
    path = get_unique_path_in_output_dir('RsaKey', 'key')

  # Ensure the path doesn't already exists (otherwise will be overwriting
  # something).
  assert not os.path.isfile(path)

  subprocess.check_call(
      ['openssl', 'genrsa', '-out', path, str(size_bits)])

  return Key(path)


def generate_ec_key(named_curve, path=None):
  """Generates an EC private key for the certificate and returns it as a Key
  object. |named_curve| can be something like secp384r1. If |path| is specified
  the resulting key will be saved at that location."""
  if path is None:
    path = get_unique_path_in_output_dir('EcKey', 'key')

  # Ensure the path doesn't already exists (otherwise will be overwriting
  # something).
  assert not os.path.isfile(path)

  subprocess.check_call(
      ['openssl', 'ecparam', '-out', path,
       '-name', named_curve, '-genkey'])

  return Key(path)


class Certificate(object):
  """Helper for building an X.509 certificate."""

  def __init__(self, name, cert_type, issuer):
    # The name will be used for the subject's CN, and also as a component of
    # the temporary filenames to help with debugging.
    self.name = name
    self.path_id = get_unique_path_id(name)

    # Allow the caller to override the key later. If no key was set will
    # auto-generate one.
    self.key = None

    # The issuer is also a Certificate object. Passing |None| means it is a
    # self-signed certificate.
    self.issuer = issuer
    if issuer is None:
      self.issuer = self

    # The config contains all the OpenSSL options that will be passed via a
    # .cnf file. Set up defaults.
    self.config = openssl_conf.Config()
    self.init_config()

    # Some settings need to be passed as flags rather than in the .cnf file.
    # Technically these can be set though a .cnf, however doing so makes it
    # sticky to the issuing certificate, rather than selecting it per
    # subordinate certificate.
    self.validity_flags = []
    self.md_flags = []

    # By default OpenSSL will use the current time for the start time. Instead
    # default to using a fixed timestamp for more predictable results each time
    # the certificates are re-generated.
    self.set_validity_range(g_default_start_date, g_default_end_date)

    # Use SHA-256 when THIS certificate is signed (setting it in the
    # configuration would instead set the hash to use when signing other
    # certificates with this one).
    self.set_signature_hash('sha256')

    # Set appropriate key usages and basic constraints. For flexibility in
    # testing (since want to generate some flawed certificates) these are set
    # on a per-certificate basis rather than automatically when signing.
    if cert_type == TYPE_END_ENTITY:
      self.get_extensions().set_property('keyUsage',
              'critical,digitalSignature,keyEncipherment')
      self.get_extensions().set_property('extendedKeyUsage',
              'serverAuth,clientAuth')
    else:
      self.get_extensions().set_property('keyUsage',
              'critical,keyCertSign,cRLSign')
      self.get_extensions().set_property('basicConstraints', 'critical,CA:true')

    # Tracks whether the PEM file for this certificate has been written (since
    # generation is done lazily).
    self.finalized = False

    # Initialize any files that will be needed if this certificate is used to
    # sign other certificates. Starts off serial numbers at 1, and will
    # increment them for each signed certificate.
    if not os.path.exists(self.get_serial_path()):
      write_string_to_file('01\n', self.get_serial_path())
    if not os.path.exists(self.get_database_path()):
      write_string_to_file('', self.get_database_path())


  def set_validity_range(self, start_date, end_date):
    """Sets the Validity notBefore and notAfter properties for the
    certificate"""
    self.validity_flags = ['-startdate', start_date, '-enddate', end_date]


  def set_signature_hash(self, md):
    """Sets the hash function that will be used when signing this certificate.
    Can be sha1, sha256, sha512, md5, etc."""
    self.md_flags = ['-md', md]


  def get_extensions(self):
    return self.config.get_section('req_ext')


  def get_path(self, suffix):
    """Forms a path to an output file for this certificate, containing the
    indicated suffix. The certificate's name will be used as its basis."""
    return os.path.join(g_out_dir, '%s%s' % (self.path_id, suffix))


  def get_name_path(self, suffix):
    """Forms a path to an output file for this CA, containing the indicated
    suffix. If multiple certificates have the same name, they will use the same
    path."""
    return get_path_in_output_dir(self.name, suffix)


  def set_key(self, key):
    assert self.finalized is False
    self.set_key_internal(key)


  def set_key_internal(self, key):
    self.key = key

    # Associate the private key with the certificate.
    section = self.config.get_section('root_ca')
    section.set_property('private_key', self.key.get_path())


  def get_key(self):
    if self.key is None:
      self.set_key_internal(generate_rsa_key(2048, path=self.get_path(".key")))
    return self.key


  def get_cert_path(self):
    return self.get_path('.pem')


  def get_serial_path(self):
    return self.get_name_path('.serial')


  def get_csr_path(self):
    return self.get_path('.csr')


  def get_database_path(self):
    return self.get_name_path('.db')


  def get_config_path(self):
    return self.get_path('.cnf')


  def get_cert_pem(self):
    # Finish generating a .pem file for the certificate.
    self.finalize()

    # Read the certificate data.
    with open(self.get_cert_path(), 'r') as f:
      return f.read()


  def finalize(self):
    """Finishes the certificate creation process. This generates any needed
    key, creates and signs the CSR. On completion the resulting PEM file can be
    found at self.get_cert_path()"""

    if self.finalized:
      return # Already finalized, no work needed.

    self.finalized = True

    # Ensure that the issuer has been "finalized", since its outputs need to be
    # accessible. Note that self.issuer could be the same as self.
    self.issuer.finalize()

    # Ensure the certificate has a key (gets lazily created by this call if
    # missing).
    self.get_key()

    # Serialize the config to a file.
    self.config.write_to_file(self.get_config_path())

    # Create a CSR.
    subprocess.check_call(
        ['openssl', 'req', '-new',
         '-key', self.key.get_path(),
         '-out', self.get_csr_path(),
         '-config', self.get_config_path()])

    cmd = ['openssl', 'ca', '-batch', '-in',
        self.get_csr_path(), '-out', self.get_cert_path(), '-config',
        self.issuer.get_config_path()]

    if self.issuer == self:
      cmd.append('-selfsign')

    # Add in any extra flags.
    cmd.extend(self.validity_flags)
    cmd.extend(self.md_flags)

    # Run the 'openssl ca' command.
    subprocess.check_call(cmd)


  def init_config(self):
    """Initializes default properties in the certificate .cnf file that are
    generic enough to work for all certificates (but can be overridden later).
    """

    # --------------------------------------
    # 'req' section
    # --------------------------------------

    section = self.config.get_section('req')

    section.set_property('encrypt_key', 'no')
    section.set_property('utf8', 'yes')
    section.set_property('string_mask', 'utf8only')
    section.set_property('prompt', 'no')
    section.set_property('distinguished_name', 'req_dn')
    section.set_property('req_extensions', 'req_ext')

    # --------------------------------------
    # 'req_dn' section
    # --------------------------------------

    # This section describes the certificate subject's distinguished name.

    section = self.config.get_section('req_dn')
    section.set_property('commonName', '"%s"' % (self.name))

    # --------------------------------------
    # 'req_ext' section
    # --------------------------------------

    # This section describes the certificate's extensions.

    section = self.config.get_section('req_ext')
    section.set_property('subjectKeyIdentifier', 'hash')

    # --------------------------------------
    # SECTIONS FOR CAs
    # --------------------------------------

    # The following sections are used by the 'openssl ca' and relate to the
    # signing operation. They are not needed for end-entity certificate
    # configurations, but only if this certifiate will be used to sign other
    # certificates.

    # --------------------------------------
    # 'ca' section
    # --------------------------------------

    section = self.config.get_section('ca')
    section.set_property('default_ca', 'root_ca')

    section = self.config.get_section('root_ca')
    section.set_property('certificate', self.get_cert_path())
    section.set_property('new_certs_dir', g_out_dir)
    section.set_property('serial', self.get_serial_path())
    section.set_property('database', self.get_database_path())
    section.set_property('unique_subject', 'no')

    # These will get overridden via command line flags.
    section.set_property('default_days', '365')
    section.set_property('default_md', 'sha256')

    section.set_property('policy', 'policy_anything')
    section.set_property('email_in_dn', 'no')
    section.set_property('preserve', 'yes')
    section.set_property('name_opt', 'multiline,-esc_msb,utf8')
    section.set_property('cert_opt', 'ca_default')
    section.set_property('copy_extensions', 'copy')
    section.set_property('x509_extensions', 'signing_ca_ext')
    section.set_property('default_crl_days', '30')
    section.set_property('crl_extensions', 'crl_ext')

    section = self.config.get_section('policy_anything')
    section.set_property('domainComponent', 'optional')
    section.set_property('countryName', 'optional')
    section.set_property('stateOrProvinceName', 'optional')
    section.set_property('localityName', 'optional')
    section.set_property('organizationName', 'optional')
    section.set_property('organizationalUnitName', 'optional')
    section.set_property('commonName', 'optional')
    section.set_property('emailAddress', 'optional')

    section = self.config.get_section('signing_ca_ext')
    section.set_property('subjectKeyIdentifier', 'hash')
    section.set_property('authorityKeyIdentifier', 'keyid:always')
    section.set_property('authorityInfoAccess', '@issuer_info')
    section.set_property('crlDistributionPoints', '@crl_info')

    section = self.config.get_section('issuer_info')
    section.set_property('caIssuers;URI.0',
                        'http://url-for-aia/%s.cer' % (self.name))

    section = self.config.get_section('crl_info')
    section.set_property('URI.0', 'http://url-for-crl/%s.crl' % (self.name))

    section = self.config.get_section('crl_ext')
    section.set_property('authorityKeyIdentifier', 'keyid:always')
    section.set_property('authorityInfoAccess', '@issuer_info')


def text_data_to_pem(block_header, text_data):
  return '%s\n-----BEGIN %s-----\n%s\n-----END %s-----\n' % (text_data,
          block_header, base64.b64encode(text_data), block_header)


class TrustAnchor(object):
  """Structure that represents a trust anchor."""

  def __init__(self, cert, constrained=False):
    self.cert = cert
    self.constrained = constrained


  def get_pem(self):
    """Returns a PEM block string describing this trust anchor."""

    cert_data = self.cert.get_cert_pem()
    block_name = 'TRUST_ANCHOR_UNCONSTRAINED'
    if self.constrained:
      block_name = 'TRUST_ANCHOR_CONSTRAINED'

    # Use a different block name in the .pem file, depending on the anchor type.
    return cert_data.replace('CERTIFICATE', block_name)


def write_test_file(description, chain, trust_anchor, utc_time, verify_result,
                    errors, out_pem=None):
  """Writes a test file that contains all the inputs necessary to run a
  verification on a certificate chain"""

  # Prepend the script name that generated the file to the description.
  test_data = '[Created by: %s]\n\n%s\n' % (sys.argv[0], description)

  # Write the certificate chain to the output file.
  for cert in chain:
    test_data += '\n' + cert.get_cert_pem()

  test_data += '\n' + trust_anchor.get_pem()
  test_data += '\n' + text_data_to_pem('TIME', utc_time)

  verify_result_string = 'SUCCESS' if verify_result else 'FAIL'
  test_data += '\n' + text_data_to_pem('VERIFY_RESULT', verify_result_string)

  if errors is not None:
    test_data += '\n' + text_data_to_pem('ERRORS', errors)

  write_string_to_file(test_data, out_pem if out_pem else g_out_pem)


def write_string_to_file(data, path):
  with open(path, 'w') as f:
    f.write(data)


def init(invoking_script_path):
  """Creates an output directory to contain all the temporary files that may be
  created, as well as determining the path for the final output. These paths
  are all based off of the name of the calling script.
  """

  global g_out_dir
  global g_out_pem

  # Base the output name off of the invoking script's name.
  out_name = os.path.splitext(os.path.basename(invoking_script_path))[0]

  # Strip the leading 'generate-'
  if out_name.startswith('generate-'):
    out_name = out_name[9:]

  # Use an output directory with the same name as the invoking script.
  g_out_dir = os.path.join('out', out_name)

  # Ensure the output directory exists and is empty.
  sys.stdout.write('Creating output directory: %s\n' % (g_out_dir))
  shutil.rmtree(g_out_dir, True)
  os.makedirs(g_out_dir)

  g_out_pem = os.path.join('%s.pem' % (out_name))


def create_self_signed_root_certificate(name):
  return Certificate(name, TYPE_CA, None)


def create_intermediate_certificate(name, issuer):
  return Certificate(name, TYPE_CA, issuer)


def create_end_entity_certificate(name, issuer):
  return Certificate(name, TYPE_END_ENTITY, issuer)

init(sys.argv[0])
