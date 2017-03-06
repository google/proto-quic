#!/usr/bin/env python
# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import os
import sys
sys.path += [os.path.join('..', 'verify_certificate_chain_unittest')]

import common

common.set_default_validity_range(common.JANUARY_1_2015_UTC,
                                  common.JANUARY_1_2021_UTC)


# Self-signed root certificate.
root = common.create_self_signed_root_certificate('Root')
common.write_string_to_file(root.get_cert_pem(), 'root.pem')


# Intermediate certificates. All have the same subject and key.
i_base = common.create_intermediate_certificate('I', root)
common.write_string_to_file(i_base.get_cert_pem(), 'i.pem')

i2 = common.create_intermediate_certificate('I', root)
i2.set_key(i_base.get_key())
common.write_string_to_file(i2.get_cert_pem(), 'i2.pem')

i3 = common.create_intermediate_certificate('I', root)
i3.set_key(i_base.get_key())
common.write_string_to_file(i3.get_cert_pem(), 'i3.pem')


# More Intermediate certificates, which are just to generate the proper config
# files so the target certs will have the desired Authority Information Access
# values. These ones aren't saved to files.
i_no_aia = common.create_intermediate_certificate('I', root)
i_no_aia.set_key(i_base.get_key())
section = i_no_aia.config.get_section('signing_ca_ext')
section.set_property('authorityInfoAccess', None)

i_two_aia = common.create_intermediate_certificate('I', root)
i_two_aia.set_key(i_base.get_key())
section = i_two_aia.config.get_section('issuer_info')
section.set_property('caIssuers;URI.1', 'http://url-for-aia2/I2.foo')

i_three_aia = common.create_intermediate_certificate('I', root)
i_three_aia.set_key(i_base.get_key())
section = i_three_aia.config.get_section('issuer_info')
section.set_property('caIssuers;URI.1', 'http://url-for-aia2/I2.foo')
section.set_property('caIssuers;URI.2', 'http://url-for-aia3/I3.foo')

i_six_aia = common.create_intermediate_certificate('I', root)
i_six_aia.set_key(i_base.get_key())
section = i_six_aia.config.get_section('issuer_info')
section.set_property('caIssuers;URI.1', 'http://url-for-aia2/I2.foo')
section.set_property('caIssuers;URI.2', 'http://url-for-aia3/I3.foo')
section.set_property('caIssuers;URI.3', 'http://url-for-aia4/I4.foo')
section.set_property('caIssuers;URI.4', 'http://url-for-aia5/I5.foo')
section.set_property('caIssuers;URI.5', 'http://url-for-aia6/I6.foo')

i_file_aia = common.create_intermediate_certificate('I', root)
i_file_aia.set_key(i_base.get_key())
section = i_file_aia.config.get_section('issuer_info')
section.set_property('caIssuers;URI.0', 'file:///dev/null')

i_invalid_url_aia = common.create_intermediate_certificate('I', root)
i_invalid_url_aia.set_key(i_base.get_key())
section = i_invalid_url_aia.config.get_section('issuer_info')
section.set_property('caIssuers;URI.0', 'foobar')

i_file_and_http_aia = common.create_intermediate_certificate('I', root)
i_file_and_http_aia.set_key(i_base.get_key())
section = i_file_and_http_aia.config.get_section('issuer_info')
section.set_property('caIssuers;URI.0', 'file:///dev/null')
section.set_property('caIssuers;URI.1', 'http://url-for-aia2/I2.foo')

i_invalid_and_http_aia = common.create_intermediate_certificate('I', root)
i_invalid_and_http_aia.set_key(i_base.get_key())
section = i_invalid_and_http_aia.config.get_section('issuer_info')
section.set_property('caIssuers;URI.0', 'foobar')
section.set_property('caIssuers;URI.1', 'http://url-for-aia2/I2.foo')


# target certs

target = common.create_end_entity_certificate('target', i_base)
target.get_extensions().set_property('subjectAltName', 'DNS:target')
common.write_string_to_file(target.get_cert_pem(), 'target_one_aia.pem')

target = common.create_end_entity_certificate('target', i_no_aia)
target.get_extensions().set_property('subjectAltName', 'DNS:target')
common.write_string_to_file(target.get_cert_pem(), 'target_no_aia.pem')

target = common.create_end_entity_certificate('target', i_two_aia)
target.get_extensions().set_property('subjectAltName', 'DNS:target')
common.write_string_to_file(target.get_cert_pem(), 'target_two_aia.pem')

target = common.create_end_entity_certificate('target', i_three_aia)
target.get_extensions().set_property('subjectAltName', 'DNS:target')
common.write_string_to_file(target.get_cert_pem(), 'target_three_aia.pem')

target = common.create_end_entity_certificate('target', i_six_aia)
target.get_extensions().set_property('subjectAltName', 'DNS:target')
common.write_string_to_file(target.get_cert_pem(), 'target_six_aia.pem')

target = common.create_end_entity_certificate('target', i_file_aia)
target.get_extensions().set_property('subjectAltName', 'DNS:target')
common.write_string_to_file(target.get_cert_pem(), 'target_file_aia.pem')

target = common.create_end_entity_certificate('target', i_invalid_url_aia)
target.get_extensions().set_property('subjectAltName', 'DNS:target')
common.write_string_to_file(target.get_cert_pem(), 'target_invalid_url_aia.pem')

target = common.create_end_entity_certificate('target', i_file_and_http_aia)
target.get_extensions().set_property('subjectAltName', 'DNS:target')
common.write_string_to_file(target.get_cert_pem(),
                            'target_file_and_http_aia.pem')

target = common.create_end_entity_certificate('target', i_invalid_and_http_aia)
target.get_extensions().set_property('subjectAltName', 'DNS:target')
common.write_string_to_file(target.get_cert_pem(),
                            'target_invalid_and_http_aia.pem')
