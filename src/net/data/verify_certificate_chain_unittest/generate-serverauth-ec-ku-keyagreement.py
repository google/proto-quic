#!/usr/bin/python
# Copyright (c) 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Certificate chain with 1 intermediate, a trusted root, and a target
certificate for serverAuth that has only keyAgreement."""

import common

# Self-signed root certificate (used as trust anchor).
root = common.create_self_signed_root_certificate('Root')

# Intermediate certificate.
intermediate = common.create_intermediate_certificate('Intermediate', root)

# Target certificate.
target = common.create_end_entity_certificate('Target', intermediate)
target.set_key(common.get_or_generate_ec_key(
    'secp384r1', common.create_key_path(target.name)))
target.get_extensions().set_property('extendedKeyUsage', 'serverAuth')
target.get_extensions().set_property('keyUsage', 'critical,keyAgreement')


chain = [target, intermediate]
trusted = common.TrustAnchor(root, constrained=False)
time = common.DEFAULT_TIME
key_purpose = common.KEY_PURPOSE_SERVER_AUTH
verify_result = True
errors = None

common.write_test_file(__doc__, chain, trusted, time, key_purpose,
                       verify_result, errors)
