#!/usr/bin/python
# Copyright (c) 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Certificate chain with a trusted root using RSA, and intermediate using EC,
and a target certificate using RSA. Verification is expected to succeed."""

import common

# Self-signed root certificate (used as trust anchor). using RSA.
root = common.create_self_signed_root_certificate('Root')

# Intermediate using an EC key for the P-384 curve.
intermediate = common.create_intermediate_certificate('Intermediate', root)
intermediate.set_key(common.generate_ec_key('secp384r1'))

# Target certificate contains an RSA key (but is signed using ECDSA).
target = common.create_end_entity_certificate('Target', intermediate)

chain = [target, intermediate]
trusted = common.TrustAnchor(root, constrained=False)
time = common.DEFAULT_TIME
verify_result = True
errors = None

common.write_test_file(__doc__, chain, trusted, time, verify_result, errors)
