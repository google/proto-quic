#!/usr/bin/python
# Copyright (c) 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Certificate chain with a trusted root using RSA, and intermediate using EC,
and a target certificate using RSA. Verification is expected to succeed."""

import sys
sys.path += ['..']

import common

# Self-signed root certificate (used as trust anchor). using RSA.
root = common.create_self_signed_root_certificate('Root')

# Intermediate using an EC key for the P-384 curve.
intermediate = common.create_intermediate_certificate('Intermediate', root)
intermediate.set_key(common.get_or_generate_ec_key(
    'secp384r1', common.create_key_path(intermediate.name)))

# Target certificate contains an RSA key (but is signed using ECDSA).
target = common.create_end_entity_certificate('Target', intermediate)

chain = [target, intermediate, root]
common.write_chain(__doc__, chain, 'chain.pem')
