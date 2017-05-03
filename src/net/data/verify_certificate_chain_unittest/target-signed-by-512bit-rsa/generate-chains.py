#!/usr/bin/python
# Copyright (c) 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Certificate chain with 1 intermediate and a trusted root. The target
certificate is signed using a weak RSA key (512-bit modulus), and so
verification is expected to fail."""

import sys
sys.path += ['..']

import common

# Self-signed root certificate (used as trust anchor).
root = common.create_self_signed_root_certificate('Root')

# Intermediate with a very weak key size (512-bit RSA).
intermediate = common.create_intermediate_certificate('Intermediate', root)
intermediate.set_key(common.get_or_generate_rsa_key(
    512, common.create_key_path(intermediate.name)))

# Target certificate.
target = common.create_end_entity_certificate('Target', intermediate)

chain = [target, intermediate, root]
common.write_chain(__doc__, chain, 'chain.pem')
