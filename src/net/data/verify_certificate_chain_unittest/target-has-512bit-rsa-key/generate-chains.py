#!/usr/bin/python
# Copyright (c) 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Valid certificate chain where the target certificate contains a public key
with a 512-bit modulus (weak)."""

import sys
sys.path += ['..']

import common

# Self-signed root certificate.
root = common.create_self_signed_root_certificate('Root')

# Intermediate
intermediate = common.create_intermediate_certificate('Intermediate', root)

# Target certificate.
target = common.create_end_entity_certificate('Target', intermediate)
target.set_key(common.get_or_generate_rsa_key(
    512, common.create_key_path(target.name)))

chain = [target, intermediate, root]
common.write_chain(__doc__, chain, 'chain.pem')
