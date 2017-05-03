#!/usr/bin/python
# Copyright (c) 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Certificate chain with 1 intermediate, a trusted root, and a target
certificate that is not a CA, and yet has the keyCertSign bit set. Verification
is expected to fail, since keyCertSign should only be asserted when CA is
true."""

import sys
sys.path += ['..']

import common

# Self-signed root certificate (used as trust anchor).
root = common.create_self_signed_root_certificate('Root')

# Intermediate certificate.
intermediate = common.create_intermediate_certificate('Intermediate', root)

# Target certificate (end entity but has keyCertSign bit set).
target = common.create_end_entity_certificate('Target', intermediate)
target.get_extensions().set_property('keyUsage',
    'critical,digitalSignature,keyEncipherment,keyCertSign')

chain = [target, intermediate, root]
common.write_chain(__doc__, chain, 'chain.pem')
