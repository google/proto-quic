#!/usr/bin/python
# Copyright (c) 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Certificate chain with 1 intermediate and a trusted root. The intermediate
contains a keyUsage extension, HOWEVER it does not contain the keyCertSign bit.
Hence validation is expected to fail."""

import sys
sys.path += ['..']

import common

# Self-signed root certificate (used as trust anchor).
root = common.create_self_signed_root_certificate('Root')

# Intermediate that is missing keyCertSign.
intermediate = common.create_intermediate_certificate('Intermediate', root)
intermediate.get_extensions().set_property('keyUsage',
    'critical,digitalSignature,keyEncipherment')

# Target certificate.
target = common.create_end_entity_certificate('Target', intermediate)

chain = [target, intermediate, root]
common.write_chain(__doc__, chain, 'chain.pem')
