#!/usr/bin/python
# Copyright (c) 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Certificate chain with 1 intermediate, a trusted root, and a target
certificate that is also a CA. Verification is expected to succeed, as the test
code accepts any target certificate."""

import sys
sys.path += ['..']

import common

# Self-signed root certificate (used as trust anchor).
root = common.create_self_signed_root_certificate('Root')

# Intermediate certificate.
intermediate = common.create_intermediate_certificate('Intermediate', root)

# Target certificate (is also a CA)
target = common.create_intermediate_certificate('Target', intermediate)

chain = [target, intermediate, root]
common.write_chain(__doc__, chain, 'chain.pem')
