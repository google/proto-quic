#!/usr/bin/python
# Copyright (c) 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Certificate chain with 1 intermediate and a trusted root. The trusted root
is NOT self signed, however its issuer is not included in the chain or root
store. Verification is expected to succeed since the root is trusted."""

import sys
sys.path += ['..']

import common

shadow_root = common.create_self_signed_root_certificate('ShadowRoot')

# Non-self-signed root (part of trust store).
root = common.create_intermediate_certificate('Root', shadow_root)

# Intermediate certificate.
intermediate = common.create_intermediate_certificate('Intermediate', root)

# Target certificate.
target = common.create_end_entity_certificate('Target', intermediate)

chain = [target, intermediate, root]
common.write_chain(__doc__, chain, 'chain.pem')
