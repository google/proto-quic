#!/usr/bin/python
# Copyright (c) 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Certificate chain where the root certificate is not self-signed (or
self-issued for that matter)."""

import sys
sys.path += ['..']

import common

shadow_root = common.create_self_signed_root_certificate('ShadowRoot')

# Non-self-signed root certificate.
root = common.create_intermediate_certificate('Root', shadow_root)

# Intermediate certificate.
intermediate = common.create_intermediate_certificate('Intermediate', root)

# Target certificate.
target = common.create_end_entity_certificate('Target', intermediate)

chain = [target, intermediate, root]
common.write_chain(__doc__, chain, 'chain.pem')
