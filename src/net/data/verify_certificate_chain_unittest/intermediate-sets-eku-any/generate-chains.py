#!/usr/bin/python
# Copyright (c) 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Certificate chain with 1 intermediate and a trusted root. The intermediate
restricts the EKU to clientAuth + any, and the target has serverAuth +
clientAuth. Verification is expected to succeed because intermediate will match
the "any"."""

import sys
sys.path += ['..']

import common

# Self-signed root certificate (used as trust anchor).
root = common.create_self_signed_root_certificate('Root')

# Intermediate certificate.
intermediate = common.create_intermediate_certificate('Intermediate', root)
intermediate.get_extensions().set_property('extendedKeyUsage',
                                           'clientAuth,anyExtendedKeyUsage')

# Target certificate.
target = common.create_end_entity_certificate('Target', intermediate)
target.get_extensions().set_property('extendedKeyUsage',
                                     'serverAuth,clientAuth')

chain = [target, intermediate, root]
common.write_chain(__doc__, chain, 'chain.pem')
