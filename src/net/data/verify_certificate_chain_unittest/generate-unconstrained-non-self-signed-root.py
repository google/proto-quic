#!/usr/bin/python
# Copyright (c) 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Certificate chain with 1 intermediate and a non-self-signed trust anchor.
Verification should succeed, it doesn't matter that the root was not
self-signed if it is designated as the trust anchor."""

import common

uber_root = common.create_self_signed_root_certificate('UberRoot')

# Non-self-signed root certificate (used as trust anchor)
root = common.create_intermediate_certificate('Root', uber_root)

# Intermediate certificate.
intermediate = common.create_intermediate_certificate('Intermediate', root)

# Target certificate.
target = common.create_end_entity_certificate('Target', intermediate)

chain = [target, intermediate]
trusted = common.TrustAnchor(root, constrained=False)
time = common.DEFAULT_TIME
verify_result = True
errors = None

common.write_test_file(__doc__, chain, trusted, time, verify_result, errors)

