#!/bin/sh

# Copyright (c) 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# This script is used to generate the test keys for the unit test in
# android/keystore_unittest.c.
#
# These are test RSA / DSA / ECDSA private keys in PKCS#8 format, as well
# as the corresponding DSA / ECDSA public keys.
#

# Exit script as soon a something fails.
set -e

mkdir -p out
rm -rf out/*

# Generate a single 2048-bits RSA private key in PKCS#8 format.
KEY=android-test-key-rsa
openssl genrsa \
    -out out/$KEY.pem \
    2048

# Generate a 2048-bits DSA private key in PKCS#8 format,
# as well as its public key in X.509 DER format.
KEY=android-test-key-dsa
openssl dsaparam \
    -out out/$KEY.param.pem \
    2048

openssl gendsa \
    -out out/$KEY.pem \
    out/$KEY.param.pem

openssl dsa \
    -in out/$KEY.pem \
    -outform PEM \
    -out out/$KEY-public.pem \
    -pubout

rm out/$KEY.param.pem

# Generate an ECDSA private key, in PKCS#8 format,
# as well as its public key in X.509 DER format.
KEY=android-test-key-ecdsa
openssl ecparam -genkey -name prime256v1 -out out/$KEY.pem

openssl ec \
    -in out/$KEY.pem \
    -outform PEM \
    -out out/$KEY-public.pem \
    -pubout

# We're done here.
