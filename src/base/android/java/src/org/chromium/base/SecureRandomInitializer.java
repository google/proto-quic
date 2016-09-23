// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.base;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.SecureRandom;

/**
 * This class contains code to initialize a SecureRandom generator securely on Android platforms
 * <= 4.3. See
 * {@link http://android-developers.blogspot.com/2013/08/some-securerandom-thoughts.html}.
 */
public class SecureRandomInitializer {
    private static final int NUM_RANDOM_BYTES = 16;

    /**
     * Safely initializes the random number generator, by seeding it with data from /dev/urandom.
     */
    public static void initialize(SecureRandom generator) throws IOException {
        FileInputStream fis = null;
        try {
            byte[] seedBytes = new byte[NUM_RANDOM_BYTES];
            fis = new FileInputStream("/dev/urandom");
            if (fis.read(seedBytes) != seedBytes.length) {
                throw new IOException("Failed to get enough random data.");
            }
            generator.setSeed(seedBytes);
        } finally {
            StreamUtil.closeQuietly(fis);
        }
    }
}
