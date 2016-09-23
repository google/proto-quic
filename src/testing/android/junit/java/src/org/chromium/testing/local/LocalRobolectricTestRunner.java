// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.testing.local;

import org.junit.runners.model.InitializationError;

import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;
import org.robolectric.manifest.AndroidManifest;

/**
 * A custom Robolectric Junit4 Test Runner. This test runner will ignore the
 * API level written in the AndroidManifest as that can cause issues if
 * Robolectric does not support that API level. The API level will be grabbed
 * from the robolectric Config annotation, or just be
 * |DEFAULT_ANDROID_API_LEVEL|
 */
public class LocalRobolectricTestRunner extends RobolectricTestRunner {

    private static final int DEFAULT_ANDROID_API_LEVEL = 21;

    public LocalRobolectricTestRunner(Class<?> testClass) throws InitializationError {
        super(testClass);
    }

    @Override
    protected int pickSdkVersion(Config config, AndroidManifest appManifest) {
        // Pulling from the manifest is dangerous as the apk might target a version of
        // android that robolectric does not yet support. We still allow the API level to
        // be overridden with the Config annotation.
        if (config != null) {
            if (config.sdk().length > 1) {
                throw new IllegalArgumentException(
                        "RobolectricTestRunner does not support multiple values for @Config.sdk");
            } else if (config.sdk().length == 1) {
                return config.sdk()[0];
            }
        }
        return DEFAULT_ANDROID_API_LEVEL;
    }
}
