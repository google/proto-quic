// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.testing.local;

import org.junit.runners.model.InitializationError;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;
import org.robolectric.internal.ManifestFactory;

/**
 * A custom Robolectric Junit4 Test Runner with Chromium specific settings.
 */
public class LocalRobolectricTestRunner extends RobolectricTestRunner {
    private static final int DEFAULT_SDK = 25;

    public LocalRobolectricTestRunner(Class<?> testClass) throws InitializationError {
        super(testClass);
    }

    @Override
    protected Config buildGlobalConfig() {
        return new Config.Builder().setSdk(DEFAULT_SDK).build();
    }

    @Override
    protected ManifestFactory getManifestFactory(Config config) {
        return new GNManifestFactory();
    }
}
