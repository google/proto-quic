// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.base.test;

import android.os.Bundle;
import android.support.test.runner.AndroidJUnitRunner;

import org.chromium.base.multidex.ChromiumMultiDexInstaller;

/**
 * A custom AndroidJUnitRunner that supports multidex installer.
 *
 * This class is the equivalent of BaseChromiumInstrumentationTestRunner in JUnit3. Please
 * beware that is this not a class runner. It is declared in test apk AndroidManifest.xml
 * <instrumentation>
 */
public class BaseChromiumAndroidJUnitRunner extends AndroidJUnitRunner {
    @Override
    public void onCreate(Bundle arguments) {
        ChromiumMultiDexInstaller.install(getTargetContext());
        super.onCreate(arguments);
    }
}
