// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.base.test;

import android.app.Application;
import android.content.Context;

import org.chromium.base.multidex.ChromiumMultiDexInstaller;
import org.chromium.base.test.util.CommandLineFlags;

// TODO(jbudorick): Add support for on-device handling of timeouts.
/**
 * An Instrumentation test runner for applications that are based on
 * {@code org.chromium.base.BaseChromiumApplication}
 */
public class BaseChromiumInstrumentationTestRunner extends BaseInstrumentationTestRunner {
    @Override
    public Application newApplication(ClassLoader cl, String className, Context context)
            throws ClassNotFoundException, IllegalAccessException, InstantiationException {
        ChromiumMultiDexInstaller.install(new BaseChromiumRunnerCommon.MultiDexContextWrapper(
                getContext(), getTargetContext()));
        BaseChromiumRunnerCommon.reorderDexPathElements(cl, getContext(), getTargetContext());
        return super.newApplication(cl, className, context);
    }

    /**
     * Override this method to register hooks and checks to be run for each test. Make sure to call
     * the base implementation if you do so.
     *
     * @see BaseTestResult#addSkipCheck(BaseTestResult.SkipCheck)
     * @see BaseTestResult#addPreTestHook(BaseTestResult.PreTestHook)
     */
    @Override
    protected void addTestHooks(BaseTestResult result) {
        super.addTestHooks(result);
        result.addPreTestHook(CommandLineFlags.getRegistrationHook());
    }
}
