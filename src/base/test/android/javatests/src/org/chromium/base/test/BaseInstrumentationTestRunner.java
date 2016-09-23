// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.base.test;

import android.app.ActivityOptions;
import android.content.Context;
import android.content.ContextWrapper;
import android.content.Intent;
import android.test.AndroidTestRunner;
import android.test.InstrumentationTestRunner;

import junit.framework.TestResult;

import org.chromium.base.test.util.DisableIfSkipCheck;
import org.chromium.base.test.util.MinAndroidSdkLevelSkipCheck;
import org.chromium.base.test.util.RestrictionSkipCheck;
import org.chromium.test.reporter.TestStatusListener;

// TODO(jbudorick): Add support for on-device handling of timeouts.
/**
 * An Instrumentation test runner that checks SDK level for tests with specific requirements.
 *
 * If the package application for which the instrumetation targets is based on
    * {@code org.chromium.base.BaseChromiumApplication}, one should use
    * {@code BaseChromiumInstrumentationTestRunner}
 */
public class BaseInstrumentationTestRunner extends InstrumentationTestRunner {
    @Override
    protected AndroidTestRunner getAndroidTestRunner() {
        AndroidTestRunner runner = new AndroidTestRunner() {
            @Override
            protected TestResult createTestResult() {
                BaseTestResult r = new BaseTestResult(BaseInstrumentationTestRunner.this);
                addTestHooks(r);
                return r;
            }
        };
        runner.addTestListener(new TestStatusListener(getContext()));
        return runner;
    }

    /**
     * Override this method to register hooks and checks to be run for each test. Make sure to call
     * the base implementation if you do so.
     *
     * @see BaseTestResult#addSkipCheck(BaseTestResult.SkipCheck)
     * @see BaseTestResult#addPreTestHook(BaseTestResult.PreTestHook)
     */
    protected void addTestHooks(BaseTestResult result) {
        result.addSkipCheck(new MinAndroidSdkLevelSkipCheck());
        result.addSkipCheck(new RestrictionSkipCheck(getTargetContext()));
        result.addSkipCheck(new DisableIfSkipCheck());
    }

    @Override
    public Context getTargetContext() {
        return new ContextWrapper(super.getTargetContext()) {
            @Override
            public void startActivity(Intent intent) {
                Context context = getApplicationContext();
                ActivityOptions activityOptions =
                        ActivityOptions.makeCustomAnimation(context, 0, 0);
                startActivity(intent, activityOptions.toBundle());
            }
        };
    }
}
