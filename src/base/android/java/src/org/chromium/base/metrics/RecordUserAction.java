// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.base.metrics;

import org.chromium.base.ThreadUtils;
import org.chromium.base.VisibleForTesting;
import org.chromium.base.annotations.JNINamespace;

/**
 * Java API for recording UMA actions.
 *
 * WARNINGS:
 * JNI calls are relatively costly - avoid using in performance-critical code.
 *
 * We use a script (extract_actions.py) to scan the source code and extract actions. A string
 * literal (not a variable) must be passed to record().
 */
@JNINamespace("base::android")
public class RecordUserAction {
    private static boolean sIsDisabledForTests = false;

    /**
     * Tests may not have native initialized, so they may need to disable metrics.
     */
    @VisibleForTesting
    public static void disableForTests() {
        sIsDisabledForTests = true;
    }

    public static void record(final String action) {
        if (sIsDisabledForTests) return;

        if (ThreadUtils.runningOnUiThread()) {
            nativeRecordUserAction(action);
            return;
        }

        ThreadUtils.runOnUiThread(new Runnable() {
            @Override
            public void run() {
                nativeRecordUserAction(action);
            }
        });
    }

    private static native void nativeRecordUserAction(String action);
}
