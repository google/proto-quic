// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.build;

/**
 * This class is inserted in build, all Java targets have dependence on it.
 */
public class BuildHooks {
    private static Callback<AssertionError> sAssertCallback;
    /**
     * Handle AssertionError, decide whether throw or report without crashing base on gn arg.
     * This method is inserted to handle any assert failure by java_assertion_enabler.
     */
    public static void assertFailureHandler(AssertionError assertionError) {
        if (sAssertCallback != null) {
            sAssertCallback.run(assertionError);
        } else {
            throw assertionError;
        }
    }

    /**
     * Set the callback function that handles assert failure.
     * This should be called from attachBaseContext.
     */
    public static void setAssertCallback(Callback<AssertionError> callback) {
        sAssertCallback = callback;
    }
}
