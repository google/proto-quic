// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.base;

import android.os.Message;

import org.chromium.base.annotations.CalledByNative;
import org.chromium.base.annotations.JNINamespace;

/**
 * Test-only message handler enabling us to test that Java exceptions thrown from a JNI call
 * originating from the native side are propagated to the Message Handler (instead of causing a
 * native crash).
 * This class declares a custom exception and wraps the SystemMessageHandler message handling
 * mechanism to catch such exceptions. When catching an exception we call the native side to notify
 * tests that the correct exception was thrown and caught.
 */
@JNINamespace("base::android")
class TestSystemMessageHandler extends SystemMessageHandler {
    private long mWaitableTestEventNative;

    private TestSystemMessageHandler(
            long messagePumpDelegateNative, long messagePumpNative, long waitableTestEventNative) {
        super(messagePumpDelegateNative, messagePumpNative);
        mWaitableTestEventNative = waitableTestEventNative;
    }

    @Override
    public void handleMessage(Message msg) {
        try {
            super.handleMessage(msg);
        } catch (TestException e) {
            nativeNotifyTestDone(mWaitableTestEventNative);
            return;
        }
    }

    private static class TestException extends RuntimeException {
        TestException(String message) {
            super(message);
        }
    }

    @CalledByNative
    private static TestSystemMessageHandler create(
            long messagePumpDelegateNative, long messagePumpNative, long waitableTestEvent) {
        return new TestSystemMessageHandler(
                messagePumpDelegateNative, messagePumpNative, waitableTestEvent);
    }

    private static native void nativeNotifyTestDone(long messagePumpNative);
}
