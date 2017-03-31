// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.base;

import android.os.Handler;

import org.chromium.base.annotations.CalledByNative;
import org.chromium.base.annotations.JNINamespace;

@JNINamespace("base")
class JavaHandlerThreadTest {
    private static boolean sTaskExecuted;
    // This is executed as part of base_unittests. This tests that JavaHandlerThread can be used
    // by itself without attaching to its native peer.
    @CalledByNative
    private static JavaHandlerThread testAndGetJavaHandlerThread() {
        sTaskExecuted = false;
        final Object lock = new Object();
        Runnable runnable = new Runnable() {
            @Override
            public void run() {
                synchronized (lock) {
                    sTaskExecuted = true;
                    lock.notifyAll();
                }
            }
        };

        JavaHandlerThread thread = new JavaHandlerThread("base_unittests_java");
        thread.maybeStart();

        Handler handler = new Handler(thread.getLooper());
        handler.post(runnable);
        synchronized (lock) {
            while (!sTaskExecuted) {
                try {
                    lock.wait();
                } catch (InterruptedException e) {
                    // ignore interrupts
                }
            }
        }

        return thread;
    }
}
