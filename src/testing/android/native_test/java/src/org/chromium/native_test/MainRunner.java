// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.native_test;

import org.chromium.base.annotations.JNINamespace;

/**
 * This class provides a way to run the native main method.
 * It is used in the multi-process test case, so that the child process can call
 * the main method without //base/test:test_support's linkage requiring the
 * main() symbol.
 */
@JNINamespace("testing::android")
public final class MainRunner {
    // Prevent instanciation.
    private MainRunner() {
    }

    // Maps the file descriptors and executes the main method with the passed in command line.
    public static int runMain(String[] commandLine, int[] fdsToMapKeys, int[] fdsToMapFds) {
        return nativeRunMain(commandLine, fdsToMapKeys, fdsToMapFds);
    }
    private static native int nativeRunMain(
            String[] commandLine, int[] fdsToMapKeys, int[] fdsToMapFds);
}