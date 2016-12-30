// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.base;

import android.support.test.filters.SmallTest;
import android.test.InstrumentationTestCase;

import org.chromium.base.test.util.Feature;

/**
 * Test class for {@link CommandLineInitUtil}.
 */
public class CommandLineInitUtilTest extends InstrumentationTestCase {

    @Override
    public void setUp() throws Exception {
        CommandLineInitUtil.initCommandLine(getInstrumentation().getTargetContext(),
                "chrome-command-line");
    }

    /**
     * Verifies that the default command line flags get set for Chrome Public tests.
     */
    @SmallTest
    @Feature({"CommandLine"})
    public void testDefaultCommandLineFlagsSet() {
        assertTrue("CommandLine not initialized after startup", CommandLine.isInitialized());

        final CommandLine commandLine = CommandLine.getInstance();
        assertTrue(commandLine.hasSwitch("enable-test-intents"));
    }
}
