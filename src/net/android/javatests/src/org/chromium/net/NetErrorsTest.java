// Copyright 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/**
 * Tests to verify that NetError.java is created succesfully.
 */

package org.chromium.net;

import android.test.InstrumentationTestCase;
import android.test.suitebuilder.annotation.SmallTest;

import org.chromium.base.test.util.Feature;

public class NetErrorsTest extends InstrumentationTestCase {
    // These are manually copied and should be kept in sync with net_error_list.h.
    private static final int IO_PENDING_ERROR = -1;
    private static final int FAILED_ERROR = -2;

    /**
     * Test whether we can include NetError.java and call to static integers defined in the file.
     *
     * @throws Exception
     */
    @SmallTest
    @Feature({"Android-AppBase"})
    public void testExampleErrorDefined() throws Exception {
        assertEquals(IO_PENDING_ERROR, NetError.ERR_IO_PENDING);
        assertEquals(FAILED_ERROR, NetError.ERR_FAILED);
    }
}
