// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.base.test;

import android.app.Activity;
import android.test.ActivityInstrumentationTestCase2;

/**
 * Base class for all Activity-based Instrumentation tests.
 *
 * @param <T> The Activity type.
 */
public class BaseActivityInstrumentationTestCase<T extends Activity>
        extends ActivityInstrumentationTestCase2<T> {
    /**
     * Creates a instance for running tests against an Activity of the given class.
     *
     * @param activityClass The type of activity that will be tested.
     */
    public BaseActivityInstrumentationTestCase(Class<T> activityClass) {
        super(activityClass);
    }
}
