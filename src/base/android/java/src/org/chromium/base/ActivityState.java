// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.base;

import android.support.annotation.IntDef;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

/**
 * A set of states that represent the last state change of an Activity.
 */
public interface ActivityState {

    @Retention(RetentionPolicy.SOURCE)
    @IntDef({CREATED, STARTED, RESUMED, PAUSED, STOPPED, DESTROYED})
    public @interface ActivityStateEnum {}

    /**
     * Represents Activity#onCreate().
     */
    public final int CREATED = 1;

    /**
     * Represents Activity#onStart().
     */
    public final int STARTED = 2;

    /**
     * Represents Activity#onResume().
     */
    public final int RESUMED = 3;

    /**
     * Represents Activity#onPause().
     */
    public final int PAUSED = 4;

    /**
     * Represents Activity#onStop().
     */
    public final int STOPPED = 5;

    /**
     * Represents Activity#onDestroy().  This is also used when the state of an Activity is unknown.
     */
    public final int DESTROYED = 6;
}
