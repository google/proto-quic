// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.base;

import android.os.Process;
import android.os.SystemClock;
import android.support.test.filters.SmallTest;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.chromium.base.library_loader.LibraryLoader;
import org.chromium.base.library_loader.LibraryProcessType;
import org.chromium.base.test.BaseJUnit4ClassRunner;
import org.chromium.base.test.util.Feature;

/**
 * Tests for {@link EarlyTraceEvent}.
 */
@RunWith(BaseJUnit4ClassRunner.class)
public class EarlyTraceEventTest {
    private static final String EVENT_NAME = "MyEvent";
    private static final String EVENT_NAME2 = "MyOtherEvent";

    @Before
    public void setUp() throws Exception {
        LibraryLoader.get(LibraryProcessType.PROCESS_BROWSER).ensureInitialized();
        EarlyTraceEvent.sState = EarlyTraceEvent.STATE_DISABLED;
        EarlyTraceEvent.sCompletedEvents = null;
        EarlyTraceEvent.sPendingEvents = null;
    }

    @Test
    @SmallTest
    @Feature({"Android-AppBase"})
    public void testCanRecordEvent() {
        EarlyTraceEvent.enable();
        long myThreadId = Process.myTid();
        long beforeMs = SystemClock.elapsedRealtime();
        EarlyTraceEvent.begin(EVENT_NAME);
        EarlyTraceEvent.end(EVENT_NAME);
        long afterMs = SystemClock.elapsedRealtime();

        Assert.assertEquals(1, EarlyTraceEvent.sCompletedEvents.size());
        Assert.assertTrue(EarlyTraceEvent.sPendingEvents.isEmpty());
        EarlyTraceEvent.Event event = EarlyTraceEvent.sCompletedEvents.get(0);
        Assert.assertEquals(EVENT_NAME, event.mName);
        Assert.assertEquals(myThreadId, event.mThreadId);
        Assert.assertTrue(beforeMs <= event.mBeginTimeMs && event.mBeginTimeMs <= afterMs);
        Assert.assertTrue(event.mBeginTimeMs <= event.mEndTimeMs);
        Assert.assertTrue(beforeMs <= event.mEndTimeMs && event.mEndTimeMs <= afterMs);
    }

    @Test
    @SmallTest
    @Feature({"Android-AppBase"})
    public void testIncompleteEvent() {
        EarlyTraceEvent.enable();
        EarlyTraceEvent.begin(EVENT_NAME);

        Assert.assertTrue(EarlyTraceEvent.sCompletedEvents.isEmpty());
        Assert.assertEquals(1, EarlyTraceEvent.sPendingEvents.size());
        EarlyTraceEvent.Event event = EarlyTraceEvent.sPendingEvents.get(EVENT_NAME);
        Assert.assertEquals(EVENT_NAME, event.mName);
    }

    @Test
    @SmallTest
    @Feature({"Android-AppBase"})
    public void testNoDuplicatePendingEvents() {
        EarlyTraceEvent.enable();
        EarlyTraceEvent.begin(EVENT_NAME);
        try {
            EarlyTraceEvent.begin(EVENT_NAME);
        } catch (IllegalArgumentException e) {
            // Expected.
            return;
        }
        Assert.fail();
    }

    @Test
    @SmallTest
    @Feature({"Android-AppBase"})
    public void testIgnoreEventsWhenDisabled() {
        EarlyTraceEvent.begin(EVENT_NAME);
        EarlyTraceEvent.end(EVENT_NAME);
        Assert.assertNull(EarlyTraceEvent.sCompletedEvents);
    }

    @Test
    @SmallTest
    @Feature({"Android-AppBase"})
    public void testIgnoreNewEventsWhenFinishing() {
        EarlyTraceEvent.enable();
        EarlyTraceEvent.begin(EVENT_NAME);
        EarlyTraceEvent.disable();

        Assert.assertEquals(EarlyTraceEvent.STATE_FINISHING, EarlyTraceEvent.sState);
        EarlyTraceEvent.begin(EVENT_NAME2);
        EarlyTraceEvent.end(EVENT_NAME2);

        Assert.assertEquals(1, EarlyTraceEvent.sPendingEvents.size());
        Assert.assertTrue(EarlyTraceEvent.sCompletedEvents.isEmpty());
    }

    @Test
    @SmallTest
    @Feature({"Android-AppBase"})
    public void testFinishingToFinished() {
        EarlyTraceEvent.enable();
        EarlyTraceEvent.begin(EVENT_NAME);
        EarlyTraceEvent.disable();

        Assert.assertEquals(EarlyTraceEvent.STATE_FINISHING, EarlyTraceEvent.sState);
        EarlyTraceEvent.begin(EVENT_NAME2);
        EarlyTraceEvent.end(EVENT_NAME2);
        EarlyTraceEvent.end(EVENT_NAME);

        Assert.assertEquals(EarlyTraceEvent.STATE_FINISHED, EarlyTraceEvent.sState);
    }

    @Test
    @SmallTest
    @Feature({"Android-AppBase"})
    public void testCannotBeReenabledOnceFinished() {
        EarlyTraceEvent.enable();
        EarlyTraceEvent.begin(EVENT_NAME);
        EarlyTraceEvent.end(EVENT_NAME);
        EarlyTraceEvent.disable();
        Assert.assertEquals(EarlyTraceEvent.STATE_FINISHED, EarlyTraceEvent.sState);

        EarlyTraceEvent.enable();
        Assert.assertEquals(EarlyTraceEvent.STATE_FINISHED, EarlyTraceEvent.sState);
    }

    @Test
    @SmallTest
    @Feature({"Android-AppBase"})
    public void testThreadIdIsRecorded() throws Exception {
        EarlyTraceEvent.enable();
        final long[] threadId = {0};

        Thread thread = new Thread() {
            @Override
            public void run() {
                TraceEvent.begin(EVENT_NAME);
                threadId[0] = Process.myTid();
                TraceEvent.end(EVENT_NAME);
            }
        };
        thread.start();
        thread.join();

        Assert.assertEquals(1, EarlyTraceEvent.sCompletedEvents.size());
        EarlyTraceEvent.Event event = EarlyTraceEvent.sCompletedEvents.get(0);
        Assert.assertEquals(threadId[0], event.mThreadId);
    }
}
