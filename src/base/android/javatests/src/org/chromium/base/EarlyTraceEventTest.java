// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.base;

import android.os.Process;
import android.os.SystemClock;
import android.support.test.filters.SmallTest;
import android.test.InstrumentationTestCase;

import org.chromium.base.library_loader.LibraryLoader;
import org.chromium.base.library_loader.LibraryProcessType;
import org.chromium.base.test.util.Feature;

/**
 * Tests for {@link EarlyTraceEvent}.
 */
public class EarlyTraceEventTest extends InstrumentationTestCase {
    private static final String EVENT_NAME = "MyEvent";
    private static final String EVENT_NAME2 = "MyOtherEvent";

    @Override
    protected void setUp() throws Exception {
        super.setUp();
        LibraryLoader.get(LibraryProcessType.PROCESS_BROWSER).ensureInitialized();
        EarlyTraceEvent.sState = EarlyTraceEvent.STATE_DISABLED;
        EarlyTraceEvent.sCompletedEvents = null;
        EarlyTraceEvent.sPendingEvents = null;
    }

    @SmallTest
    @Feature({"Android-AppBase"})
    public void testCanRecordEvent() {
        EarlyTraceEvent.enable();
        long myThreadId = Process.myTid();
        long beforeMs = SystemClock.elapsedRealtime();
        EarlyTraceEvent.begin(EVENT_NAME);
        EarlyTraceEvent.end(EVENT_NAME);
        long afterMs = SystemClock.elapsedRealtime();

        assertEquals(1, EarlyTraceEvent.sCompletedEvents.size());
        assertTrue(EarlyTraceEvent.sPendingEvents.isEmpty());
        EarlyTraceEvent.Event event = EarlyTraceEvent.sCompletedEvents.get(0);
        assertEquals(EVENT_NAME, event.mName);
        assertEquals(myThreadId, event.mThreadId);
        assertTrue(beforeMs <= event.mBeginTimeMs && event.mBeginTimeMs <= afterMs);
        assertTrue(event.mBeginTimeMs <= event.mEndTimeMs);
        assertTrue(beforeMs <= event.mEndTimeMs && event.mEndTimeMs <= afterMs);
    }

    @SmallTest
    @Feature({"Android-AppBase"})
    public void testIncompleteEvent() {
        EarlyTraceEvent.enable();
        EarlyTraceEvent.begin(EVENT_NAME);

        assertTrue(EarlyTraceEvent.sCompletedEvents.isEmpty());
        assertEquals(1, EarlyTraceEvent.sPendingEvents.size());
        EarlyTraceEvent.Event event = EarlyTraceEvent.sPendingEvents.get(EVENT_NAME);
        assertEquals(EVENT_NAME, event.mName);
    }

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
        fail();
    }

    @SmallTest
    @Feature({"Android-AppBase"})
    public void testIgnoreEventsWhenDisabled() {
        EarlyTraceEvent.begin(EVENT_NAME);
        EarlyTraceEvent.end(EVENT_NAME);
        assertNull(EarlyTraceEvent.sCompletedEvents);
    }

    @SmallTest
    @Feature({"Android-AppBase"})
    public void testIgnoreNewEventsWhenFinishing() {
        EarlyTraceEvent.enable();
        EarlyTraceEvent.begin(EVENT_NAME);
        EarlyTraceEvent.disable();

        assertEquals(EarlyTraceEvent.STATE_FINISHING, EarlyTraceEvent.sState);
        EarlyTraceEvent.begin(EVENT_NAME2);
        EarlyTraceEvent.end(EVENT_NAME2);

        assertEquals(1, EarlyTraceEvent.sPendingEvents.size());
        assertTrue(EarlyTraceEvent.sCompletedEvents.isEmpty());
    }

    @SmallTest
    @Feature({"Android-AppBase"})
    public void testFinishingToFinished() {
        EarlyTraceEvent.enable();
        EarlyTraceEvent.begin(EVENT_NAME);
        EarlyTraceEvent.disable();

        assertEquals(EarlyTraceEvent.STATE_FINISHING, EarlyTraceEvent.sState);
        EarlyTraceEvent.begin(EVENT_NAME2);
        EarlyTraceEvent.end(EVENT_NAME2);
        EarlyTraceEvent.end(EVENT_NAME);

        assertEquals(EarlyTraceEvent.STATE_FINISHED, EarlyTraceEvent.sState);
    }

    @SmallTest
    @Feature({"Android-AppBase"})
    public void testCannotBeReenabledOnceFinished() {
        EarlyTraceEvent.enable();
        EarlyTraceEvent.begin(EVENT_NAME);
        EarlyTraceEvent.end(EVENT_NAME);
        EarlyTraceEvent.disable();
        assertEquals(EarlyTraceEvent.STATE_FINISHED, EarlyTraceEvent.sState);

        EarlyTraceEvent.enable();
        assertEquals(EarlyTraceEvent.STATE_FINISHED, EarlyTraceEvent.sState);
    }

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

        assertEquals(1, EarlyTraceEvent.sCompletedEvents.size());
        EarlyTraceEvent.Event event = EarlyTraceEvent.sCompletedEvents.get(0);
        assertEquals(threadId[0], event.mThreadId);
    }
}
