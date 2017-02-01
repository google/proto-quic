// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.base;

import android.os.Process;
import android.os.StrictMode;
import android.os.SystemClock;

import org.chromium.base.annotations.JNINamespace;
import org.chromium.base.annotations.MainDex;
import org.chromium.base.annotations.SuppressFBWarnings;

import java.io.File;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** Support for early tracing, before the native library is loaded.
 *
 * This is limited, as:
 * - Arguments are not supported
 * - Thread time is not reported
 * - Two events with the same name cannot be in progress at the same time.
 *
 * Events recorded here are buffered in Java until the native library is available. Then it waits
 * for the completion of pending events, and sends the events to the native side.
 *
 * Locking: This class is threadsafe. It is enabled when general tracing is, and then disabled when
 *          tracing is enabled from the native side. Event completions are still processed as long
 *          as some are pending, then early tracing is permanently disabled after dumping the
 *          events.  This means that if any early event is still pending when tracing is disabled,
 *          all early events are dropped.
 */
@JNINamespace("base::android")
@MainDex
public class EarlyTraceEvent {
    // Must be kept in sync with the native kAndroidTraceConfigFile.
    private static final String TRACE_CONFIG_FILENAME = "/data/local/chrome-trace-config.json";

    /** Single trace event. */
    @VisibleForTesting
    static final class Event {
        final String mName;
        final int mThreadId;
        final long mBeginTimeMs;
        long mEndTimeMs;

        Event(String name) {
            mName = name;
            mThreadId = Process.myTid();
            mBeginTimeMs = SystemClock.elapsedRealtime();
        }

        void end() {
            assert mEndTimeMs == 0;
            mEndTimeMs = SystemClock.elapsedRealtime();
        }
    }

    // State transitions are:
    // - enable(): DISABLED -> ENABLED
    // - disable(): ENABLED -> FINISHING
    // - Once there are no pending events: FINISHING -> FINISHED.
    @VisibleForTesting static final int STATE_DISABLED = 0;
    @VisibleForTesting static final int STATE_ENABLED = 1;
    @VisibleForTesting static final int STATE_FINISHING = 2;
    @VisibleForTesting static final int STATE_FINISHED = 3;

    // Locks the fields below.
    private static final Object sLock = new Object();

    @VisibleForTesting static volatile int sState = STATE_DISABLED;
    // Not final as these object are not likely to be used at all.
    @VisibleForTesting static List<Event> sCompletedEvents;
    @VisibleForTesting static Map<String, Event> sPendingEvents;

    /** @see TraceEvent#MaybeEnableEarlyTracing().
     */
    @SuppressFBWarnings("DMI_HARDCODED_ABSOLUTE_FILENAME")
    static void maybeEnable() {
        boolean shouldEnable = false;
        // Checking for the trace config filename touches the disk.
        StrictMode.ThreadPolicy oldPolicy = StrictMode.allowThreadDiskReads();
        try {
            if (CommandLine.isInitialized()
                    && CommandLine.getInstance().hasSwitch("trace-startup")) {
                shouldEnable = true;
            } else {
                try {
                    shouldEnable = (new File(TRACE_CONFIG_FILENAME)).exists();
                } catch (SecurityException e) {
                    // Access denied, not enabled.
                }
            }
        } finally {
            StrictMode.setThreadPolicy(oldPolicy);
        }
        if (shouldEnable) enable();
    }

    @VisibleForTesting
    static void enable() {
        synchronized (sLock) {
            if (sState != STATE_DISABLED) return;
            sCompletedEvents = new ArrayList<Event>();
            sPendingEvents = new HashMap<String, Event>();
            sState = STATE_ENABLED;
        }
    }

    /**
     * Disables Early tracing.
     *
     * Once this is called, no new event will be registered. However, end() calls are still recorded
     * as long as there are pending events. Once there are none left, pass the events to the native
     * side.
     */
    static void disable() {
        synchronized (sLock) {
            if (sState != STATE_ENABLED) return;
            sState = STATE_FINISHING;
            maybeFinishLocked();
        }
    }

    /** @see {@link TraceEvent#begin()}. */
    public static void begin(String name) {
        // begin() and end() are going to be called once per TraceEvent, this avoids entering a
        // synchronized block at each and every call.
        if (sState != STATE_ENABLED) return;
        Event event = new Event(name);
        Event conflictingEvent;
        synchronized (sLock) {
            if (sState != STATE_ENABLED) return;
            conflictingEvent = sPendingEvents.put(name, event);
        }
        if (conflictingEvent != null) {
            throw new IllegalArgumentException(
                    "Multiple pending trace events can't have the same name");
        }
    }

    /** @see {@link TraceEvent#end()}. */
    public static void end(String name) {
        int state = sState;
        if (state != STATE_ENABLED && state != STATE_FINISHING) return;
        synchronized (sLock) {
            if (sState != STATE_ENABLED && sState != STATE_FINISHING) return;
            Event event = sPendingEvents.remove(name);
            if (event == null) return;
            event.end();
            sCompletedEvents.add(event);
            if (sState == STATE_FINISHING) maybeFinishLocked();
        }
    }

    private static void maybeFinishLocked() {
        if (!sPendingEvents.isEmpty()) return;
        sState = STATE_FINISHED;
        dumpEvents(sCompletedEvents);
        sCompletedEvents = null;
        sPendingEvents = null;
    }

    private static void dumpEvents(List<Event> events) {
        long nativeNowUs = TimeUtils.nativeGetTimeTicksNowUs();
        long javaNowUs = SystemClock.elapsedRealtime() * 1000;
        long offsetMs = (nativeNowUs - javaNowUs) / 1000;
        for (Event event : events) {
            nativeRecordEarlyEvent(event.mName, event.mBeginTimeMs + offsetMs,
                    event.mEndTimeMs + offsetMs, event.mThreadId);
        }
    }

    private static native void nativeRecordEarlyEvent(
            String name, long beginTimeMs, long endTimeMs, int threadId);
}
