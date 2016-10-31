// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.base.metrics;

import org.chromium.base.library_loader.LibraryLoader;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * Utility classes for recording UMA metrics before the native library
 * may have been loaded.  Metrics are cached until the library is known
 * to be loaded, then committed to the MetricsService all at once.
 */
public class CachedMetrics {
    /**
     * Creating an instance of a subclass of this class automatically adds it to a list of objects
     * that are committed when the native library is available.
     */
    private abstract static class CachedHistogram {
        private static final List<CachedHistogram> sEvents = new ArrayList<CachedHistogram>();

        protected final String mHistogramName;

        /**
         * @param histogramName Name of the histogram to record.
         */
        protected CachedHistogram(String histogramName) {
            mHistogramName = histogramName;
            sEvents.add(this);
        }

        /** Commits the histogram. Expects the native library to be loaded. */
        protected abstract void commitAndClear();
    }

    /**
     * Caches an action that will be recorded after native side is loaded.
     */
    public static class ActionEvent extends CachedHistogram {
        private int mCount;

        public ActionEvent(String actionName) {
            super(actionName);
        }

        public void record() {
            if (LibraryLoader.isInitialized()) {
                recordWithNative();
            } else {
                mCount++;
            }
        }

        private void recordWithNative() {
            RecordUserAction.record(mHistogramName);
        }

        @Override
        protected void commitAndClear() {
            while (mCount > 0) {
                recordWithNative();
                mCount--;
            }
        }
    }

    /** Caches a set of integer histogram samples. */
    public static class SparseHistogramSample extends CachedHistogram {
        private final List<Integer> mSamples = new ArrayList<Integer>();

        public SparseHistogramSample(String histogramName) {
            super(histogramName);
        }

        public void record(int sample) {
            if (LibraryLoader.isInitialized()) {
                recordWithNative(sample);
            } else {
                mSamples.add(sample);
            }
        }

        private void recordWithNative(int sample) {
            RecordHistogram.recordSparseSlowlyHistogram(mHistogramName, sample);
        }

        @Override
        protected void commitAndClear() {
            for (Integer sample : mSamples) {
                recordWithNative(sample);
            }
            mSamples.clear();
        }
    }

    /** Caches a set of enumerated histogram samples. */
    public static class EnumeratedHistogramSample extends CachedHistogram {
        private final List<Integer> mSamples = new ArrayList<Integer>();
        private final int mMaxValue;

        public EnumeratedHistogramSample(String histogramName, int maxValue) {
            super(histogramName);
            mMaxValue = maxValue;
        }

        public void record(int sample) {
            if (LibraryLoader.isInitialized()) {
                recordWithNative(sample);
            } else {
                mSamples.add(sample);
            }
        }

        private void recordWithNative(int sample) {
            RecordHistogram.recordEnumeratedHistogram(mHistogramName, sample, mMaxValue);
        }

        @Override
        protected void commitAndClear() {
            for (Integer sample : mSamples) {
                recordWithNative(sample);
            }
            mSamples.clear();
        }
    }

    /** Caches a set of times histogram samples. */
    public static class TimesHistogramSample extends CachedHistogram {
        private final List<Long> mSamples = new ArrayList<Long>();
        private final TimeUnit mTimeUnit;

        public TimesHistogramSample(String histogramName, TimeUnit timeUnit) {
            super(histogramName);
            mTimeUnit = timeUnit;
        }

        public void record(long sample) {
            if (LibraryLoader.isInitialized()) {
                recordWithNative(sample);
            } else {
                mSamples.add(sample);
            }
        }

        private void recordWithNative(long sample) {
            RecordHistogram.recordTimesHistogram(mHistogramName, sample, mTimeUnit);
        }

        @Override
        protected void commitAndClear() {
            for (Long sample : mSamples) {
                recordWithNative(sample);
            }
            mSamples.clear();
        }
    }

    /**
     * Calls out to native code to commit any cached histograms and events.
     * Should be called once the native library has been loaded.
     */
    public static void commitCachedMetrics() {
        for (CachedHistogram event : CachedHistogram.sEvents) event.commitAndClear();
    }
}
